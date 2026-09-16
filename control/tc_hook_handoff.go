/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	stderrors "errors"
	"fmt"
	"sync"
)

var tcHookOwnershipMu sync.Mutex

type preparedTCHookHandoff struct {
	previous  *controlPlaneCore
	active    *tcHookSet
	displaced *tcHookSet
	adopted   bool
}

func (c *controlPlaneCore) ownedTCHookSet() *tcHookSet {
	if c == nil {
		return nil
	}
	c.tcHookMu.Lock()
	set := c.tcHooks
	c.tcHookMu.Unlock()
	return set
}

func (c *controlPlaneCore) closeOwnedTCHookSet() error {
	if c == nil {
		return nil
	}
	tcHookOwnershipMu.Lock()
	defer tcHookOwnershipMu.Unlock()
	c.tcHookMu.Lock()
	set := c.tcHooks
	c.tcHookMu.Unlock()
	if set == nil {
		return nil
	}
	return set.close()
}

func (c *controlPlaneCore) resetTCHookSetForReattach() {
	if c == nil {
		return
	}
	tcHookOwnershipMu.Lock()
	defer tcHookOwnershipMu.Unlock()
	c.tcHookMu.Lock()
	defer c.tcHookMu.Unlock()
	if c.tcHooks == nil || c.tcHooks.isClosed() {
		c.tcHooks = newTCHookSet(c.log)
	}
}

func (c *controlPlaneCore) prepareTCHookHandoff(previous *controlPlaneCore) error {
	if c == nil || previous == nil || c == previous {
		return fmt.Errorf("invalid TC HookSet handoff")
	}
	tcHookOwnershipMu.Lock()
	defer tcHookOwnershipMu.Unlock()

	previous.tcHookMu.Lock()
	active := previous.tcHooks
	previous.tcHookMu.Unlock()
	c.tcHookMu.Lock()
	defer c.tcHookMu.Unlock()
	if c.preparedTCHooks != nil {
		if c.preparedTCHooks.previous == previous && c.preparedTCHooks.active == active {
			return nil
		}
		return fmt.Errorf("TC HookSet handoff already prepared")
	}
	if active == nil || active.isClosed() {
		return fmt.Errorf("previous TC HookSet is unavailable")
	}
	if c.tcHooks == nil {
		c.tcHooks = newTCHookSet(c.log)
	}
	if !c.tcHooks.empty() {
		return fmt.Errorf("candidate TC HookSet is not empty")
	}
	c.preparedTCHooks = &preparedTCHookHandoff{
		previous:  previous,
		active:    active,
		displaced: c.tcHooks,
	}
	return nil
}

func (c *controlPlaneCore) adoptPreparedTCHookSet(previous *controlPlaneCore) error {
	if c == nil || previous == nil {
		return fmt.Errorf("missing TC HookSet handoff owner")
	}
	tcHookOwnershipMu.Lock()
	defer tcHookOwnershipMu.Unlock()

	c.tcHookMu.Lock()
	state := c.preparedTCHooks
	c.tcHookMu.Unlock()
	if state == nil || state.previous != previous {
		return fmt.Errorf("TC HookSet handoff was not prepared from expected owner")
	}
	if state.adopted {
		return nil
	}

	previous.tcHookMu.Lock()
	defer previous.tcHookMu.Unlock()
	c.tcHookMu.Lock()
	defer c.tcHookMu.Unlock()
	if previous.tcHooks != state.active || c.tcHooks != state.displaced {
		return fmt.Errorf("TC HookSet ownership changed before adoption")
	}
	previous.tcHooks, c.tcHooks = state.displaced, state.active
	state.adopted = true
	return nil
}

func (c *controlPlaneCore) restorePreparedTCHookSet(previous *controlPlaneCore) error {
	if c == nil || previous == nil {
		return nil
	}
	tcHookOwnershipMu.Lock()
	defer tcHookOwnershipMu.Unlock()

	c.tcHookMu.Lock()
	state := c.preparedTCHooks
	c.tcHookMu.Unlock()
	if state == nil || state.previous != previous || !state.adopted {
		return nil
	}

	previous.tcHookMu.Lock()
	defer previous.tcHookMu.Unlock()
	c.tcHookMu.Lock()
	defer c.tcHookMu.Unlock()
	if previous.tcHooks != state.displaced || c.tcHooks != state.active {
		return fmt.Errorf("TC HookSet ownership changed before restore")
	}
	previous.tcHooks, c.tcHooks = state.active, state.displaced
	state.adopted = false
	return nil
}

func (c *controlPlaneCore) beginTCHookReplace() error {
	if c == nil {
		return nil
	}
	c.tcHookMu.Lock()
	if c.tcHookStage != nil {
		c.tcHookMu.Unlock()
		return fmt.Errorf("TC HookSet staging already active")
	}
	target := c.tcHooks
	deferred := false
	if c.preparedTCHooks != nil {
		target = c.preparedTCHooks.active
		deferred = true
	}
	if target == nil {
		target = newTCHookSet(c.log)
		c.tcHooks = target
	}
	c.tcHookStage = target
	c.tcHookStageDeferred = deferred
	c.tcHookMu.Unlock()

	if err := target.beginReplace(); err != nil {
		c.clearTCHookStage(target)
		return err
	}
	return nil
}

func (c *controlPlaneCore) stageTCHook(spec tcHookSpec) error {
	if c == nil {
		return nil
	}
	c.tcHookMu.Lock()
	stage := c.tcHookStage
	owned := c.tcHooks
	c.tcHookMu.Unlock()
	if stage != nil {
		return stage.stage(spec)
	}
	if owned == nil {
		return fmt.Errorf("TC HookSet is unavailable")
	}
	return owned.upsert(spec)
}

func (c *controlPlaneCore) removeTCHooksForInterface(scope tcHookScope, ifindex int) error {
	if c == nil {
		return nil
	}
	c.tcHookMu.Lock()
	stage := c.tcHookStage
	owned := c.tcHooks
	c.tcHookMu.Unlock()
	if stage != nil {
		return stage.stageRemoveInterface(scope, ifindex)
	}
	if owned == nil {
		return nil
	}
	return owned.removeInterface(scope, ifindex)
}

func (c *controlPlaneCore) commitTCHookReplace() error {
	if c == nil {
		return nil
	}
	c.tcHookMu.Lock()
	stage := c.tcHookStage
	deferred := c.tcHookStageDeferred
	c.tcHookMu.Unlock()
	if stage == nil {
		return nil
	}
	if err := stage.commit(); err != nil {
		// Resolve the transaction here before dropping the stage pointer:
		// the deferred abortTCHookReplace below the failure path reads
		// tcHookStage, so once cleared it becomes a no-op and a partial
		// transaction would stay wedged in the active set — rejecting every
		// later upsert/beginReplace until restart. abort() re-applies the
		// pre-transaction snapshot for a partial commit (see tcHookSet) and
		// is a harmless no-op when the internal restore already converged.
		if abortErr := stage.abort(); abortErr != nil {
			c.log.Errorf("abort TC hook stage after failed commit: %v", abortErr)
			err = stderrors.Join(err, abortErr)
		}
		c.clearTCHookStage(stage)
		return err
	}
	if !deferred {
		stage.finalize()
		c.clearTCHookStage(stage)
	}
	return nil
}

func (c *controlPlaneCore) abortTCHookReplace() error {
	if c == nil {
		return nil
	}
	c.tcHookMu.Lock()
	stage := c.tcHookStage
	c.tcHookMu.Unlock()
	if stage == nil {
		return nil
	}
	err := stage.abort()
	c.clearTCHookStage(stage)
	return err
}

func (c *controlPlaneCore) rollbackPreparedTCHooks() error {
	if c == nil {
		return nil
	}
	c.tcHookMu.Lock()
	state := c.preparedTCHooks
	stage := c.tcHookStage
	c.tcHookMu.Unlock()
	if state == nil {
		return nil
	}
	if stage == nil {
		stage = state.active
	}
	err := stage.rollback()
	c.clearTCHookStage(stage)
	return err
}

func (c *controlPlaneCore) finalizePreparedTCHooks() error {
	if c == nil {
		return nil
	}
	c.tcHookMu.Lock()
	state := c.preparedTCHooks
	stage := c.tcHookStage
	c.tcHookMu.Unlock()
	if state == nil {
		return nil
	}
	if !state.adopted {
		return fmt.Errorf("cannot finalize TC HookSet before ownership adoption")
	}
	if stage == nil {
		stage = state.active
	}
	stage.finalize()
	c.clearTCHookStage(stage)
	c.tcHookMu.Lock()
	c.preparedTCHooks = nil
	c.tcHookMu.Unlock()
	return nil
}

func (c *controlPlaneCore) clearPreparedTCHookHandoff() error {
	if c == nil {
		return nil
	}
	c.tcHookMu.Lock()
	defer c.tcHookMu.Unlock()
	if c.preparedTCHooks != nil {
		if c.preparedTCHooks.adopted {
			return fmt.Errorf("cannot clear adopted TC HookSet handoff")
		}
		if c.preparedTCHooks.active.hasTransaction() {
			return fmt.Errorf("cannot clear TC HookSet handoff with an active transaction")
		}
	}
	c.preparedTCHooks = nil
	return nil
}

func (c *controlPlaneCore) clearTCHookStage(expected *tcHookSet) {
	c.tcHookMu.Lock()
	if c.tcHookStage == expected {
		c.tcHookStage = nil
		c.tcHookStageDeferred = false
	}
	c.tcHookMu.Unlock()
}

// PrepareTCHookHandoff borrows the previous generation's HookSet for a
// reversible kernel commit while ownership remains with the active generation.
func (c *ControlPlane) PrepareTCHookHandoff(previous *ControlPlane) error {
	if c == nil || c.core == nil || previous == nil || previous.core == nil {
		return fmt.Errorf("missing control plane for TC HookSet handoff")
	}
	return c.core.prepareTCHookHandoff(previous.core)
}

// AdoptPreparedTCHookSet atomically swaps userspace ownership after the kernel
// HookSet transaction has committed and before the supervisor publishes it.
func (c *ControlPlane) AdoptPreparedTCHookSet(previous *ControlPlane) error {
	if c == nil || c.core == nil || previous == nil || previous.core == nil {
		return fmt.Errorf("missing control plane for TC HookSet adoption")
	}
	return c.core.adoptPreparedTCHookSet(previous.core)
}

// RestorePreparedTCHookSet returns ownership to the previous generation before
// rolling back a failed publish.
func (c *ControlPlane) RestorePreparedTCHookSet(previous *ControlPlane) error {
	if c == nil || c.core == nil || previous == nil || previous.core == nil {
		return nil
	}
	return c.core.restorePreparedTCHookSet(previous.core)
}

// FinalizePreparedTCHooks releases rollback-only old program references after
// supervisor publication can no longer fail.
func (c *ControlPlane) FinalizePreparedTCHooks() error {
	if c == nil || c.core == nil {
		return nil
	}
	return c.core.finalizePreparedTCHooks()
}

// ClearPreparedTCHookHandoff clears a non-adopted handoff after rollback.
func (c *ControlPlane) ClearPreparedTCHookHandoff() error {
	if c == nil || c.core == nil {
		return nil
	}
	return c.core.clearPreparedTCHookHandoff()
}
