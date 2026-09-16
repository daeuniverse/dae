/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	stderrors "errors"
	"fmt"
	"time"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/component/routing"
)

const (
	routingEpochSlotCount                = 2
	routingEpochSlotUnset                = ^uint32(0)
	routingEpochCleanupMaxAttempts       = 5
	routingEpochCleanupInitialRetryDelay = 25 * time.Millisecond
	routingEpochCleanupMaximumRetryDelay = 200 * time.Millisecond
	// routingEpochActiveSlotCacheTTL bounds how long readActiveRoutingEpochSlot
	// reuses a cached active slot. The slot only changes on publish/rollback,
	// so a stale cache is correct except inside a reload cut-over window, where
	// the retiring generation may keep consulting/writing the shared endpoint
	// pool for up to TTL; such writes carry slot/generation stamps and are
	// filtered downstream by routingEpochExecutionMatches.
	routingEpochActiveSlotCacheTTL = 50 * time.Millisecond
)

type (
	routingEpochCleanupWaitFunc func(context.Context, time.Duration) error
	routingEpochMapCleanupFunc  func(*bpfObjects, uint32) error
)

func waitForRoutingEpochCleanupRetry(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func routingEpochCleanupRetryDelay(attempt int) time.Duration {
	delay := routingEpochCleanupInitialRetryDelay << max(attempt-1, 0)
	return min(delay, routingEpochCleanupMaximumRetryDelay)
}

func retryPreviousRoutingEpochCleanup(
	ctx context.Context,
	cleanup func() error,
	wait routingEpochCleanupWaitFunc,
) error {
	if cleanup == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if wait == nil {
		wait = waitForRoutingEpochCleanupRetry
	}

	var lastErr error
	for attempt := 1; attempt <= routingEpochCleanupMaxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			if lastErr == nil {
				return fmt.Errorf("routing epoch cleanup canceled before attempt %d: %w", attempt, err)
			}
			return fmt.Errorf(
				"routing epoch cleanup canceled after %d attempts: %w",
				attempt-1,
				stderrors.Join(lastErr, err),
			)
		}

		lastErr = cleanup()
		if lastErr == nil {
			return nil
		}
		if attempt == routingEpochCleanupMaxAttempts {
			break
		}
		if err := wait(ctx, routingEpochCleanupRetryDelay(attempt)); err != nil {
			return fmt.Errorf(
				"routing epoch cleanup interrupted after %d attempts: %w",
				attempt,
				stderrors.Join(lastErr, err),
			)
		}
	}

	return fmt.Errorf(
		"routing epoch cleanup failed after %d attempts: %w",
		routingEpochCleanupMaxAttempts,
		lastErr,
	)
}

type routingEpochActiveSlotSnapshot struct {
	slot             uint32
	cachedAtUnixNano int64
	valid            bool
	publishing       bool
}

type routingEpochActiveSlotCacheEntry struct {
	core     *controlPlaneCore
	previous *routingEpochActiveSlotSnapshot
}

type routingEpochActiveSlotCachePublication struct {
	entries []routingEpochActiveSlotCacheEntry
}

func validRoutingEpochSlot(slot uint32) bool {
	return slot < routingEpochSlotCount
}

func (c *controlPlaneCore) hasActiveRoutingEpochMap(bpf *bpfObjects) bool {
	return bpf != nil && bpf.ActiveRoutingEpochMap != nil
}

func (c *controlPlaneCore) clearStagedRoutingEpochLocked() {
	c.routingEpochStaged = false
	c.routingEpochStagedSlot = routingEpochSlotUnset
	c.routingEpochStagedEpoch = 0
}

func (c *controlPlaneCore) hasStagedRoutingEpochLocked(slot uint32, epoch uint64) bool {
	return c.routingEpochStaged && c.routingEpochStagedSlot == slot && c.routingEpochStagedEpoch == epoch
}

func (c *controlPlaneCore) cacheActiveRoutingEpochSlot(observed *routingEpochActiveSlotSnapshot, slot uint32) bool {
	if observed != nil && observed.publishing {
		return false
	}
	return c.routingEpochActiveSlotCache.CompareAndSwap(observed, &routingEpochActiveSlotSnapshot{
		slot:             slot,
		cachedAtUnixNano: time.Now().UnixNano(),
		valid:            true,
	})
}

func (c *controlPlaneCore) publishActiveRoutingEpochSlotCache(slot uint32) {
	c.routingEpochActiveSlotCache.Store(&routingEpochActiveSlotSnapshot{
		slot:             slot,
		cachedAtUnixNano: time.Now().UnixNano(),
		valid:            true,
	})
}

func (c *controlPlaneCore) invalidateActiveRoutingEpochSlotCache() *routingEpochActiveSlotSnapshot {
	// Swap in a unique token so a lookup that began before invalidation cannot
	// successfully compare-and-swap its stale result after the selector flips.
	return c.routingEpochActiveSlotCache.Swap(&routingEpochActiveSlotSnapshot{publishing: true})
}

func beginRoutingEpochActiveSlotCachePublication(primary *controlPlaneCore, peers ...*controlPlaneCore) routingEpochActiveSlotCachePublication {
	publication := routingEpochActiveSlotCachePublication{
		entries: make([]routingEpochActiveSlotCacheEntry, 0, 1+len(peers)),
	}
	add := func(core *controlPlaneCore) {
		if core == nil {
			return
		}
		for _, entry := range publication.entries {
			if entry.core == core {
				return
			}
		}
		publication.entries = append(publication.entries, routingEpochActiveSlotCacheEntry{
			core:     core,
			previous: core.invalidateActiveRoutingEpochSlotCache(),
		})
	}
	add(primary)
	for _, peer := range peers {
		add(peer)
	}
	return publication
}

func (p routingEpochActiveSlotCachePublication) publish(slot uint32) {
	for _, entry := range p.entries {
		entry.core.publishActiveRoutingEpochSlotCache(slot)
	}
}

func (p routingEpochActiveSlotCachePublication) restore() {
	for _, entry := range p.entries {
		entry.core.routingEpochActiveSlotCache.Store(entry.previous)
	}
}

func (c *controlPlaneCore) readActiveRoutingEpochSlot() (uint32, error) {
	if c == nil {
		return 0, nil
	}
	for {
		observed := c.routingEpochActiveSlotCache.Load()
		nowNano := time.Now().UnixNano()
		if observed != nil && observed.valid {
			// delta >= 0 guards against wall-clock rollback (NTP step) widening the stale window.
			if delta := nowNano - observed.cachedAtUnixNano; delta >= 0 && delta < int64(routingEpochActiveSlotCacheTTL) {
				return observed.slot, nil
			}
		}
		bpf := c.PeekBpf()
		if !c.hasActiveRoutingEpochMap(bpf) {
			return 0, nil
		}
		var slot uint32
		if err := bpf.ActiveRoutingEpochMap.Lookup(uint32(0), &slot); err != nil {
			return 0, fmt.Errorf("lookup active routing epoch slot: %w", err)
		}
		if !validRoutingEpochSlot(slot) {
			return 0, fmt.Errorf("active routing epoch slot %d is invalid", slot)
		}
		if observed != nil && observed.publishing {
			// A selector update owns the cache token. Return the map result for
			// this call, but do not make it outlive the in-progress cutover.
			return slot, nil
		}
		if c.cacheActiveRoutingEpochSlot(observed, slot) {
			return slot, nil
		}
		// A selector publisher replaced the cache token while the map lookup
		// was in flight. Retry instead of letting the stale lookup overwrite
		// the publisher's slot.
	}
}

func (c *ControlPlane) publishRoutingEpoch() error {
	if c == nil || c.core == nil {
		return nil
	}
	c.routingEpochPeerMu.RLock()
	defer c.routingEpochPeerMu.RUnlock()
	var peerCore *controlPlaneCore
	if c.routingEpochPeer != nil {
		peerCore = c.routingEpochPeer.core
	}
	return c.core.PublishRoutingEpoch(peerCore)
}

func (c *ControlPlane) rollbackRoutingEpoch() error {
	if c == nil || c.core == nil {
		return nil
	}
	c.routingEpochPeerMu.RLock()
	defer c.routingEpochPeerMu.RUnlock()
	var peerCore *controlPlaneCore
	if c.routingEpochPeer != nil {
		peerCore = c.routingEpochPeer.core
	}
	return c.core.RollbackRoutingEpoch(peerCore)
}

// PrepareRoutingEpoch reserves the route-plan slot used by this control-plane
// generation. Shared BPF reloads prepare the inactive slot; fresh datapaths
// use their zero-initialized active slot.
func (c *controlPlaneCore) PrepareRoutingEpoch(epoch routing.PolicyEpoch, sharedReload bool) (uint32, error) {
	if c == nil {
		return 0, nil
	}
	if epoch == 0 {
		return 0, fmt.Errorf("routing policy epoch must be non-zero")
	}

	c.routingEpochMu.Lock()
	defer c.routingEpochMu.Unlock()
	c.clearStagedRoutingEpochLocked()

	active, err := c.readActiveRoutingEpochSlot()
	if err != nil {
		return 0, err
	}
	target := active
	if sharedReload {
		target ^= 1
		c.routingEpochPreviousSlot.Store(active)
	} else {
		// A fresh datapath has an isolated, zero-initialized selector. Its
		// predecessor remains owned by the old hook and is not a projection in
		// these maps that can be rolled back or retired.
		c.routingEpochPreviousSlot.Store(routingEpochSlotUnset)
	}
	c.routingEpochRollbackOff.Store(false)
	c.routingEpochSlot.Store(target)
	c.routingEpochPolicyEpoch.Store(uint64(epoch))
	return target, nil
}

func (c *controlPlaneCore) RoutingEpochSlot() uint32 {
	if c == nil {
		return 0
	}
	if slot := c.routingEpochSlot.Load(); validRoutingEpochSlot(slot) {
		return slot
	}
	return 0
}

func (c *controlPlaneCore) routingEpochEnabled() bool {
	if c == nil {
		return false
	}
	return c.hasActiveRoutingEpochMap(c.PeekBpf()) && validRoutingEpochSlot(c.routingEpochSlot.Load())
}

// StageRoutingEpoch records the policy epoch for this generation's prepared
// slot. The selector is deliberately not changed here. The policy epoch is
// owned by the control plane; the datapath only needs the active slot and its
// routing metadata length.
func (c *controlPlaneCore) StageRoutingEpoch() error {
	if c == nil {
		return nil
	}
	c.routingEpochMu.Lock()
	defer c.routingEpochMu.Unlock()
	c.clearStagedRoutingEpochLocked()

	bpf := c.PeekBpf()
	if !c.hasActiveRoutingEpochMap(bpf) {
		return nil
	}
	slot := c.routingEpochSlot.Load()
	epoch := c.routingEpochPolicyEpoch.Load()
	if !validRoutingEpochSlot(slot) {
		return fmt.Errorf("routing epoch slot %d is invalid", slot)
	}
	if epoch == 0 {
		return fmt.Errorf("routing epoch slot %d has no policy epoch", slot)
	}
	c.routingEpochStaged = true
	c.routingEpochStagedSlot = slot
	c.routingEpochStagedEpoch = epoch
	return nil
}

// PublishRoutingEpoch atomically changes the slot consulted by route(). Call
// it only after the selected slot's rules, LPM tries, and domain projection
// have all been prepared.
//
// ROUTING-EPOCH-1 contract: reload orchestration is the single writer for a linked
// pair. Per-core routingEpochMu does not serialize a concurrent publisher on
// the peer, so any future parallel publication must add lifecycle-level
// serialization around the complete selector/cache transaction. See the
// ROUTING-EPOCH-1 section in docs/weak-memory-publication-audit.md.
func (c *controlPlaneCore) PublishRoutingEpoch(peerCaches ...*controlPlaneCore) error {
	if c == nil {
		return nil
	}
	c.routingEpochMu.Lock()
	defer c.routingEpochMu.Unlock()

	bpf := c.PeekBpf()
	if !c.hasActiveRoutingEpochMap(bpf) {
		return nil
	}
	slot := c.routingEpochSlot.Load()
	epoch := c.routingEpochPolicyEpoch.Load()
	if !validRoutingEpochSlot(slot) || epoch == 0 || !c.hasStagedRoutingEpochLocked(slot, epoch) {
		return fmt.Errorf("routing epoch slot %d with policy epoch %d has not been staged", slot, epoch)
	}
	publication := beginRoutingEpochActiveSlotCachePublication(c, peerCaches...)
	if err := bpf.ActiveRoutingEpochMap.Update(uint32(0), slot, ebpf.UpdateAny); err != nil {
		publication.restore()
		return fmt.Errorf("publish routing epoch slot %d: %w", slot, err)
	}
	publication.publish(slot)
	return nil
}

// RollbackRoutingEpoch restores the slot that was active when this generation
// began preparation. It does not mutate either plan's maps.
func (c *controlPlaneCore) RollbackRoutingEpoch(peerCaches ...*controlPlaneCore) error {
	if c == nil {
		return nil
	}
	c.routingEpochMu.Lock()
	defer c.routingEpochMu.Unlock()

	bpf := c.PeekBpf()
	if !c.hasActiveRoutingEpochMap(bpf) {
		return nil
	}
	if c.routingEpochRollbackOff.Load() {
		return nil
	}
	previous := c.routingEpochPreviousSlot.Load()
	if !validRoutingEpochSlot(previous) {
		return nil
	}
	publication := beginRoutingEpochActiveSlotCachePublication(c, peerCaches...)
	if err := bpf.ActiveRoutingEpochMap.Update(uint32(0), previous, ebpf.UpdateAny); err != nil {
		publication.restore()
		return fmt.Errorf("rollback routing epoch slot %d: %w", previous, err)
	}
	publication.publish(previous)
	return nil
}

func clearPreviousRoutingEpochMaps(bpf *bpfObjects, previous uint32) error {
	var errs []error
	if bpf != nil && bpf.RoutingMetaMap != nil {
		if err := bpf.RoutingMetaMap.Update(previous, uint32(0), ebpf.UpdateAny); err != nil {
			errs = append(errs, fmt.Errorf("clear routing metadata for slot %d: %w", previous, err))
		}
	}
	if err := clearReloadDomainRoutingMapSlot(bpf, previous); err != nil {
		errs = append(errs, err)
	}
	return stderrors.Join(errs...)
}

// finalizePreviousRoutingEpoch releases the inactive domain projection after
// the previous generation has drained and rollback is no longer possible.
//
// ROUTING-EPOCH-2 contract: userspace retirement is currently the only
// quiescence barrier before old-slot cleanup. There is no proven kernel grace
// period covering a TC invocation that sampled the old selector before the
// flip. Do not move this cleanup earlier or make it concurrent with cutover
// without supported-kernel evidence that those invocations have quiesced. See
// the ROUTING-EPOCH-2 section in docs/weak-memory-publication-audit.md.
func (c *controlPlaneCore) finalizePreviousRoutingEpoch() error {
	return c.finalizePreviousRoutingEpochWithCleanup(clearPreviousRoutingEpochMaps)
}

func (c *controlPlaneCore) finalizePreviousRoutingEpochWithCleanup(cleanup routingEpochMapCleanupFunc) error {
	if c == nil || c.routingEpochPolicyEpoch.Load() == 0 {
		return nil
	}
	if cleanup == nil {
		cleanup = clearPreviousRoutingEpochMaps
	}

	for {
		previous := c.routingEpochPreviousSlot.Load()
		if !validRoutingEpochSlot(previous) {
			return nil
		}

		// Projection writers take this lock before consulting the slot tracker.
		// Preserve that ordering while excluding a final write to the retiring
		// slot and serializing against prepare/publish/rollback.
		c.domainRoutingProjectionMu[previous].Lock()
		c.routingEpochMu.Lock()
		if c.routingEpochPreviousSlot.Load() != previous {
			c.routingEpochMu.Unlock()
			c.domainRoutingProjectionMu[previous].Unlock()
			continue
		}

		active, err := c.readActiveRoutingEpochSlot()
		if err != nil {
			c.routingEpochMu.Unlock()
			c.domainRoutingProjectionMu[previous].Unlock()
			return err
		}
		current := c.routingEpochSlot.Load()
		if !validRoutingEpochSlot(current) || active != current || previous == current {
			c.routingEpochMu.Unlock()
			c.domainRoutingProjectionMu[previous].Unlock()
			return fmt.Errorf(
				"cannot retire routing epoch slot %d while active=%d current=%d",
				previous,
				active,
				current,
			)
		}

		// Disable rollback before erasing the previous projection. The caller
		// reaches this method only after the old generation has drained and
		// closed, so retaining a selector back to partially cleared state would
		// be less safe than reporting a cleanup error.
		c.routingEpochRollbackOff.Store(true)
		bpf := c.PeekBpf()
		cleanupErr := cleanup(bpf, previous)

		c.domainRoutingSlots[previous] = newDomainRoutingTracker()
		if previous == 0 {
			c.domainRouting = c.domainRoutingSlots[previous]
		}
		if cleanupErr == nil {
			c.routingEpochPreviousSlot.Store(routingEpochSlotUnset)
		}
		c.routingEpochMu.Unlock()
		c.domainRoutingProjectionMu[previous].Unlock()
		return cleanupErr
	}
}

func (c *controlPlaneCore) domainRoutingTrackerForSlot(slot uint32) *domainRoutingTracker {
	if c == nil || !validRoutingEpochSlot(slot) {
		return nil
	}
	c.routingEpochMu.Lock()
	defer c.routingEpochMu.Unlock()
	if slot == 0 && c.domainRouting != nil && c.domainRoutingSlots[slot] == nil {
		c.domainRoutingSlots[slot] = c.domainRouting
	}
	if c.domainRoutingSlots[slot] == nil {
		c.domainRoutingSlots[slot] = newDomainRoutingTracker()
		if slot == 0 {
			c.domainRouting = c.domainRoutingSlots[slot]
		}
	}
	return c.domainRoutingSlots[slot]
}

func (c *controlPlaneCore) resetDomainRoutingSlot(slot uint32) {
	if c == nil || !validRoutingEpochSlot(slot) {
		return
	}
	c.routingEpochMu.Lock()
	c.domainRoutingSlots[slot] = newDomainRoutingTracker()
	if slot == 0 {
		c.domainRouting = c.domainRoutingSlots[slot]
	}
	c.routingEpochMu.Unlock()
}

func (c *controlPlaneCore) clearDomainRoutingSlot(slot uint32) error {
	if c == nil || !validRoutingEpochSlot(slot) {
		return nil
	}
	c.domainRoutingProjectionMu[slot].Lock()
	defer c.domainRoutingProjectionMu[slot].Unlock()
	if err := clearReloadDomainRoutingMapSlot(c.PeekBpf(), slot); err != nil {
		return err
	}
	c.resetDomainRoutingSlot(slot)
	return nil
}
