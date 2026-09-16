/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/control"
	"github.com/sirupsen/logrus"
)

func notifyRunStateChange(runStateChanges chan<- struct{}) {
	select {
	case runStateChanges <- struct{}{}:
	default:
	}
}

func beginReloadHandoff(reloading *atomic.Bool, runStateChanges chan<- struct{}) {
	if reloading != nil {
		reloading.Store(true)
	}
	notifyRunStateChange(runStateChanges)
}

func waitForControlPlaneDrain(
	log *logrus.Logger,
	ctx context.Context,
	c reloadRetirementControlPlane,
	maxWait time.Duration,
	logEvery time.Duration,
) controlPlaneDrainWaitResult {
	if c == nil || c.ActiveSessionCount() == 0 {
		return controlPlaneDrainIdle
	}

	idleCh := c.DrainIdleCh()

	timer := time.NewTimer(maxWait)
	defer timer.Stop()

	var ticker *time.Ticker
	var tickCh <-chan time.Time
	if logEvery > 0 {
		ticker = time.NewTicker(logEvery)
		defer ticker.Stop()
		tickCh = ticker.C
	}

	for {
		select {
		case <-ctx.Done():
			return controlPlaneDrainCanceled
		case <-idleCh:
			return controlPlaneDrainIdle
		case <-timer.C:
			return controlPlaneDrainTimeout
		case <-tickCh:
			if log != nil && log.IsLevelEnabled(logrus.DebugLevel) {
				log.WithField("active_sessions", c.ActiveSessionCount()).
					Debugln("[Reload] Old control plane still draining active sessions")
			}
		}
	}
}

func retireControlPlaneConnections(
	log *logrus.Logger,
	ctx context.Context,
	c retirementDrainPlane,
	abort bool,
	maxDrain time.Duration,
) {
	// Retirement is two-stage: either abort everything when explicitly
	// requested, or drain and then abort only the generation-owned pending
	// work. Established connections are never aborted on a drain path: the
	// successor generation is already serving those flows (see b7fb496d).
	switch {
	case abort:
		log.Warnln("[Reload] Abort requested; aborting stale connections immediately")
		if err := c.AbortConnections(); err != nil {
			log.WithError(err).Warnln("[Reload] Failed to abort stale connections")
		}
	default:
		switch waitForControlPlaneDrain(log, ctx, c, maxDrain, controlPlaneRetirementLogEvery) {
		case controlPlaneDrainIdle:
			log.Infoln("[Reload] Old control plane drained active sessions; retiring immediately")
		case controlPlaneDrainCanceled:
			log.Warnln("[Reload] Retirement canceled; aborting generation-owned pending work")
			if err := c.AbortPendingConnections(); err != nil {
				log.WithError(err).Warnln("[Reload] Failed to abort pending connections")
			}
		case controlPlaneDrainTimeout:
			log.WithField("active_sessions", c.ActiveSessionCount()).
				Warnln("[Reload] Old control plane drain timed out; aborting pending generation work")
			if err := c.AbortPendingConnections(); err != nil {
				log.WithError(err).Warnln("[Reload] Failed to abort pending connections")
			}
		}
	}
	// Seal generation admission on every retirement path and wait for any lease
	// acquired before abort/drain committed to closing the owner. Bound the
	// IdleCh wait with the same maxDrain used above so a stuck ticket cannot
	// pin retirement forever.
	c.StopRoutingEpochExecutionWithTimeout(maxDrain)
}

func shutdownAfterSignalWithHandoff(
	log *logrus.Logger,
	listener signalShutdownListener,
	c signalShutdownControlPlane,
	netns signalShutdownNetns,
	fastExit bool,
	handoff *signalShutdownStagedHandoff,
) error {
	closeListener := func(listener signalShutdownListener) {
		if listener == nil {
			return
		}
		if e := listener.Close(); e != nil {
			log.Warnf("close listener: %v", e)
		}
	}
	detachPlane := func(c signalShutdownControlPlane) {
		if c == nil {
			return
		}
		if e := c.DetachBpfHooks(); e != nil {
			log.Warnf("detach BPF hooks: %v", e)
		}
	}
	abortAndClosePlane := func(c signalShutdownControlPlane) error {
		if c == nil {
			return nil
		}
		if e := c.AbortConnections(); e != nil {
			log.Warnf("abort connections: %v", e)
		}
		if e := c.Close(); e != nil {
			return e
		}
		return nil
	}

	closeListener(listener)
	if handoff != nil {
		if handoff.oldListener != nil && handoff.oldListener != listener {
			closeListener(handoff.oldListener)
		}
		if handoff.newListener != nil && handoff.newListener != listener && handoff.newListener != handoff.oldListener {
			closeListener(handoff.newListener)
		}
	}

	detachPlane(c)
	if handoff != nil {
		if handoff.oldControlPlane != nil && handoff.oldControlPlane != c {
			detachPlane(handoff.oldControlPlane)
		}
		if handoff.newControlPlane != nil && handoff.newControlPlane != c && handoff.newControlPlane != handoff.oldControlPlane {
			detachPlane(handoff.newControlPlane)
		}
	}

	// Always tear down the dae netns first, even on fast exit. Closing the
	// netns removes the dae0/dae0peer netkit (or veth) pair and the named
	// netns /run/netns/daens, and is cheap. Leaving it behind leaks kernel
	// state after every stop and can break a subsequent restart.
	if netns != nil {
		if e := netns.Close(); e != nil {
			log.Warnf("close dae netns: %v", e)
		}
	}

	if fastExit {
		log.Infoln("[Shutdown] Fast exit enabled; skipping in-process control-plane teardown. Residual connection state will be purged on next startup.")
		return nil
	}
	if handoff != nil {
		if handoff.oldCancel != nil {
			handoff.oldCancel()
		}
		if handoff.newCancel != nil {
			handoff.newCancel()
		}
	}

	var closeErrs []error
	if err := abortAndClosePlane(c); err != nil {
		closeErrs = append(closeErrs, err)
	}
	if handoff != nil {
		if handoff.oldControlPlane != nil && handoff.oldControlPlane != c {
			if err := abortAndClosePlane(handoff.oldControlPlane); err != nil {
				closeErrs = append(closeErrs, err)
			}
		}
		if handoff.newControlPlane != nil && handoff.newControlPlane != c && handoff.newControlPlane != handoff.oldControlPlane {
			if err := abortAndClosePlane(handoff.newControlPlane); err != nil {
				closeErrs = append(closeErrs, err)
			}
		}
	}
	// After all control planes are closed, reset global UDP state to stop
	// background janitors and release pooled sockets. This must only run during
	// process shutdown; hot reload must never reset shared global pools.
	control.ResetGlobalUdpState()

	if len(closeErrs) > 0 {
		return fmt.Errorf("close control plane: %w", errors.Join(closeErrs...))
	}
	return nil
}
