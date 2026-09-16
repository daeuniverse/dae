/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	stderrors "errors"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/sirupsen/logrus"
)

var (
	// relayHalfCloseTimeout bounds how long the peer of a half-closed relay
	// may still deliver data after our side sent EOF.
	relayHalfCloseTimeout = envOverrideDuration("DAE_TCP_RELAY_HALF_CLOSE_TIMEOUT", 10*time.Second)
	// relayIdleTimeout bounds how long a relay may sit with zero traffic in
	// both directions before it is force-closed. A half-open peer (vanished
	// without FIN/RST) otherwise parks the directional read forever and the
	// relay leaks. Any traffic in either direction refreshes lastActive, so
	// long-lived but active connections (SSH, gaming) are never touched.
	//
	// Applications that legitimately stay silent for long stretches (idle
	// database CLI sessions, MQTT keepalives longer than the default, long
	// CONNECT tunnels) can raise this via DAE_TCP_RELAY_IDLE_TIMEOUT
	// without recompiling. It is a var rather than a const so deployments
	// can retune reclaim pressure per environment; the config-file grammar
	// does not carry this knob.
	relayIdleTimeout = envOverrideDuration("DAE_TCP_RELAY_IDLE_TIMEOUT", 5*time.Minute)
	// relayIdleCheckInterval is the watchdog cadence for idle reclamation.
	relayIdleCheckInterval = 30 * time.Second
	// relayCancelNudgeInterval only applies after cancellation. At that point,
	// prompt teardown matters more than avoiding deadline syscalls.
	relayCancelNudgeInterval = 100 * time.Millisecond
)

// envOverrideDuration applies an optional process-level override for tunables
// that are not exposed through the config-file grammar. Invalid or non-positive
// values fall back to def with a warning instead of silently misbehaving.
func envOverrideDuration(name string, def time.Duration) time.Duration {
	raw := os.Getenv(name)
	if raw == "" {
		return def
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		logrus.StandardLogger().Warnf("invalid %s=%q, using default %s", name, raw, def)
		return def
	}
	return d
}

type relayCore struct {
	left  netproxy.Conn
	right netproxy.Conn

	copyEngine       relayCopyEngine
	halfCloseTimeout time.Duration
	idleTimeout      time.Duration
	idleCheckPeriod  time.Duration
	leftRecord       func(int64)
	rightRecord      func(int64)

	// lastActiveNano is the last time either direction read or wrote data.
	// Guarded by atomic; updated by the copy engines via onActive.
	lastActiveNano atomic.Int64
	// halfClosed is set after one direction EOFs and CloseWrite's the peer.
	// Remaining traffic then rolls the half-close read deadline (idle-based,
	// not a one-shot 10s cut of a still-active download).
	halfClosed atomic.Bool
}

type relayDirection struct {
	name   string
	src    netproxy.Conn
	dst    netproxy.Conn
	record func(int64)
}

type relayResult struct {
	dir string
	err error
}

func newRelayCore(lConn, rConn netproxy.Conn, leftRecord func(int64), rightRecord func(int64)) *relayCore {
	return &relayCore{
		left:             lConn,
		right:            rConn,
		copyEngine:       defaultRelayCopyEngine{},
		halfCloseTimeout: relayHalfCloseTimeout,
		idleTimeout:      relayIdleTimeout,
		idleCheckPeriod:  relayIdleCheckInterval,
		leftRecord:       leftRecord,
		rightRecord:      rightRecord,
	}
}

func (c *relayCore) run(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithCancel(ctx)
	watchDone := make(chan struct{})

	results := make(chan relayResult, 2)
	var relayDone atomic.Bool
	var forceCloseOnce sync.Once

	// nudgeReads repeatedly pokes SetReadDeadline on both conns. quic-go
	// (hy2/tuic) may not synchronously unblock a Read after a single
	// SetReadDeadline + Close: the blocked goroutine can remain parked in
	// an internal channel receive. Repeatedly advancing the deadline gives
	// the runtime additional wake-up opportunities without harming already-
	// closed conns (SetReadDeadline on a closed conn returns an error we
	// ignore). TCP conns unblock on the very first nudge, so the loop is
	// a no-op for them thereafter.
	nudgeReads := func() {
		past := time.Unix(1, 0)
		_ = c.left.SetReadDeadline(past)
		_ = c.right.SetReadDeadline(past)
	}

	forceClose := func() {
		forceCloseOnce.Do(func() {
			nudgeReads()
			_ = c.left.Close()
			_ = c.right.Close()
		})
	}

	// LIFO on return: close watchDone before canceling the derived context,
	// so a normally completed relay doesn't close already-finished sockets.
	defer cancel()
	defer close(watchDone)

	// Idle watchdog: half-open peers (vanished without FIN/RST) never return
	// from their directional read, so without a bound the relay goroutine pair
	// leaks. Any traffic in either direction refreshes lastActiveNano; only a
	// fully idle relay is reclaimed.
	//
	// The watchdog handles ctx cancellation without exiting. For QUIC streams
	// (hy2/tuic), SetReadDeadline and even Close/CancelRead may not synchronously
	// unblock a pending Read in quic-go. It therefore disables the one-shot
	// ctx case after cancellation and keeps nudging on its ticker until both
	// directions finish.
	c.lastActiveNano.Store(time.Now().UnixNano())
	idleTimeout := c.idleTimeout
	if idleTimeout <= 0 {
		idleTimeout = relayIdleTimeout
	}
	checkPeriod := c.idleCheckPeriod
	if checkPeriod <= 0 {
		checkPeriod = relayIdleCheckInterval
	}
	go func() {
		ctxDone := ctx.Done()
		ctxCanceled := false
		ticker := time.NewTicker(checkPeriod)
		defer ticker.Stop()
		for {
			select {
			case <-watchDone:
				return
			case <-ctxDone:
				if relayDone.Load() {
					return
				}
				// Close once on cancellation, then disable this closed-channel
				// case so a stuck QUIC relay cannot spin before the next nudge.
				forceClose()
				ctxCanceled = true
				ctxDone = nil
				ticker.Reset(relayCancelNudgeInterval)
			case <-ticker.C:
				if ctxCanceled {
					// Keep nudging after cancellation — quic-go may need
					// multiple deadline pokes to unblock a parked Read.
					nudgeReads()
					continue
				}
				if time.Since(time.Unix(0, c.lastActiveNano.Load())) > idleTimeout {
					// Idle reclaim enters the same nudge mode as external
					// cancellation; a QUIC Read may survive the first Close.
					cancel()
					forceClose()
					ctxCanceled = true
					ctxDone = nil
					ticker.Reset(relayCancelNudgeInterval)
				}
			}
		}
	}()

	runDirection := func(dir relayDirection) {
		// Coalesce activity refreshes to ~4Hz per direction: the watchdog
		// only needs second-level granularity, and per-chunk atomic stores
		// on the shared lastActiveNano word showed measurable cross-core
		// contention under multi-core relaying.
		var lastRefreshNano int64
		const refreshInterval = int64(250 * time.Millisecond)
		onActive := func(_ int64) {
			now := time.Now().UnixNano()
			if now-lastRefreshNano < refreshInterval {
				return
			}
			lastRefreshNano = now
			c.lastActiveNano.Store(now)
			if c.halfClosed.Load() {
				_ = dir.src.SetReadDeadline(time.Now().Add(c.halfCloseTimeout))
			}
		}
		_, err := c.copyEngine.Copy(ctx, dir.dst, dir.src, dir.record, onActive)

		closeWriteRelayConn(dir.dst)

		if err != nil {
			// Any directional copy error is treated as terminal for this relay:
			// cancel shared context and force-close both sides to promptly
			// unblock pending reads/writes in the peer direction.
			cancel()
			forceClose()
		} else {
			// Graceful half-close: idle-bound the peer's pending read on
			// dir.dst (source of the opposite direction). Activity in the
			// remaining direction rolls the deadline via onActive.
			c.lastActiveNano.Store(time.Now().UnixNano())
			c.halfClosed.Store(true)
			_ = dir.dst.SetReadDeadline(time.Now().Add(c.halfCloseTimeout))
		}

		results <- relayResult{
			dir: dir.name,
			err: err,
		}
	}

	go runDirection(relayDirection{
		name:   "l2r",
		src:    c.left,
		dst:    c.right,
		record: c.rightRecord,
	})
	go runDirection(relayDirection{
		name:   "r2l",
		src:    c.right,
		dst:    c.left,
		record: c.leftRecord,
	})

	first := <-results
	second := <-results
	relayDone.Store(true)
	return mergeRelayErrors(first.err, second.err)
}

// mergeRelayErrors combines errors from both relay directions.
// Uses errors.Join to preserve both errors for inspection with errors.Is/As.
func mergeRelayErrors(err1, err2 error) error {
	return stderrors.Join(err1, err2)
}
