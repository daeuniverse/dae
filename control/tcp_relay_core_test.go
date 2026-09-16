/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

// blockingMockConn blocks on Read until closed; Write always succeeds.
type blockingMockConn struct {
	closed atomic.Bool
}

func (m *blockingMockConn) Read(b []byte) (int, error) {
	for !m.closed.Load() {
		time.Sleep(10 * time.Millisecond)
	}
	return 0, net.ErrClosed
}
func (m *blockingMockConn) Write(b []byte) (int, error) { return len(b), nil }
func (m *blockingMockConn) ReadFrom(p []byte) (int, netip.AddrPort, error) {
	return 0, netip.AddrPort{}, io.EOF
}
func (m *blockingMockConn) WriteTo(p []byte, addr string) (int, error) { return len(p), nil }
func (m *blockingMockConn) Close() error                               { m.closed.Store(true); return nil }
func (m *blockingMockConn) SetDeadline(t time.Time) error              { return nil }
func (m *blockingMockConn) SetReadDeadline(t time.Time) error          { return nil }
func (m *blockingMockConn) SetWriteDeadline(t time.Time) error         { return nil }

// A fully idle relay (both directions blocked on Read, no traffic) must be
// reclaimed by the idle watchdog.
func TestRelayIdleWatchdogReclaimsIdleRelay(t *testing.T) {
	l := &blockingMockConn{}
	r := &blockingMockConn{}
	rc := newRelayCore(l, r, nil, nil)
	// Inject a short idle bound and fast check cadence for the test.
	rc.idleTimeout = 200 * time.Millisecond
	rc.idleCheckPeriod = 50 * time.Millisecond

	ctx := t.Context()

	done := make(chan error, 1)
	go func() { done <- rc.run(ctx) }()

	select {
	case <-done:
		// run returned -> both directional copies were unblocked and the
		// relay reclaimed.
	case <-time.After(3 * time.Second):
		t.Fatal("idle relay was not reclaimed by the watchdog")
	}
}

// Active relays (traffic refreshing lastActiveNano) must NOT be reclaimed.
func TestRelayIdleWatchdogKeepsActiveRelay(t *testing.T) {
	l := &blockingMockConn{}
	r := &activeMockConn{}
	rc := newRelayCore(l, r, nil, nil)
	rc.idleTimeout = 300 * time.Millisecond
	rc.idleCheckPeriod = 50 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- rc.run(ctx) }()

	// Let the watchdog tick several times; an active relay must survive.
	time.Sleep(1 * time.Second)
	select {
	case err := <-done:
		t.Fatalf("active relay was reclaimed: %v", err)
	default:
	}
	cancel()
}

// activeMockConn produces a steady stream of reads so the relay is never idle.
type activeMockConn struct {
	closed atomic.Bool
	reads  atomic.Int64
}

func (m *activeMockConn) Read(b []byte) (int, error) {
	for !m.closed.Load() {
		if m.reads.Add(1) > 0 && m.reads.Load()%5 == 0 {
			b[0] = 'x'
			return 1, nil
		}
		time.Sleep(5 * time.Millisecond)
	}
	return 0, net.ErrClosed
}
func (m *activeMockConn) Write(b []byte) (int, error) { return len(b), nil }
func (m *activeMockConn) ReadFrom(p []byte) (int, netip.AddrPort, error) {
	return 0, netip.AddrPort{}, io.EOF
}
func (m *activeMockConn) WriteTo(p []byte, addr string) (int, error) { return len(p), nil }
func (m *activeMockConn) Close() error                               { m.closed.Store(true); return nil }
func (m *activeMockConn) SetDeadline(t time.Time) error              { return nil }
func (m *activeMockConn) SetReadDeadline(t time.Time) error          { return nil }
func (m *activeMockConn) SetWriteDeadline(t time.Time) error         { return nil }

// The idle watchdog must not interfere with graceful half-close semantics:
// a relay reclaimed by the watchdog returns promptly (its reads were
// unblocked by forceClose), whatever the surfaced error.
func TestRelayIdleWatchdogCoexistsWithHalfClose(t *testing.T) {
	l := &blockingMockConn{}
	rc := newRelayCore(l, l, nil, nil)
	rc.idleTimeout = 100 * time.Millisecond
	rc.idleCheckPeriod = 20 * time.Millisecond

	ctx := t.Context()

	done := make(chan error, 1)
	go func() { done <- rc.run(ctx) }()

	// Both directions blocked; watchdog should reclaim after ~100ms.
	select {
	case <-done:
		// Reclaimed promptly; the surfaced error (closed conn) is expected.
	case <-time.After(3 * time.Second):
		t.Fatal("relay not reclaimed")
	}
}

// delayedReleaseMockConn simulates a QUIC stream Read that does not unblock
// immediately on Close/SetReadDeadline, but eventually returns after a delay.
// This mirrors the real-world quic-go behavior where CancelRead may take a
// tick or two to propagate to the blocked goroutine.
type delayedReleaseMockConn struct {
	closed       atomic.Bool
	closeCh      chan struct{}
	releaseDelay time.Duration
}

func newDelayedReleaseMockConn(delay time.Duration) *delayedReleaseMockConn {
	return &delayedReleaseMockConn{closeCh: make(chan struct{}), releaseDelay: delay}
}

func (m *delayedReleaseMockConn) Read(b []byte) (int, error) {
	<-m.closeCh
	time.Sleep(m.releaseDelay)
	return 0, net.ErrClosed
}
func (m *delayedReleaseMockConn) Write(b []byte) (int, error) { return len(b), nil }
func (m *delayedReleaseMockConn) ReadFrom(p []byte) (int, netip.AddrPort, error) {
	return 0, netip.AddrPort{}, io.EOF
}
func (m *delayedReleaseMockConn) WriteTo(p []byte, addr string) (int, error) { return len(p), nil }
func (m *delayedReleaseMockConn) Close() error {
	if m.closed.CompareAndSwap(false, true) {
		close(m.closeCh)
	}
	return nil
}
func (m *delayedReleaseMockConn) SetDeadline(t time.Time) error      { return nil }
func (m *delayedReleaseMockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *delayedReleaseMockConn) SetWriteDeadline(t time.Time) error { return nil }

type repeatedNudgeMockConn struct {
	closed   atomic.Bool
	released atomic.Bool
	nudges   atomic.Int32
	release  chan struct{}
}

func newRepeatedNudgeMockConn() *repeatedNudgeMockConn {
	return &repeatedNudgeMockConn{release: make(chan struct{})}
}

func (m *repeatedNudgeMockConn) Read([]byte) (int, error) {
	<-m.release
	return 0, net.ErrClosed
}
func (m *repeatedNudgeMockConn) Write(b []byte) (int, error) { return len(b), nil }
func (m *repeatedNudgeMockConn) ReadFrom([]byte) (int, netip.AddrPort, error) {
	return 0, netip.AddrPort{}, io.EOF
}
func (m *repeatedNudgeMockConn) WriteTo(p []byte, _ string) (int, error) { return len(p), nil }
func (m *repeatedNudgeMockConn) Close() error {
	m.closed.Store(true)
	return nil
}
func (m *repeatedNudgeMockConn) SetDeadline(time.Time) error { return nil }
func (m *repeatedNudgeMockConn) SetReadDeadline(time.Time) error {
	if m.nudges.Add(1) >= 3 && m.closed.Load() {
		m.releaseRead()
	}
	return nil
}
func (m *repeatedNudgeMockConn) SetWriteDeadline(time.Time) error { return nil }
func (m *repeatedNudgeMockConn) releaseRead() {
	if m.released.CompareAndSwap(false, true) {
		close(m.release)
	}
}

func TestRelayIdleWatchdogKeepsNudgingUntilReadsReturn(t *testing.T) {
	l := newRepeatedNudgeMockConn()
	r := newRepeatedNudgeMockConn()
	defer l.releaseRead()
	defer r.releaseRead()
	rc := newRelayCore(l, r, nil, nil)
	rc.idleTimeout = 40 * time.Millisecond
	rc.idleCheckPeriod = 20 * time.Millisecond

	done := make(chan error, 1)
	go func() { done <- rc.run(context.Background()) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("idle cancellation stopped nudging before reads returned")
	}
	if l.nudges.Load() < 3 || r.nudges.Load() < 3 {
		t.Fatalf("insufficient read nudges: left=%d right=%d", l.nudges.Load(), r.nudges.Load())
	}
}

// TestRelayWatchdogSurvivesCtxCancel verifies that the watchdog keeps the
// relay alive after ctx cancellation (e.g. reload) and eventually reclaims
// it when the QUIC-like delayed Read finally returns.
func TestRelayCancelNudgesFasterThanIdleCadence(t *testing.T) {
	l := newRepeatedNudgeMockConn()
	r := newRepeatedNudgeMockConn()
	defer l.releaseRead()
	defer r.releaseRead()
	rc := newRelayCore(l, r, nil, nil)
	rc.idleTimeout = time.Hour
	rc.idleCheckPeriod = time.Hour

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- rc.run(ctx) }()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("canceled relay kept the idle watchdog cadence")
	}
	if l.nudges.Load() < 3 || r.nudges.Load() < 3 {
		t.Fatalf("insufficient cancel nudges: left=%d right=%d", l.nudges.Load(), r.nudges.Load())
	}
}

func TestRelayWatchdogSurvivesCtxCancel(t *testing.T) {
	// Conn whose Read releases 200ms after Close (simulating quic-go delay).
	l := newDelayedReleaseMockConn(200 * time.Millisecond)
	r := newDelayedReleaseMockConn(200 * time.Millisecond)
	rc := newRelayCore(l, r, nil, nil)
	rc.idleTimeout = 5 * time.Second // long idle; we test ctx-cancel, not idle
	rc.idleCheckPeriod = 50 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- rc.run(ctx) }()

	// Cancel ctx (simulating reload) after a brief warm-up.
	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case <-done:
		// Success: the watchdog forceClosed, the delayed Reads eventually
		// returned, and run() finished cleanly.
	case <-time.After(5 * time.Second):
		t.Fatal("relay leaked: run() did not return after ctx cancel + delayed Read release")
	}
}

// eofMockConn returns EOF immediately so both copy directions finish without
// forceClose. It verifies normal exit stops the watcher before canceling ctx.
type eofMockConn struct {
	closed atomic.Bool
}

func (m *eofMockConn) Read([]byte) (int, error)    { return 0, io.EOF }
func (m *eofMockConn) Write(b []byte) (int, error) { return len(b), nil }
func (m *eofMockConn) ReadFrom([]byte) (int, netip.AddrPort, error) {
	return 0, netip.AddrPort{}, io.EOF
}
func (m *eofMockConn) WriteTo(p []byte, _ string) (int, error) { return len(p), nil }
func (m *eofMockConn) Close() error {
	m.closed.Store(true)
	return nil
}
func (m *eofMockConn) SetDeadline(time.Time) error      { return nil }
func (m *eofMockConn) SetReadDeadline(time.Time) error  { return nil }
func (m *eofMockConn) SetWriteDeadline(time.Time) error { return nil }

// delayedEOFConn EOFs the first Read after delay, then blocks until closed.
type delayedEOFConn struct {
	delay  time.Duration
	closed atomic.Bool
	once   atomic.Bool
}

func (m *delayedEOFConn) Read([]byte) (int, error) {
	if m.once.CompareAndSwap(false, true) {
		timer := time.NewTimer(m.delay)
		defer timer.Stop()
		for {
			if m.closed.Load() {
				return 0, net.ErrClosed
			}
			select {
			case <-timer.C:
				if m.closed.Load() {
					return 0, net.ErrClosed
				}
				return 0, io.EOF
			case <-time.After(5 * time.Millisecond):
			}
		}
	}
	for !m.closed.Load() {
		time.Sleep(5 * time.Millisecond)
	}
	return 0, net.ErrClosed
}
func (m *delayedEOFConn) Write(b []byte) (int, error) { return len(b), nil }
func (m *delayedEOFConn) ReadFrom([]byte) (int, netip.AddrPort, error) {
	return 0, netip.AddrPort{}, io.EOF
}
func (m *delayedEOFConn) WriteTo(p []byte, _ string) (int, error) { return len(p), nil }
func (m *delayedEOFConn) Close() error {
	m.closed.Store(true)
	return nil
}
func (m *delayedEOFConn) SetDeadline(time.Time) error      { return nil }
func (m *delayedEOFConn) SetReadDeadline(time.Time) error  { return nil }
func (m *delayedEOFConn) SetWriteDeadline(time.Time) error { return nil }

// deadlineBlockConn blocks on Read until closed or the read deadline fires.
type deadlineBlockConn struct {
	closed atomic.Bool
	dlNano atomic.Int64
}

func (m *deadlineBlockConn) Read([]byte) (int, error) {
	for {
		if m.closed.Load() {
			return 0, net.ErrClosed
		}
		if dl := m.dlNano.Load(); dl != 0 && time.Now().UnixNano() >= dl {
			return 0, io.EOF
		}
		time.Sleep(5 * time.Millisecond)
	}
}
func (m *deadlineBlockConn) Write(b []byte) (int, error) { return len(b), nil }
func (m *deadlineBlockConn) ReadFrom([]byte) (int, netip.AddrPort, error) {
	return 0, netip.AddrPort{}, io.EOF
}
func (m *deadlineBlockConn) WriteTo(p []byte, _ string) (int, error) { return len(p), nil }
func (m *deadlineBlockConn) Close() error {
	m.closed.Store(true)
	return nil
}
func (m *deadlineBlockConn) SetDeadline(deadline time.Time) error {
	return m.SetReadDeadline(deadline)
}
func (m *deadlineBlockConn) SetReadDeadline(t time.Time) error {
	if t.IsZero() {
		m.dlNano.Store(0)
		return nil
	}
	m.dlNano.Store(t.UnixNano())
	return nil
}
func (m *deadlineBlockConn) SetWriteDeadline(time.Time) error { return nil }

func TestRelayHalfCloseRefreshOutlivesPriorIdle(t *testing.T) {
	// Mirrors production ratios: idleTimeout (5m) > halfCloseTimeout (10s).
	// EOF arrives late in the idle window; without refreshing lastActive the
	// watchdog would reclaim before the half-close drain finishes.
	const (
		idleTimeout      = 150 * time.Millisecond
		idleCheckPeriod  = 15 * time.Millisecond
		halfCloseTimeout = 80 * time.Millisecond
		eofDelay         = 110 * time.Millisecond
	)
	src := &delayedEOFConn{delay: eofDelay}
	dst := &deadlineBlockConn{}
	rc := newRelayCore(src, dst, nil, nil)
	rc.idleTimeout = idleTimeout
	rc.idleCheckPeriod = idleCheckPeriod
	rc.halfCloseTimeout = halfCloseTimeout

	done := make(chan error, 1)
	go func() { done <- rc.run(context.Background()) }()

	// Past the original idle bound (150ms) but before half-close (110+80=190ms).
	select {
	case <-done:
		t.Fatal("idle watchdog forceClosed during half-close drain")
	case <-time.After(170 * time.Millisecond):
	}

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("half-close drain did not finish")
	}
}

func TestRelayWatcherStopsOnNormalCompletion(t *testing.T) {
	l := &eofMockConn{}
	r := &eofMockConn{}
	rc := newRelayCore(l, r, nil, nil)
	rc.idleTimeout = time.Hour
	rc.idleCheckPeriod = time.Hour

	done := make(chan error, 1)
	go func() { done <- rc.run(context.Background()) }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("normal relay returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("normal relay did not return")
	}

	// Give the watcher a scheduling turn after run's deferred cancel.
	time.Sleep(10 * time.Millisecond)
	if l.closed.Load() || r.closed.Load() {
		t.Fatal("watcher forceClosed sockets after a normally completed relay")
	}
}

func TestRelayWatcherForceClosesOnParentCancel(t *testing.T) {
	l := &blockingMockConn{}
	r := &blockingMockConn{}
	rc := newRelayCore(l, r, nil, nil)
	rc.idleTimeout = time.Hour
	rc.idleCheckPeriod = time.Hour

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- rc.run(ctx) }()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("relay did not return after parent ctx cancel")
	}
	if !l.closed.Load() || !r.closed.Load() {
		t.Fatal("parent cancel did not forceClose both sockets")
	}
}
