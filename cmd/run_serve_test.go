/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

// mockRetirementPlane records retirement calls for reload drain tests.
type mockRetirementPlane struct {
	activeSessions        int
	idleCh                chan struct{}
	abortConnectionsCalls int
	abortPendingCalls     int
	stopRoutingCalls      int
}

func (m *mockRetirementPlane) ActiveSessionCount() int { return m.activeSessions }

func (m *mockRetirementPlane) DrainIdleCh() <-chan struct{} { return m.idleCh }

func (m *mockRetirementPlane) AbortConnections() error {
	m.abortConnectionsCalls++
	return nil
}

func (m *mockRetirementPlane) AbortPendingConnections() error {
	m.abortPendingCalls++
	return nil
}

func (m *mockRetirementPlane) StopRoutingEpochExecution() { m.stopRoutingCalls++ }

func (m *mockRetirementPlane) StopRoutingEpochExecutionWithTimeout(time.Duration) {
	m.stopRoutingCalls++
}

// TestRetireDrainIdlePreservesConnections guards the zero-downtime reload
// guarantee: when the old control plane drains its routing-epoch leases
// normally (idle path), retirement must NOT call AbortConnections — that
// would kill active relay flows and break hot-reload connectivity.
func TestRetireDrainIdlePreservesConnections(t *testing.T) {
	plane := &mockRetirementPlane{activeSessions: 0, idleCh: make(chan struct{})}
	retireControlPlaneConnections(logrus.New(), context.Background(), plane, false, time.Second)
	if plane.abortConnectionsCalls != 0 {
		t.Fatalf("drain-idle retirement must NOT call AbortConnections (would kill active flows), got %d calls", plane.abortConnectionsCalls)
	}
	if plane.abortPendingCalls != 0 {
		t.Fatalf("drain-idle retirement must NOT call AbortPendingConnections, got %d calls", plane.abortPendingCalls)
	}
	if plane.stopRoutingCalls != 1 {
		t.Fatalf("expected StopRoutingEpochExecution, got %d", plane.stopRoutingCalls)
	}
}

// TestRetireDrainCanceledAbortsPending covers the retirement-canceled path:
// only pending work is aborted; active connections are preserved.
func TestRetireDrainCanceledAbortsPending(t *testing.T) {
	plane := &mockRetirementPlane{activeSessions: 1, idleCh: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	retireControlPlaneConnections(logrus.New(), ctx, plane, false, time.Second)
	if plane.abortPendingCalls != 1 {
		t.Fatalf("canceled retirement must abort pending connections, got %d", plane.abortPendingCalls)
	}
	if plane.abortConnectionsCalls != 0 {
		t.Fatalf("canceled retirement must NOT call AbortConnections (would kill active flows), got %d", plane.abortConnectionsCalls)
	}
}

// TestRetireDrainTimeoutAbortsPending covers the drain-timeout path:
// only pending work is aborted; active connections are preserved.
func TestRetireDrainTimeoutAbortsPending(t *testing.T) {
	plane := &mockRetirementPlane{activeSessions: 1, idleCh: make(chan struct{})}
	retireControlPlaneConnections(logrus.New(), context.Background(), plane, false, 50*time.Millisecond)
	if plane.abortPendingCalls != 1 {
		t.Fatalf("timeout retirement must abort pending connections, got %d", plane.abortPendingCalls)
	}
	if plane.abortConnectionsCalls != 0 {
		t.Fatalf("timeout retirement must NOT call AbortConnections (would kill active flows), got %d", plane.abortConnectionsCalls)
	}
}

// TestRetireAbortPathKeepsBehavior guards the immediate-abort path (used
// during full shutdown, not reload): AbortConnections is expected here.
func TestRetireAbortPathKeepsBehavior(t *testing.T) {
	plane := &mockRetirementPlane{activeSessions: 1, idleCh: make(chan struct{})}
	retireControlPlaneConnections(logrus.New(), context.Background(), plane, true, time.Second)
	if plane.abortConnectionsCalls != 1 {
		t.Fatalf("abort retirement must call AbortConnections, got %d", plane.abortConnectionsCalls)
	}
	if plane.abortPendingCalls != 0 {
		t.Fatalf("abort retirement must not call AbortPendingConnections, got %d", plane.abortPendingCalls)
	}
}

type mockShutdownListener struct {
	closeCalls int
}

func (m *mockShutdownListener) Close() error {
	m.closeCalls++
	return nil
}

type mockShutdownPlane struct {
	detachCalls int
	abortCalls  int
	closeCalls  int
}

func (m *mockShutdownPlane) DetachBpfHooks() error {
	m.detachCalls++
	return nil
}

func (m *mockShutdownPlane) AbortConnections() error {
	m.abortCalls++
	return nil
}

func (m *mockShutdownPlane) Close() error {
	m.closeCalls++
	return nil
}

type mockShutdownNetns struct {
	closeCalls int
}

func (m *mockShutdownNetns) Close() error {
	m.closeCalls++
	return nil
}

func TestShutdownFastExitStillTearsDownNetns(t *testing.T) {
	listener := &mockShutdownListener{}
	plane := &mockShutdownPlane{}
	netns := &mockShutdownNetns{}

	if err := shutdownAfterSignalWithHandoff(logrus.New(), listener, plane, netns, true, nil); err != nil {
		t.Fatalf("fast-exit shutdown returned error: %v", err)
	}
	if listener.closeCalls != 1 {
		t.Fatalf("fast exit must still close the listener, got %d", listener.closeCalls)
	}
	if plane.detachCalls != 1 {
		t.Fatalf("fast exit must still detach BPF hooks, got %d", plane.detachCalls)
	}
	if netns.closeCalls != 1 {
		t.Fatalf("fast exit must tear down dae netns, got %d", netns.closeCalls)
	}
	if plane.abortCalls != 0 || plane.closeCalls != 0 {
		t.Fatalf("fast exit must skip control-plane abort/close, abort=%d close=%d", plane.abortCalls, plane.closeCalls)
	}
}

func TestShutdownGracefulTearsDownNetnsAndControlPlane(t *testing.T) {
	listener := &mockShutdownListener{}
	plane := &mockShutdownPlane{}
	netns := &mockShutdownNetns{}

	if err := shutdownAfterSignalWithHandoff(logrus.New(), listener, plane, netns, false, nil); err != nil {
		t.Fatalf("graceful shutdown returned error: %v", err)
	}
	if netns.closeCalls != 1 {
		t.Fatalf("graceful shutdown must tear down dae netns, got %d", netns.closeCalls)
	}
	if plane.abortCalls != 1 || plane.closeCalls != 1 {
		t.Fatalf("graceful shutdown must abort and close the control plane, abort=%d close=%d", plane.abortCalls, plane.closeCalls)
	}
}
