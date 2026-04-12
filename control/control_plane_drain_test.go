/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"io"
	"testing"

	"github.com/sirupsen/logrus"
)

func TestControlPlaneDrainTrackerAcquireRelease(t *testing.T) {
	tracker := newControlPlaneDrainTracker()
	if tracker.Count() != 0 {
		t.Fatalf("initial Count() = %d, want 0", tracker.Count())
	}

	releaseA := tracker.Acquire()
	releaseB := tracker.Acquire()
	if tracker.Count() != 2 {
		t.Fatalf("Count() after acquire = %d, want 2", tracker.Count())
	}

	releaseA()
	if tracker.Count() != 1 {
		t.Fatalf("Count() after first release = %d, want 1", tracker.Count())
	}

	select {
	case <-tracker.IdleCh():
		t.Fatal("idle channel closed while tracker still has active sessions")
	default:
	}

	releaseB()
	if tracker.Count() != 0 {
		t.Fatalf("Count() after second release = %d, want 0", tracker.Count())
	}

	select {
	case <-tracker.IdleCh():
	default:
		t.Fatal("idle channel should be closed after all sessions release")
	}
}

func TestUdpEndpointAdoptGenerationTransfersDrainOwnership(t *testing.T) {
	oldTracker := newControlPlaneDrainTracker()
	newTracker := newControlPlaneDrainTracker()
	ue := &UdpEndpoint{
		drainTracker: oldTracker,
		drainRelease: oldTracker.Acquire(),
	}

	if oldTracker.Count() != 1 {
		t.Fatalf("oldTracker Count() = %d, want 1", oldTracker.Count())
	}

	ue.adoptGeneration(nil, newTracker)

	if oldTracker.Count() != 0 {
		t.Fatalf("oldTracker Count() after adoption = %d, want 0", oldTracker.Count())
	}
	if newTracker.Count() != 1 {
		t.Fatalf("newTracker Count() after adoption = %d, want 1", newTracker.Count())
	}

	if err := ue.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if newTracker.Count() != 0 {
		t.Fatalf("newTracker Count() after close = %d, want 0", newTracker.Count())
	}
}

func TestCommitPreparedDatapathStartsConnStateJanitor(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cp := &ControlPlane{
		log:                    logger,
		ctx:                    ctx,
		preparedDatapathCommit: true,
		connStateJanitorStop:   make(chan struct{}),
		connStateJanitorDone:   make(chan struct{}),
	}

	if cp.connStateJanitorStarted.Load() {
		t.Fatal("expected conn-state janitor to start disabled")
	}

	if err := cp.CommitPreparedDatapath(); err != nil {
		t.Fatalf("CommitPreparedDatapath() error = %v", err)
	}
	if !cp.connStateJanitorStarted.Load() {
		t.Fatal("expected CommitPreparedDatapath to start conn-state janitor")
	}
	if cp.preparedDatapathCommit {
		t.Fatal("expected preparedDatapathCommit to be cleared after commit")
	}

	cp.stopConnStateJanitor()
}

func TestStartPreparedDNSListenerOnlyRunsWhenDeferred(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	cp := &ControlPlane{
		log: logger,
		dnsListener: &DNSListener{
			log: logger,
		},
	}

	if err := cp.StartPreparedDNSListener(); err != nil {
		t.Fatalf("StartPreparedDNSListener() without deferred flag error = %v", err)
	}
	if cp.dnsListenerStopRegistered {
		t.Fatal("expected StartPreparedDNSListener to no-op when deferred flag is false")
	}

	cp.delayDNSListenerStart = true
	if err := cp.StartPreparedDNSListener(); err != nil {
		t.Fatalf("StartPreparedDNSListener() with deferred flag error = %v", err)
	}
	if cp.delayDNSListenerStart {
		t.Fatal("expected deferred DNS listener flag to be cleared")
	}
	if !cp.dnsListenerStopRegistered {
		t.Fatal("expected DNS listener stop hook to be registered after deferred start")
	}
}
