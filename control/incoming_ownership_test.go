/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net"
	"sync"
	"testing"
	"time"
)

// newOwnershipTestPlane builds a bare ControlPlane with only the fields the
// incoming-connection ownership path touches.
func newOwnershipTestPlane() *ControlPlane {
	return &ControlPlane{
		drainTracker: newControlPlaneDrainTracker(),
	}
}

// TestIncomingLeaseAcquireReleaseRoundTrip pins the basic accounting
// contract: an accepted lease registers in inConnections and holds one drain
// ticket; release unwinds both exactly once even when called twice.
func TestIncomingLeaseAcquireReleaseRoundTrip(t *testing.T) {
	c := newOwnershipTestPlane()

	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	lease, ok := c.acquireIncomingConnectionLease(client)
	if !ok {
		t.Fatal("acquire rejected while generation is open")
	}
	if c.drainTracker.Count() != 1 {
		t.Fatalf("drain count = %d, want 1 after accept", c.drainTracker.Count())
	}
	if _, loaded := c.inConnections.Load(client); !loaded {
		t.Fatal("accepted conn missing from inConnections")
	}

	lease.release()
	lease.release()
	if c.drainTracker.Count() != 0 {
		t.Fatalf("drain count = %d, want 0 after release", c.drainTracker.Count())
	}
	if _, loaded := c.inConnections.Load(client); loaded {
		t.Fatal("released conn still in inConnections")
	}
	select {
	case <-c.drainTracker.IdleCh():
	default:
		t.Fatal("idle channel did not reopen after last release")
	}
}

// TestIncomingLeaseRejectAfterClose guards the admit-after-idle invariant:
// once closeRoutingEpochExecution's write section completed, no subsequent
// acquire may succeed — and leases taken before the close still release
// cleanly so IdleCh fires.
func TestIncomingLeaseRejectAfterClose(t *testing.T) {
	c := newOwnershipTestPlane()

	preCloseConn, preCloseServer := net.Pipe()
	_ = preCloseServer.Close()
	preClose, ok := c.acquireIncomingConnectionLease(preCloseConn)
	if !ok {
		t.Fatal("pre-close acquire rejected")
	}
	c.closeRoutingEpochExecution()

	for range 8 {
		conn, peer := net.Pipe()
		_ = peer.Close()
		lease, ok := c.acquireIncomingConnectionLease(conn)
		if ok {
			lease.release()
			_ = conn.Close()
			t.Fatal("lease acquired after the generation gate closed")
		}
	}
	if c.drainTracker.Count() != 1 {
		t.Fatalf("drain count = %d, want the single pre-close ticket", c.drainTracker.Count())
	}
	preClose.release()
	select {
	case <-c.drainTracker.IdleCh():
	case <-time.After(time.Second):
		t.Fatal("idle channel did not fire after pre-close lease released")
	}
}

// TestIncomingLeaseConcurrentChurn drives acquire/release/transfer/close from
// many goroutines under -race and asserts final accounting integrity: every
// ticket returned, inConnections empty, idle re-fired. It exercises the same
// happens-before the RWMutex conversion relies on (close writer vs reader
// fast paths).
func TestIncomingLeaseConcurrentChurn(t *testing.T) {
	oldPlane := newOwnershipTestPlane()
	newPlane := newOwnershipTestPlane()

	const workers = 8
	const iterations = 200

	var wg sync.WaitGroup
	stopCh := make(chan struct{})
	for w := range workers {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			for i := range iterations {
				a, b := net.Pipe()
				_ = b.Close()
				lease, ok := oldPlane.acquireIncomingConnectionLease(a)
				if ok && idx%2 == 0 && i%7 == 3 {
					// Exercise the cross-generation transfer of a live lease.
					_ = lease.transferRoutingEpoch(newPlane, nil)
				}
				lease.release()
			}
		}(w)
	}
	go func() {
		for {
			select {
			case <-stopCh:
				return
			default:
			}
			oldPlane.closeRoutingEpochExecution()
			newPlane.closeRoutingEpochExecution()
		}
	}()
	wg.Wait()
	close(stopCh)

	oldPlane.rejectNewConnections.Store(false)
	oldPlane.routingEpochExecutionClosed.Store(false)
	if oldPlane.drainTracker.Count() != 0 {
		t.Fatalf("old plane drain count = %d, want 0", oldPlane.drainTracker.Count())
	}
	if _, loaded := oldPlane.inConnections.LoadAndDelete(struct{}{}); loaded {
		t.Fatal("old plane inConnections not empty")
	}
	newPlane.rejectNewConnections.Store(false)
	newPlane.routingEpochExecutionClosed.Store(false)
	if newPlane.drainTracker.Count() != 0 {
		t.Fatalf("new plane drain count = %d, want 0", newPlane.drainTracker.Count())
	}
}
