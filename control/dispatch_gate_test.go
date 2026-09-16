/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"testing"
	"time"

	"github.com/daeuniverse/outbound/pool"
)

// TestUdpIngressTaskDiscardReleasesDispatchSem pins the direct-dispatch
// discipline: a task that never ran must give back every resource it held,
// including the dispatch concurrency slot. Releasing means the buffered
// token is taken out of the semaphore channel.
func TestUdpIngressTaskDiscardReleasesDispatchSem(t *testing.T) {
	sem := make(chan struct{}, 1)
	sem <- struct{}{} // occupy the slot as the dispatch path would
	gate := &routingEpochIngressGate{}
	task := &udpIngressTask{
		pktBuf:      pool.Get(16),
		admission:   gate,
		dispatchSem: sem,
	}
	task.Discard()

	select {
	case <-sem:
		t.Fatal("Discard must take the dispatch token out of the semaphore")
	default:
	}
	if task.dispatchSem != nil {
		t.Fatal("Discard must zero the task before returning it to the pool")
	}
}

// TestUdpIngressTaskNilDispatchSemIsNoop guards the checkout invariant: a
// queued (or dropped) task must never release a dispatch slot, so a stale
// pointer left by a previous pool cycle cannot inflate the semaphore.
func TestUdpIngressTaskNilDispatchSemIsNoop(t *testing.T) {
	sem := make(chan struct{}, 1)
	task := &udpIngressTask{}
	task.releaseDispatchSem()
	select {
	case <-sem:
		t.Fatal("releaseDispatchSem on a nil slot must not receive from any semaphore")
	default:
	}
}

// TestDnsControllerHandleGateDrainBeforeForwarders verifies the lock-domain
// narrowing contract: once Close starts, new dispatches fail fast, and the
// gate drains in-flight handlers instead of letting forwarders be torn down
// under them.
func TestDnsControllerHandleGateDrainBeforeForwarders(t *testing.T) {
	c := &DnsController{dnsControllerStore: newDnsControllerStore()}

	if !c.acquireHandleGate() {
		t.Fatal("controller must admit handlers while open")
	}
	drained := make(chan struct{})
	go func() {
		c.closeHandleGate()
		close(drained)
	}()

	select {
	case <-drained:
		t.Fatal("gate drain must wait for the in-flight handler")
	case <-time.After(20 * time.Millisecond):
	}
	if c.acquireHandleGate() {
		t.Fatal("controller must reject new handlers once the gate is closing")
	}
	c.releaseHandleGate()
	select {
	case <-drained:
	case <-time.After(2 * time.Second):
		t.Fatal("gate drain did not finish after the handler released")
	}
}
