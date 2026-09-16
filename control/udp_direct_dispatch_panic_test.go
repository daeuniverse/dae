/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/pool"
)

// newPanickingDirectDispatchTask builds a direct-dispatch task whose Run
// panics deterministically (a ControlPlane without a core and without a
// logger dereferences the nil logger on the routing-result fallback path)
// while holding every resource the direct path holds: an admission ticket, a
// dispatch semaphore slot, a pooled packet buffer, and the pooled task.
//
// It mirrors the real checkout: the caller takes the token, assigns
// dispatchSem, and hands the task to the spawn site.
func newPanickingDirectDispatchTask(t *testing.T, gate *routingEpochIngressGate, sem chan struct{}, buf pool.PB) *udpIngressTask {
	t.Helper()
	if !gate.tryAcquire() {
		t.Fatal("admission gate must admit the packet")
	}
	select {
	case sem <- struct{}{}:
	default:
		t.Fatal("dispatch semaphore slot must be free")
	}
	task := udpIngressTaskPool.Get().(*udpIngressTask)
	task.c = &ControlPlane{}
	task.pktBuf = buf
	task.admission = gate
	task.realDst = netip.MustParseAddrPort("198.51.100.9:443")
	task.convergeSrc = netip.MustParseAddrPort("192.0.2.9:40009")
	task.dispatchSem = sem
	return task
}

// assertIngressTaskZeroed checks the pool-return invariant: the task's defers
// zero every field before Put so no stale pointer leaks into the next
// checkout (udpIngressTask is not comparable because pktBuf is a slice).
func assertIngressTaskZeroed(t *testing.T, task *udpIngressTask) {
	t.Helper()
	if task.c != nil || task.lConn != nil || task.pktBuf != nil || task.admission != nil ||
		task.dispatchSem != nil || task.realDst.IsValid() || task.convergeSrc.IsValid() {
		t.Fatalf("task not zeroed before returning to the pool: %+v", *task)
	}
}

// TestDirectDispatchTaskPanicIsolation is a regression guard: a panic in one
// directly dispatched packet must not escape its goroutine, and it must be
// counted through the production reporter.
func TestDirectDispatchTaskPanicIsolation(t *testing.T) {
	gate := &routingEpochIngressGate{}
	sem := make(chan struct{}, 1)
	task := newPanickingDirectDispatchTask(t, gate, sem, pool.Get(2048))

	var counter atomic.Uint64
	func() {
		defer func() {
			if escaped := recover(); escaped != nil {
				t.Fatalf("direct-dispatch panic escaped its isolation wrapper: %v", escaped)
			}
		}()
		runDirectDispatchTask(task, &counter)
	}()

	if got := counter.Load(); got != 1 {
		t.Fatalf("direct-dispatch panic counter = %d, want 1", got)
	}
	assertIngressTaskZeroed(t, task)
}

// TestDirectDispatchTaskPanicReleasesResourcesExactlyOnce locks the "recover
// must not release anything" second half: Run's own defers already returned
// the dispatch slot, the admission ticket, the packet buffer, and the pooled
// task during the unwind, so the recovery handler must add no release of its
// own.
func TestDirectDispatchTaskPanicReleasesResourcesExactlyOnce(t *testing.T) {
	gate := &routingEpochIngressGate{}
	sem := make(chan struct{}, 1)
	// A buffer from a high size class: the assertion below drains several
	// buffers of the same class, so contamination from other tests' smaller
	// buckets cannot produce a false pass or fail.
	const bufSize = 1 << 15
	buf := pool.Get(bufSize)
	// Preload the same size class so the post-panic drain finds the released
	// buffer even if another test left unrelated entries in the bucket.
	filler := pool.Get(bufSize)
	filler.Put()

	task := newPanickingDirectDispatchTask(t, gate, sem, buf)

	var counter atomic.Uint64
	done := make(chan struct{})
	go func() {
		defer close(done)
		runDirectDispatchTask(task, &counter)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("runDirectDispatchTask did not return: a resource was released twice (double release blocks on the semaphore or the gate)")
	}

	if got := counter.Load(); got != 1 {
		t.Fatalf("direct-dispatch panic counter = %d, want 1", got)
	}
	// Admission ticket: exactly one release. A second release underflows the
	// counter to ^uint64(0) instead of 0.
	if got := gate.state.Load(); got != 0 {
		t.Fatalf("admission gate state = %d, want 0 (exactly one release)", got)
	}
	// Dispatch slot: exactly one receive. The semaphore is empty afterwards.
	if got := len(sem); got != 0 {
		t.Fatalf("dispatch semaphore holds %d tokens after the panic, want 0", got)
	}
	// Task object: zeroed and returned to the pool.
	assertIngressTaskZeroed(t, task)
	// Packet buffer: the pooled array may come back out of its size class. A
	// double Put would let the same backing array be handed out twice
	// (pool.Put buckets by cap and is not idempotent), which is the aliasing
	// bug the recovery must avoid. A zero count is not a failure by itself:
	// sync.Pool may drop entries at any GC, so this only fails on the aliasing
	// it is looking for. The deterministic guards for "exactly one release" are
	// the gate counter, the semaphore, and the wrapper's source contract.
	found := 0
	for range 64 {
		got := pool.Get(bufSize)
		if cap(got) != 0 && cap(buf) != 0 && &got[0] == &buf[0] {
			found++
		}
	}
	if found > 1 {
		t.Fatalf("released packet buffer observed %d times in its size class: the recovery released it more than once", found)
	}
	if found == 0 {
		t.Log("packet buffer entry was no longer pooled (GC dropped it); the deterministic release guards above still hold")
	}
}

// TestDirectDispatchSpawnSitePanicIsolation is the source contract for:
// both goroutine spawn sites on the UDP ingress path (the direct-dispatch task
// and the ingress read loop) must run under a recover, and the recovery must
// not re-release the resources Run's defers already released.
func TestDirectDispatchSpawnSitePanicIsolation(t *testing.T) {
	src, err := os.ReadFile("control_plane.go")
	if err != nil {
		t.Fatalf("read control_plane.go: %v", err)
	}
	text := string(src)

	spawn := "go runDirectDispatchTask(task, &c.udpDirectDispatchPanicCount)"
	if !strings.Contains(text, spawn) {
		t.Fatalf("direct-dispatch spawn site is not panic-isolated: %q missing", spawn)
	}
	if strings.Contains(text, "go task.Run()") {
		t.Fatal("bare `go task.Run()` spawn site must not come back")
	}

	before, _, ok := strings.Cut(text, "processPacket := func(pktBuf pool.PB")
	if !ok {
		t.Fatal("ingress read loop body not found in control_plane.go")
	}
	// The read-loop handler is the goroutine body directly preceding
	// processPacket's definition.
	handler := before
	handler = handler[strings.LastIndex(handler, "go func() {"):]
	if !strings.Contains(handler, "recover()") {
		t.Fatal("ingress read loop has no panic isolation")
	}
	if !strings.Contains(handler, "fatalIngressLoopError(") {
		t.Fatal("ingress read loop panic recovery must end the loop loudly (fatalIngressLoopError)")
	}
	if !strings.Contains(handler, "reportPacketPathPanic(\"udp_ingress\"") {
		t.Fatal("ingress read loop panic must be counted through reportPacketPathPanic")
	}
	if strings.Contains(handler, ".Discard()") || strings.Contains(handler, ".Put()") {
		t.Fatal("read-loop recovery must not release resources a second time")
	}

	wrapperSrc, err := os.ReadFile("udp_task_pool.go")
	if err != nil {
		t.Fatalf("read udp_task_pool.go: %v", err)
	}
	start := strings.Index(string(wrapperSrc), "func runDirectDispatchTask(")
	if start < 0 {
		t.Fatal("runDirectDispatchTask is missing from udp_task_pool.go")
	}
	body := string(wrapperSrc)[start:]
	if end := strings.Index(body, "\n}\n"); end > 0 {
		body = body[:end]
	}
	for _, forbidden := range []string{"Discard()", ".Put()", "release("} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("runDirectDispatchTask recovery re-releases %q; Run's defers already ran", forbidden)
		}
	}
	if !strings.Contains(body, "reportPacketPathPanic(") {
		t.Fatal("runDirectDispatchTask must report through reportPacketPathPanic")
	}
}
