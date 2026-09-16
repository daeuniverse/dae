/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// TestJanitorLockScopeContract is the source contract: the janitor must
// scope each key class to the lock that protects it (UDP -> udpStateMu, TCP ->
// generationsMu) instead of taking both, and it must not park the critical
// section on a deferred unlock that drags the trailing stats/logging inside it.
func TestJanitorLockScopeContract(t *testing.T) {
	src, err := os.ReadFile("conn_state_janitor.go")
	if err != nil {
		t.Fatalf("read conn_state_janitor.go: %v", err)
	}
	text := string(src)

	if strings.Contains(text, "defer manager.generationsMu.Unlock()") ||
		strings.Contains(text, "defer manager.udpStateMu.RUnlock()") {
		t.Fatal("the janitor still parks its critical section on a deferred unlock")
	}

	udpIdx := strings.Index(text, "manager.udpStateMu.RLock()")
	tcpIdx := strings.Index(text, "manager.generationsMu.Lock()")
	if udpIdx < 0 || tcpIdx < 0 {
		t.Fatal("janitor pin recheck sections are missing")
	}
	if tcpIdx < udpIdx {
		t.Fatal("expected the UDP class to be rechecked first, in its own critical section")
	}
	udpBlock := text[udpIdx:tcpIdx]
	if strings.Contains(udpBlock, "generationsMu") {
		t.Fatalf("UDP delete section takes generationsMu; a UDP-only cycle must not queue behind TCP flow registration:\n%s", udpBlock)
	}
	if !strings.Contains(udpBlock, "deleteKeys(udpKeysToDelete") {
		t.Fatalf("UDP delete must run inside the udpStateMu critical section:\n%s", udpBlock)
	}
	tcpBlock := text[tcpIdx:]
	if end := strings.Index(tcpBlock, "return udpStats, tcpStats"); end > 0 {
		tcpBlock = tcpBlock[:end]
	}
	if strings.Contains(tcpBlock, "udpStateMu") {
		t.Fatalf("TCP delete section takes udpStateMu; the two classes must stay disjoint:\n%s", tcpBlock)
	}
	if !strings.Contains(tcpBlock, "deleteKeys(tcpKeysToDelete") {
		t.Fatalf("TCP delete must run inside the generationsMu critical section:\n%s", tcpBlock)
	}
	if !strings.Contains(text, "countConnStateJanitorDeleteError(") {
		t.Fatal("janitor delete failures must be counted, not silently dropped")
	}
}

// TestJanitorUdpDeleteDoesNotTakeGenerationsMu is the behavioral half of:
// with generationsMu held by another goroutine (a TCP flow registration), a
// UDP-only cleanup cycle must still complete and delete its entries. Before the
// split the janitor took generationsMu for every cycle, so this would block.
// It needs a kernel conn_state map and therefore skips in the dae_stub_ebpf
// build.
func TestJanitorUdpDeleteDoesNotTakeGenerationsMu(t *testing.T) {
	f := newReloadRetirementCleanupFixture(t)

	udpKey := bpfTuplesKeyFromAddrPorts(
		netip.MustParseAddrPort("192.0.2.61:41001"),
		netip.MustParseAddrPort("198.51.100.61:4000"), unix.IPPROTO_UDP)
	udpValue := bpfConnState{LastSeenNs: 1}
	udpValue.Meta.Data.HasRouting = 1
	if err := f.connState.Update(&udpKey, &udpValue, ebpf.UpdateAny); err != nil {
		t.Fatalf("seed UDP conn_state: %v", err)
	}

	// Simulate a long TCP flow registration holding the generation lock.
	f.manager.generationsMu.Lock()

	done := make(chan struct{})
	go func() {
		defer close(done)
		f.plane.cleanupConnStateMapBeforeLocked(true, 0)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		f.manager.generationsMu.Unlock()
		t.Fatal("UDP-only cleanup blocked on generationsMu; the per-key-class lock split is gone")
	}
	f.manager.generationsMu.Unlock()

	if connStateExists(f.connState, udpKey) {
		t.Fatal("expired UDP entry was not deleted by the cleanup cycle")
	}
	// The critical sections must be closed by the time the cycle returns: the
	// trailing stats and logging must not run under either manager lock.
	if !f.manager.generationsMu.TryLock() {
		t.Fatal("generationsMu still held after cleanup returned")
	}
	f.manager.generationsMu.Unlock()
	if !f.manager.udpStateMu.TryLock() {
		t.Fatal("udpStateMu still held after cleanup returned")
	}
	f.manager.udpStateMu.Unlock()
}
