/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"sync"
	"testing"

	"github.com/daeuniverse/dae/common"
	"golang.org/x/sys/unix"
	"net/netip"
)

// TestSnapshotPinnedUDPEmpty verifies that snapshotPinnedUDP returns an empty
// (non-nil) map when no tuples are pinned, and nil for a nil manager.
func TestSnapshotPinnedUDPEmpty(t *testing.T) {
	// nil manager
	var nilMgr *SessionManager
	if got := nilMgr.snapshotPinnedUDP(); got != nil {
		t.Fatalf("nil manager snapshot = %v, want nil", got)
	}

	// Empty manager
	mgr := NewSessionManager(context.Background())
	defer func() { _ = mgr.Close() }()

	got := mgr.snapshotPinnedUDP()
	if got == nil {
		t.Fatal("expected non-nil empty map")
	}
	if len(got) != 0 {
		t.Fatalf("expected 0 entries, got %d", len(got))
	}
}

// TestSnapshotPinnedTCPEmpty verifies that snapshotPinnedTCP returns an empty
// (non-nil) map when no tuples are pinned, and nil for a nil manager.
func TestSnapshotPinnedTCPEmpty(t *testing.T) {
	var nilMgr *SessionManager
	if got := nilMgr.snapshotPinnedTCP(); got != nil {
		t.Fatalf("nil manager snapshot = %v, want nil", got)
	}

	mgr := NewSessionManager(context.Background())
	defer func() { _ = mgr.Close() }()

	got := mgr.snapshotPinnedTCP()
	if got == nil {
		t.Fatal("expected non-nil empty map")
	}
	if len(got) != 0 {
		t.Fatalf("expected 0 entries, got %d", len(got))
	}
}

// TestSnapshotPinnedUDPReflectsRetained verifies that retained tuples appear
// in the snapshot and are absent after release.
func TestSnapshotPinnedUDPReflectsRetained(t *testing.T) {
	mgr := NewSessionManager(context.Background())
	defer func() { _ = mgr.Close() }()

	src := common.ConvergeAddrPort(netip.MustParseAddrPort("192.0.2.1:1000"))
	dst := common.ConvergeAddrPort(netip.MustParseAddrPort("198.51.100.1:443"))
	key := bpfTuplesKeyFromAddrPorts(src, dst, uint8(unix.IPPROTO_UDP))

	// Before retain: not in snapshot
	snap := mgr.snapshotPinnedUDP()
	if _, found := snap[key]; found {
		t.Fatal("found unpinned key in snapshot")
	}

	// Retain
	mgr.RetainUdpConnStateTuples([]bpfTuplesKey{key})

	// After retain: in snapshot
	snap = mgr.snapshotPinnedUDP()
	if _, found := snap[key]; !found {
		t.Fatal("retained key not found in snapshot")
	}

	// Release (requires BPF map — use nil bpfObjects, ReleaseUdpConnStateTuples
	// only touches the BPF map for batch delete, which is best-effort)
	mgr.udpStateMu.Lock()
	mgr.pinnedUDP[key] = 0
	delete(mgr.pinnedUDP, key)
	mgr.udpStateMu.Unlock()

	snap = mgr.snapshotPinnedUDP()
	if _, found := snap[key]; found {
		t.Fatal("released key still in snapshot")
	}
}

// TestSnapshotPinnedTCPReflectsRetained verifies TCP pin snapshot consistency.
func TestSnapshotPinnedTCPReflectsRetained(t *testing.T) {
	mgr := NewSessionManager(context.Background())
	defer func() { _ = mgr.Close() }()

	src := common.ConvergeAddrPort(netip.MustParseAddrPort("192.0.2.2:2000"))
	dst := common.ConvergeAddrPort(netip.MustParseAddrPort("198.51.100.2:80"))
	key := bpfTuplesKeyFromAddrPorts(src, dst, uint8(unix.IPPROTO_TCP))

	// Directly manipulate the pinned shard (normally done via adoptTCP)
	pinShard := &mgr.pinnedShards[tuplesShardIndex(&key)]
	pinShard.pin(key)

	snap := mgr.snapshotPinnedTCP()
	if _, found := snap[key]; !found {
		t.Fatal("retained TCP key not found in snapshot")
	}

	// Decrement
	pinShard.unpin(key)

	snap = mgr.snapshotPinnedTCP()
	if _, found := snap[key]; found {
		t.Fatal("released TCP key still in snapshot")
	}
}

// TestSnapshotPinnedUDPConcurrentSafe verifies that snapshot reads are safe
// under concurrent writes (retain/release). This is a race detector test —
// run with -race.
func TestSnapshotPinnedUDPConcurrentSafe(t *testing.T) {
	mgr := NewSessionManager(context.Background())
	defer func() { _ = mgr.Close() }()

	baseSrc := netip.MustParseAddrPort("203.0.113.1:0")
	baseDst := netip.MustParseAddrPort("198.51.100.1:443")

	var wg sync.WaitGroup
	const writers = 4
	const readers = 4
	const iterations = 200

	// Writers: retain and release tuples
	for w := range writers {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			for i := range iterations {
				src := common.ConvergeAddrPort(netip.AddrPortFrom(baseSrc.Addr(), uint16(idx*1000+i)))
				key := bpfTuplesKeyFromAddrPorts(src, baseDst, uint8(unix.IPPROTO_UDP))
				mgr.RetainUdpConnStateTuples([]bpfTuplesKey{key})
				// Release without BPF map (direct pin removal)
				mgr.udpStateMu.Lock()
				if mgr.pinnedUDP[key] > 0 {
					mgr.pinnedUDP[key]--
					if mgr.pinnedUDP[key] <= 0 {
						delete(mgr.pinnedUDP, key)
					}
				}
				mgr.udpStateMu.Unlock()
			}
		}(w)
	}

	// Readers: snapshot while writers are mutating
	for range readers {
		wg.Go(func() {
			for range iterations {
				_ = mgr.snapshotPinnedUDP()
				// Should never panic or race
			}
		})
	}

	wg.Wait()
}

// TestSnapshotPinnedTCPConcurrentSafe verifies TCP pin snapshot reads under
// concurrent writes. Run with -race.
func TestSnapshotPinnedTCPConcurrentSafe(t *testing.T) {
	mgr := NewSessionManager(context.Background())
	defer func() { _ = mgr.Close() }()

	baseSrc := netip.MustParseAddrPort("203.0.113.2:0")
	baseDst := netip.MustParseAddrPort("198.51.100.2:80")

	var wg sync.WaitGroup
	const writers = 4
	const readers = 4
	const iterations = 200

	for w := range writers {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			for i := range iterations {
				src := common.ConvergeAddrPort(netip.AddrPortFrom(baseSrc.Addr(), uint16(idx*1000+i)))
				key := bpfTuplesKeyFromAddrPorts(src, baseDst, uint8(unix.IPPROTO_TCP))
				shard := &mgr.pinnedShards[tuplesShardIndex(&key)]
				shard.pin(key)
				shard.unpin(key)
			}
		}(w)
	}

	for range readers {
		wg.Go(func() {
			for range iterations {
				_ = mgr.snapshotPinnedTCP()
			}
		})
	}

	wg.Wait()
}

// TestSnapshotPinnedUDPRefcountMultiple verifies that multiple retains of the
// same key produce a single snapshot entry, and the key disappears only after
// all refs are released.
func TestSnapshotPinnedUDPRefcountMultiple(t *testing.T) {
	mgr := NewSessionManager(context.Background())
	defer func() { _ = mgr.Close() }()

	src := common.ConvergeAddrPort(netip.MustParseAddrPort("192.0.2.10:9999"))
	dst := common.ConvergeAddrPort(netip.MustParseAddrPort("198.51.100.10:53"))
	key := bpfTuplesKeyFromAddrPorts(src, dst, uint8(unix.IPPROTO_UDP))

	// Retain twice
	mgr.RetainUdpConnStateTuples([]bpfTuplesKey{key})
	mgr.RetainUdpConnStateTuples([]bpfTuplesKey{key})

	snap := mgr.snapshotPinnedUDP()
	if _, found := snap[key]; !found {
		t.Fatal("multi-retained key not in snapshot")
	}

	// Release once: should still be pinned
	mgr.udpStateMu.Lock()
	mgr.pinnedUDP[key]--
	mgr.udpStateMu.Unlock()

	snap = mgr.snapshotPinnedUDP()
	if _, found := snap[key]; !found {
		t.Fatal("key disappeared after first release of refcount 2")
	}

	// Release again: should be gone
	mgr.udpStateMu.Lock()
	if mgr.pinnedUDP[key] > 0 {
		mgr.pinnedUDP[key]--
	}
	if mgr.pinnedUDP[key] <= 0 {
		delete(mgr.pinnedUDP, key)
	}
	mgr.udpStateMu.Unlock()

	snap = mgr.snapshotPinnedUDP()
	if _, found := snap[key]; found {
		t.Fatal("key still present after full release")
	}
}
