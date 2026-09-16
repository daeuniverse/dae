/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func pinnedUDPRefs(m *SessionManager, key bpfTuplesKey) int {
	m.udpStateMu.RLock()
	defer m.udpStateMu.RUnlock()
	return m.pinnedUDP[key]
}

// TestTrackUdpConnStateTuplePairMovesPins is a regression guard: the tracker
// used to accumulate one pin per observed tuple pair for the endpoint's whole
// lifetime, so a long-lived endpoint permanently pinned tuples it no longer
// served and the janitor could never retire them. A pair change must release
// the previous pair.
func TestTrackUdpConnStateTuplePairMovesPins(t *testing.T) {
	manager := NewSessionManager(context.Background())
	first := netip.MustParseAddrPort("192.0.2.31:41001")
	second := netip.MustParseAddrPort("198.51.100.31:443")
	third := netip.MustParseAddrPort("192.0.2.32:41002")
	fourth := netip.MustParseAddrPort("198.51.100.32:443")

	oldForward := bpfTuplesKeyFromAddrPorts(first, second, uint8(unix.IPPROTO_UDP))
	oldReverse := bpfTuplesKeyFromAddrPorts(second, first, uint8(unix.IPPROTO_UDP))
	newForward := bpfTuplesKeyFromAddrPorts(third, fourth, uint8(unix.IPPROTO_UDP))
	newReverse := bpfTuplesKeyFromAddrPorts(fourth, third, uint8(unix.IPPROTO_UDP))

	ue := &UdpEndpoint{udpConnStateOwner: manager}
	ue.TrackUdpConnStateTuplePair(first, second)
	for _, key := range []bpfTuplesKey{oldForward, oldReverse} {
		if got := pinnedUDPRefs(manager, key); got != 1 {
			t.Fatalf("pinned refs for %+v after first track = %d, want 1", key, got)
		}
	}

	ue.TrackUdpConnStateTuplePair(third, fourth)
	for _, key := range []bpfTuplesKey{oldForward, oldReverse} {
		if got := pinnedUDPRefs(manager, key); got != 0 {
			t.Fatalf("regression: superseded tuple %+v still pinned (refs=%d)", key, got)
		}
	}
	for _, key := range []bpfTuplesKey{newForward, newReverse} {
		if got := pinnedUDPRefs(manager, key); got != 1 {
			t.Fatalf("pinned refs for new tuple %+v = %d, want 1", key, got)
		}
	}

	// Re-observing the same pair must not re-pin or release anything.
	ue.TrackUdpConnStateTuplePair(third, fourth)
	for _, key := range []bpfTuplesKey{newForward, newReverse} {
		if got := pinnedUDPRefs(manager, key); got != 1 {
			t.Fatalf("repeated track changed refs for %+v to %d, want 1", key, got)
		}
	}

	ue.releaseTrackedUdpConnState()
	for _, key := range []bpfTuplesKey{newForward, newReverse} {
		if got := pinnedUDPRefs(manager, key); got != 0 {
			t.Fatalf("release left %+v pinned (refs=%d)", key, got)
		}
	}
}

// TestTrackUdpConnStateTuplePairKeepsSharedTuple is the "do not over-release"
// second half: when the same tuple is tracked by two endpoints, one
// endpoint's pair change must only drop its own reference. The physical
// conn_state entry survives until the last owner releases it.
func TestTrackUdpConnStateTuplePairKeepsSharedTuple(t *testing.T) {
	manager := NewSessionManager(context.Background())
	sharedSrc := netip.MustParseAddrPort("192.0.2.41:41001")
	sharedDst := netip.MustParseAddrPort("198.51.100.41:443")
	otherSrc := netip.MustParseAddrPort("192.0.2.42:41002")
	otherDst := netip.MustParseAddrPort("198.51.100.42:443")

	sharedForward := bpfTuplesKeyFromAddrPorts(sharedSrc, sharedDst, uint8(unix.IPPROTO_UDP))
	sharedReverse := bpfTuplesKeyFromAddrPorts(sharedDst, sharedSrc, uint8(unix.IPPROTO_UDP))
	otherForward := bpfTuplesKeyFromAddrPorts(otherSrc, otherDst, uint8(unix.IPPROTO_UDP))
	otherReverse := bpfTuplesKeyFromAddrPorts(otherDst, otherSrc, uint8(unix.IPPROTO_UDP))

	// Seed the kernel entry so the "not deleted" half is observable when real
	// maps are available. The refcount assertions below hold in both builds;
	// the map-based ones only run where a kernel map can be created (the
	// dae_stub_ebpf build has no BPF objects, and newJanitorTestMap would skip
	// the whole test instead of just that half).
	var connMap *ebpf.Map
	if spec, err := loadBpf(); err == nil && spec != nil {
		connMap = newJanitorTestMap(t, "conn_state_map")
		value := bpfConnState{LastSeenNs: 1}
		value.Meta.Data.HasRouting = 1
		if err := connMap.Update(&sharedForward, &value, ebpf.UpdateAny); err != nil {
			t.Fatalf("seed conn_state: %v", err)
		}
		manager.udpBPF.Store(&bpfObjects{bpfMaps: bpfMaps{ConnStateMap: connMap}})
	}

	owner := &UdpEndpoint{udpConnStateOwner: manager}
	other := &UdpEndpoint{udpConnStateOwner: manager}
	owner.TrackUdpConnStateTuplePair(sharedSrc, sharedDst)
	other.TrackUdpConnStateTuplePair(sharedSrc, sharedDst)
	if got := pinnedUDPRefs(manager, sharedForward); got != 2 {
		t.Fatalf("shared tuple refs = %d, want 2", got)
	}

	// The first owner moves to a different pair: its own reference drops, the
	// shared entry stays pinned by the other owner.
	owner.TrackUdpConnStateTuplePair(otherSrc, otherDst)
	if got := pinnedUDPRefs(manager, sharedForward); got != 1 {
		t.Fatalf("shared tuple refs after one owner moved = %d, want 1 (the other owner)", got)
	}
	if connMap != nil && !connStateExists(connMap, sharedForward) {
		t.Fatal("regression: the shared conn_state entry was deleted while another endpoint still pins it")
	}
	if got := pinnedUDPRefs(manager, otherForward); got != 1 {
		t.Fatalf("moved owner's new tuple refs = %d, want 1", got)
	}
	if got := pinnedUDPRefs(manager, sharedReverse); got != 1 {
		t.Fatalf("shared reverse tuple refs = %d, want 1", got)
	}
	if got := pinnedUDPRefs(manager, otherReverse); got != 1 {
		t.Fatalf("moved owner's new reverse tuple refs = %d, want 1", got)
	}

	other.releaseTrackedUdpConnState()
	if got := pinnedUDPRefs(manager, sharedForward); got != 0 {
		t.Fatalf("shared tuple refs after the last owner released = %d, want 0", got)
	}
	if connMap != nil && connStateExists(connMap, sharedForward) {
		t.Fatal("conn_state entry leaked after the last pin dropped")
	}
}
