/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	stderrors "errors"
	"net/netip"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
)

func TestUdpConnStateTrackerRetainWaitsForFinalize(t *testing.T) {
	tracker := newUdpConnStateTracker()
	key := bpfTuplesKeyFromAddrPorts(
		netip.MustParseAddrPort("192.0.2.10:40000"),
		netip.MustParseAddrPort("198.51.100.20:443"),
		uint8(syscall.IPPROTO_UDP),
	)

	tracker.Retain([]bpfTuplesKey{key})
	releases := tracker.BeginRelease([]bpfTuplesKey{key})
	if len(releases) != 1 {
		t.Fatalf("BeginRelease() releases = %d, want 1", len(releases))
	}

	retained := make(chan struct{})
	go func() {
		tracker.Retain([]bpfTuplesKey{key})
		close(retained)
	}()

	select {
	case <-retained:
		t.Fatal("Retain should block while the last owner is finalizing delete")
	case <-time.After(20 * time.Millisecond):
	}

	tracker.FinalizeRelease(releases)

	select {
	case <-retained:
	case <-time.After(time.Second):
		t.Fatal("Retain did not resume after FinalizeRelease")
	}
}

func TestUdpConnStateTrackerSharedTupleSurvivesUntilLastEndpointCloses(t *testing.T) {
	udpMap := newJanitorTestMap(t, "udp_conn_state_map")
	handoffMap := newJanitorTestMap(t, "routing_handoff_map")
	core := &controlPlaneCore{
		bpf: &bpfObjects{
			bpfMaps: bpfMaps{
				UdpConnStateMap:   udpMap,
				RoutingHandoffMap: handoffMap,
			},
		},
	}

	src := netip.MustParseAddrPort("192.0.2.10:40000")
	dst := netip.MustParseAddrPort("198.51.100.20:443")
	forward := bpfTuplesKeyFromAddrPorts(src, dst, uint8(syscall.IPPROTO_UDP))
	reverse := bpfTuplesKeyFromAddrPorts(dst, src, uint8(syscall.IPPROTO_UDP))

	for _, key := range []bpfTuplesKey{forward, reverse} {
		state := bpfUdpConnState{LastSeenNs: 1}
		if err := udpMap.Update(&key, &state, ebpf.UpdateAny); err != nil {
			t.Fatalf("update udp conn-state %v: %v", key, err)
		}
		handoff := bpfRoutingHandoff{LastSeenNs: 1}
		if err := handoffMap.Update(&key, &handoff, ebpf.UpdateAny); err != nil {
			t.Fatalf("update handoff %v: %v", key, err)
		}
	}

	ue1 := &UdpEndpoint{
		poolKey:           UdpEndpointKey{Src: src},
		udpConnStateOwner: core,
	}
	ue2 := &UdpEndpoint{
		poolKey:           UdpEndpointKey{Src: src, RouteScope: udpEndpointRouteScope{Dscp: 46, Outbound: 1}},
		udpConnStateOwner: core,
	}

	ue1.TrackUdpConnStateTuplePair(src, dst)
	ue2.TrackUdpConnStateTuplePair(src, dst)

	if err := ue1.Close(); err != nil {
		t.Fatalf("ue1.Close(): %v", err)
	}
	for _, key := range []bpfTuplesKey{forward, reverse} {
		var state bpfUdpConnState
		if err := udpMap.Lookup(&key, &state); err != nil {
			t.Fatalf("Lookup(%v) after first close err = %v, want tuple to remain", key, err)
		}
		var handoff bpfRoutingHandoff
		if err := handoffMap.Lookup(&key, &handoff); err != nil {
			t.Fatalf("HandoffLookup(%v) after first close err = %v, want handoff to remain", key, err)
		}
	}

	if err := ue2.Close(); err != nil {
		t.Fatalf("ue2.Close(): %v", err)
	}
	for _, key := range []bpfTuplesKey{forward, reverse} {
		var state bpfUdpConnState
		if err := udpMap.Lookup(&key, &state); !stderrors.Is(err, ebpf.ErrKeyNotExist) {
			t.Fatalf("Lookup(%v) after second close err = %v, want %v", key, err, ebpf.ErrKeyNotExist)
		}
		var handoff bpfRoutingHandoff
		if err := handoffMap.Lookup(&key, &handoff); !stderrors.Is(err, ebpf.ErrKeyNotExist) {
			t.Fatalf("HandoffLookup(%v) after second close err = %v, want %v", key, err, ebpf.ErrKeyNotExist)
		}
	}
}

func TestControlPlaneCoreReleaseUdpConnStateTuplesWithoutMapDropsTrackerRef(t *testing.T) {
	core := &controlPlaneCore{}
	key := bpfTuplesKeyFromAddrPorts(
		netip.MustParseAddrPort("192.0.2.20:40020"),
		netip.MustParseAddrPort("198.51.100.30:443"),
		uint8(syscall.IPPROTO_UDP),
	)

	core.RetainUdpConnStateTuples([]bpfTuplesKey{key})
	if err := core.ReleaseUdpConnStateTuples([]bpfTuplesKey{key}); err != nil {
		t.Fatalf("ReleaseUdpConnStateTuples() error = %v", err)
	}

	tracker := core.getUdpConnStateTracker()
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	if _, ok := tracker.entries[key]; ok {
		t.Fatal("expected tracker entry to be removed even when no BPF map is attached")
	}
}
