/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	stderrors "errors"
	"io"
	"net/netip"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/sirupsen/logrus"
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
	udpMap := newJanitorTestMap(t, "conn_state_map")
	core := &controlPlaneCore{
		bpf: &bpfObjects{
			bpfMaps: bpfMaps{
				ConnStateMap: udpMap,
			},
		},
	}

	src := netip.MustParseAddrPort("192.0.2.10:40000")
	dst := netip.MustParseAddrPort("198.51.100.20:443")
	forward := bpfTuplesKeyFromAddrPorts(src, dst, uint8(syscall.IPPROTO_UDP))
	reverse := bpfTuplesKeyFromAddrPorts(dst, src, uint8(syscall.IPPROTO_UDP))

	for _, key := range []bpfTuplesKey{forward, reverse} {
		state := bpfConnState{LastSeenNs: 1}
		if err := udpMap.Update(&key, &state, ebpf.UpdateAny); err != nil {
			t.Fatalf("update udp conn-state %v: %v", key, err)
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
		var state bpfConnState
		if err := udpMap.Lookup(&key, &state); err != nil {
			t.Fatalf("Lookup(%v) after first close err = %v, want tuple to remain", key, err)
		}
	}

	if err := ue2.Close(); err != nil {
		t.Fatalf("ue2.Close(): %v", err)
	}
	for _, key := range []bpfTuplesKey{forward, reverse} {
		var state bpfConnState
		if err := udpMap.Lookup(&key, &state); !stderrors.Is(err, ebpf.ErrKeyNotExist) {
			t.Fatalf("Lookup(%v) after second close err = %v, want %v", key, err, ebpf.ErrKeyNotExist)
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

func TestAcquireSharedUdpConnStateTrackerSharesByBpfObject(t *testing.T) {
	bpf := &bpfObjects{}

	first := acquireSharedUdpConnStateTracker(bpf)
	second := acquireSharedUdpConnStateTracker(bpf)
	if first != second {
		t.Fatal("expected same BPF object to share one UDP conn-state tracker")
	}

	releaseSharedUdpConnStateTracker(bpf, first)
	releaseSharedUdpConnStateTracker(bpf, second)

	sharedUdpConnStateTrackerRegistry.mu.Lock()
	_, ok := sharedUdpConnStateTrackerRegistry.entries[bpf]
	sharedUdpConnStateTrackerRegistry.mu.Unlock()
	if ok {
		t.Fatal("expected tracker registry entry to be released after the last owner")
	}
}

func TestUdpEndpointAdoptGenerationTransfersTrackedTupleOwnership(t *testing.T) {
	udpMap := newJanitorTestMap(t, "conn_state_map")
	oldCore := &controlPlaneCore{
		bpf: &bpfObjects{
			bpfMaps: bpfMaps{
				ConnStateMap: udpMap,
			},
		},
	}
	newCore := &controlPlaneCore{
		bpf: &bpfObjects{
			bpfMaps: bpfMaps{
				ConnStateMap: udpMap,
			},
		},
	}

	src := netip.MustParseAddrPort("192.0.2.40:40040")
	dst := netip.MustParseAddrPort("198.51.100.50:443")
	forward := bpfTuplesKeyFromAddrPorts(src, dst, uint8(syscall.IPPROTO_UDP))
	reverse := bpfTuplesKeyFromAddrPorts(dst, src, uint8(syscall.IPPROTO_UDP))

	for _, key := range []bpfTuplesKey{forward, reverse} {
		state := bpfConnState{LastSeenNs: 1}
		if err := udpMap.Update(&key, &state, ebpf.UpdateAny); err != nil {
			t.Fatalf("update udp conn-state %v: %v", key, err)
		}
	}

	ue := &UdpEndpoint{
		poolKey:           UdpEndpointKey{Src: src},
		udpConnStateOwner: oldCore,
	}
	ue.TrackUdpConnStateTuplePair(src, dst)

	oldTracker := oldCore.getUdpConnStateTracker()
	oldTracker.mu.Lock()
	if len(oldTracker.entries) != 2 {
		oldTracker.mu.Unlock()
		t.Fatalf("old tracker entries before adoption = %d, want 2", len(oldTracker.entries))
	}
	oldTracker.mu.Unlock()

	ue.adoptGeneration(newCore, nil)

	oldTracker.mu.Lock()
	oldEntryCount := len(oldTracker.entries)
	oldTracker.mu.Unlock()
	if oldEntryCount != 0 {
		t.Fatalf("old tracker entries after adoption = %d, want 0", oldEntryCount)
	}

	newTracker := newCore.getUdpConnStateTracker()
	newTracker.mu.Lock()
	newEntryCount := len(newTracker.entries)
	newTracker.mu.Unlock()
	if newEntryCount != 2 {
		t.Fatalf("new tracker entries after adoption = %d, want 2", newEntryCount)
	}

	if err := ue.Close(); err != nil {
		t.Fatalf("ue.Close(): %v", err)
	}
	for _, key := range []bpfTuplesKey{forward, reverse} {
		var state bpfConnState
		if err := udpMap.Lookup(&key, &state); !stderrors.Is(err, ebpf.ErrKeyNotExist) {
			t.Fatalf("Lookup(%v) after close err = %v, want %v", key, err, ebpf.ErrKeyNotExist)
		}
	}
}

func TestUdpEndpointAdoptGenerationKeepsSharedTupleUntilLastEndpointCloses(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	udpMap := newJanitorTestMap(t, "conn_state_map")
	sharedBpf := &bpfObjects{
		bpfMaps: bpfMaps{
			ConnStateMap: udpMap,
		},
	}
	tracker := acquireSharedUdpConnStateTracker(sharedBpf)
	defer releaseSharedUdpConnStateTracker(sharedBpf, tracker)

	oldCore := &controlPlaneCore{
		log: logger,
		bpf: sharedBpf,
	}
	oldCore.udpConnStateTracker.Store(tracker)
	newCore := &controlPlaneCore{
		log: logger,
		bpf: sharedBpf,
	}
	newCore.udpConnStateTracker.Store(tracker)

	src := netip.MustParseAddrPort("192.0.2.60:40060")
	dst := netip.MustParseAddrPort("198.51.100.70:443")
	forward := bpfTuplesKeyFromAddrPorts(src, dst, uint8(syscall.IPPROTO_UDP))
	reverse := bpfTuplesKeyFromAddrPorts(dst, src, uint8(syscall.IPPROTO_UDP))

	for _, key := range []bpfTuplesKey{forward, reverse} {
		state := bpfConnState{LastSeenNs: 1}
		if err := udpMap.Update(&key, &state, ebpf.UpdateAny); err != nil {
			t.Fatalf("update udp conn-state %v: %v", key, err)
		}
	}

	ueOld := &UdpEndpoint{
		poolKey:           UdpEndpointKey{Src: src},
		udpConnStateOwner: oldCore,
	}
	ueAdopted := &UdpEndpoint{
		poolKey:           UdpEndpointKey{Src: src, RouteScope: udpEndpointRouteScope{Outbound: 1}},
		udpConnStateOwner: oldCore,
	}

	ueOld.TrackUdpConnStateTuplePair(src, dst)
	ueAdopted.TrackUdpConnStateTuplePair(src, dst)
	ueAdopted.adoptGeneration(newCore, nil)

	if err := ueOld.Close(); err != nil {
		t.Fatalf("ueOld.Close(): %v", err)
	}
	for _, key := range []bpfTuplesKey{forward, reverse} {
		var state bpfConnState
		if err := udpMap.Lookup(&key, &state); err != nil {
			t.Fatalf("Lookup(%v) after old endpoint close err = %v, want tuple to remain", key, err)
		}
	}

	if err := ueAdopted.Close(); err != nil {
		t.Fatalf("ueAdopted.Close(): %v", err)
	}
	for _, key := range []bpfTuplesKey{forward, reverse} {
		var state bpfConnState
		if err := udpMap.Lookup(&key, &state); !stderrors.Is(err, ebpf.ErrKeyNotExist) {
			t.Fatalf("Lookup(%v) after adopted endpoint close err = %v, want %v", key, err, ebpf.ErrKeyNotExist)
		}
	}
}
