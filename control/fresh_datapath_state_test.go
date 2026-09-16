/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	stderrors "errors"
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func TestFreshDatapathStateReplacesProcessFlowMapsAndKeepsCapacity(t *testing.T) {
	connState := newJanitorTestMap(t, "conn_state_map")
	redirectTrack := newJanitorTestMap(t, "redirect_track")
	cookiePID := newJanitorTestMap(t, "cookie_pid_map")
	plane := &ControlPlane{core: &controlPlaneCore{}}
	plane.core.bpf.Store(&bpfObjects{bpfMaps: bpfMaps{
		ConnStateMap:  connState,
		RedirectTrack: redirectTrack,
		CookiePidMap:  cookiePID,
	}})

	state, err := plane.SnapshotFreshDatapathState()
	if err != nil {
		t.Fatalf("SnapshotFreshDatapathState() error = %v", err)
	}
	options := &ebpf.CollectionOptions{}
	maxEntries, err := state.apply(options, connState.MaxEntries()+1, nil)
	if err != nil {
		t.Fatalf("apply() error = %v", err)
	}
	if maxEntries != connState.MaxEntries() {
		t.Fatalf("max entries = %d, want %d", maxEntries, connState.MaxEntries())
	}
	for name, want := range map[string]*ebpf.Map{
		"conn_state_map": connState,
		"redirect_track": redirectTrack,
		"cookie_pid_map": cookiePID,
	} {
		if got := options.MapReplacements[name]; got != want {
			t.Fatalf("replacement %s = %p, want %p", name, got, want)
		}
	}
}

func TestAdoptProcessFlowDatapathMovesUDPDeletionToSuccessorHandle(t *testing.T) {
	oldMap := newJanitorTestMap(t, "conn_state_map")
	newMap := newJanitorTestMap(t, "conn_state_map")
	oldBPF := &bpfObjects{bpfMaps: bpfMaps{ConnStateMap: oldMap}}
	newBPF := &bpfObjects{bpfMaps: bpfMaps{ConnStateMap: newMap}}
	manager := NewSessionManager(context.Background())
	defer func() { _ = manager.Close() }()
	manager.udpBPF.Store(oldBPF)
	previous := &ControlPlane{sessionManager: manager, core: &controlPlaneCore{}}
	previous.core.bpf.Store(oldBPF)
	successor := &ControlPlane{sessionManager: manager, core: &controlPlaneCore{}}
	successor.core.bpf.Store(newBPF)

	key := bpfTuplesKeyFromAddrPorts(
		netip.MustParseAddrPort("192.0.2.80:45000"),
		netip.MustParseAddrPort("198.51.100.90:443"),
		unix.IPPROTO_UDP,
	)
	state := bpfConnState{LastSeenNs: 1}
	if err := newMap.Update(&key, &state, ebpf.UpdateAny); err != nil {
		t.Fatalf("update successor conn state: %v", err)
	}
	manager.RetainUdpConnStateTuples([]bpfTuplesKey{key})
	if err := successor.AdoptProcessFlowDatapath(previous); err != nil {
		t.Fatalf("AdoptProcessFlowDatapath() error = %v", err)
	}
	if err := manager.ReleaseUdpConnStateTuples([]bpfTuplesKey{key}); err != nil {
		t.Fatalf("ReleaseUdpConnStateTuples() error = %v", err)
	}
	var got bpfConnState
	if err := newMap.Lookup(&key, &got); !stderrors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("successor conn state after release error = %v, want %v", err, ebpf.ErrKeyNotExist)
	}
}
