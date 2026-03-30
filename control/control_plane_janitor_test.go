/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	stderrors "errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/daeuniverse/dae/common"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

func TestUpdateConnStateJanitorPressureActivatesOnOverflow(t *testing.T) {
	state := updateConnStateJanitorPressure(connStateJanitorPressureState{}, true, 0)
	if !state.active {
		t.Fatal("expected pressure mode to activate on overflow")
	}
	if state.belowThresholdRounds != 0 {
		t.Fatalf("expected belowThresholdRounds to reset, got %d", state.belowThresholdRounds)
	}
}

func TestUpdateConnStateJanitorPressureActivatesOnUsage(t *testing.T) {
	state := updateConnStateJanitorPressure(connStateJanitorPressureState{}, false, connStateJanitorPressureEnterUsage)
	if !state.active {
		t.Fatal("expected pressure mode to activate on high usage")
	}
}

func TestUpdateConnStateJanitorPressureExitsAfterConsecutiveLowUsage(t *testing.T) {
	state := connStateJanitorPressureState{active: true}
	for i := 0; i < connStateJanitorPressureExitRounds-1; i++ {
		state = updateConnStateJanitorPressure(state, false, connStateJanitorPressureExitUsage-1)
		if !state.active {
			t.Fatalf("pressure mode exited too early at round %d", i+1)
		}
	}
	state = updateConnStateJanitorPressure(state, false, connStateJanitorPressureExitUsage-1)
	if state.active {
		t.Fatal("expected pressure mode to exit after enough low-usage rounds")
	}
	if state.belowThresholdRounds != 0 {
		t.Fatalf("expected belowThresholdRounds to reset after exit, got %d", state.belowThresholdRounds)
	}
}

func TestUpdateConnStateJanitorPressureResetsExitCountdown(t *testing.T) {
	state := connStateJanitorPressureState{
		active:               true,
		belowThresholdRounds: connStateJanitorPressureExitRounds - 1,
	}
	state = updateConnStateJanitorPressure(state, false, connStateJanitorPressureEnterUsage)
	if !state.active {
		t.Fatal("expected pressure mode to remain active")
	}
	if state.belowThresholdRounds != 0 {
		t.Fatalf("expected high usage to reset belowThresholdRounds, got %d", state.belowThresholdRounds)
	}
}

func TestDisablePinnedConnStateMaps(t *testing.T) {
	spec := &ebpf.CollectionSpec{
		Maps: map[string]*ebpf.MapSpec{
			"tcp_conn_state_map": {
				Name:    "tcp_conn_state_map",
				Pinning: ebpf.PinByName,
			},
			"udp_conn_state_map": {
				Name:    "udp_conn_state_map",
				Pinning: ebpf.PinByName,
			},
			"domain_routing_map": {
				Name:    "domain_routing_map",
				Pinning: ebpf.PinByName,
			},
		},
	}

	if err := disablePinnedConnStateMaps(spec); err != nil {
		t.Fatalf("disablePinnedConnStateMaps returned error: %v", err)
	}
	if got := spec.Maps["tcp_conn_state_map"].Pinning; got != ebpf.PinNone {
		t.Fatalf("tcp_conn_state_map pinning = %v, want %v", got, ebpf.PinNone)
	}
	if got := spec.Maps["udp_conn_state_map"].Pinning; got != ebpf.PinNone {
		t.Fatalf("udp_conn_state_map pinning = %v, want %v", got, ebpf.PinNone)
	}
	if got := spec.Maps["domain_routing_map"].Pinning; got != ebpf.PinByName {
		t.Fatalf("domain_routing_map pinning = %v, want %v", got, ebpf.PinByName)
	}
}

func TestCleanupPinnedConnStateMapFiles(t *testing.T) {
	pinPath := t.TempDir()
	for _, name := range []string{"tcp_conn_state_map", "udp_conn_state_map", "domain_routing_map"} {
		if err := os.WriteFile(filepath.Join(pinPath, name), []byte("x"), 0644); err != nil {
			t.Fatalf("write test pin file %s: %v", name, err)
		}
	}

	removed := cleanupPinnedConnStateMapFiles(nil, pinPath)
	if removed != 2 {
		t.Fatalf("cleanupPinnedConnStateMapFiles removed %d files, want 2", removed)
	}

	for _, name := range []string{"tcp_conn_state_map", "udp_conn_state_map"} {
		if _, err := os.Stat(filepath.Join(pinPath, name)); !os.IsNotExist(err) {
			t.Fatalf("expected %s to be removed, stat err=%v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(pinPath, "domain_routing_map")); err != nil {
		t.Fatalf("expected unrelated pin file to remain: %v", err)
	}
}

func TestCleanupUdpConnStateMapRemovesExpiredRoutingResult(t *testing.T) {
	udpMap := newJanitorTestMap(t, "udp_conn_state_map")
	now := monotonicNowNs(t)

	freshSrc := common.ConvergeAddrPort(netip.MustParseAddrPort("10.0.0.1:12345"))
	freshDst := common.ConvergeAddrPort(netip.MustParseAddrPort("1.1.1.1:443"))
	staleSrc := common.ConvergeAddrPort(netip.MustParseAddrPort("10.0.0.2:12346"))
	staleDst := common.ConvergeAddrPort(netip.MustParseAddrPort("1.1.1.1:443"))

	freshKey := tuplesKeyFromAddrPorts(freshSrc, freshDst, unix.IPPROTO_UDP)
	staleKey := tuplesKeyFromAddrPorts(staleSrc, staleDst, unix.IPPROTO_UDP)

	var freshState bpfUdpConnState
	freshState.LastSeenNs = now
	freshState.Meta.Data.Mark = 101
	freshState.Meta.Data.Outbound = 7
	freshState.Meta.Data.Dscp = 8
	freshState.Meta.Data.HasRouting = 1
	freshState.Pid = 42
	copy(freshState.Pname[:], "udp-fresh")
	copy(freshState.Mac[:], []byte{1, 2, 3, 4, 5, 6})

	staleState := freshState
	staleState.LastSeenNs = staleTimestampNs(now, udpConnStateTimeoutNormal+time.Second)
	staleState.Meta.Data.Mark = 202
	staleState.Meta.Data.Outbound = 9
	staleState.Pid = 43
	copy(staleState.Pname[:], "udp-stale")

	if err := udpMap.Update(freshKey, &freshState, ebpf.UpdateAny); err != nil {
		t.Fatalf("update fresh udp conn-state: %v", err)
	}
	if err := udpMap.Update(staleKey, &staleState, ebpf.UpdateAny); err != nil {
		t.Fatalf("update stale udp conn-state: %v", err)
	}

	core := &controlPlaneCore{bpf: &bpfObjects{bpfMaps: bpfMaps{UdpConnStateMap: udpMap}}}
	plane := &ControlPlane{
		log:                  logrus.New(),
		core:                 core,
		connStateJanitorStop: make(chan struct{}),
	}

	stats := plane.cleanupUdpConnStateMap(false)
	if stats.entries != 2 {
		t.Fatalf("cleanupUdpConnStateMap entries = %d, want 2", stats.entries)
	}
	if stats.deleted != 1 {
		t.Fatalf("cleanupUdpConnStateMap deleted = %d, want 1", stats.deleted)
	}

	freshResult, err := core.RetrieveRoutingResult(freshSrc, freshDst, unix.IPPROTO_UDP)
	if err != nil {
		t.Fatalf("RetrieveRoutingResult fresh udp: %v", err)
	}
	if freshResult.Mark != freshState.Meta.Data.Mark || freshResult.Outbound != freshState.Meta.Data.Outbound {
		t.Fatalf("fresh udp routing result = %+v, want mark=%d outbound=%d", freshResult, freshState.Meta.Data.Mark, freshState.Meta.Data.Outbound)
	}

	staleResult, err := core.RetrieveRoutingResult(staleSrc, staleDst, unix.IPPROTO_UDP)
	if !stderrors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("RetrieveRoutingResult stale udp err = %v, want %v", err, ebpf.ErrKeyNotExist)
	}
	if staleResult != nil {
		t.Fatalf("stale udp routing result = %+v, want nil", staleResult)
	}
}

func TestCleanupTcpConnStateMapRemovesExpiredRoutingResult(t *testing.T) {
	tcpMap := newJanitorTestMap(t, "tcp_conn_state_map")
	now := monotonicNowNs(t)

	freshSrc := common.ConvergeAddrPort(netip.MustParseAddrPort("10.0.1.1:22345"))
	freshDst := common.ConvergeAddrPort(netip.MustParseAddrPort("2.2.2.2:443"))
	staleSrc := common.ConvergeAddrPort(netip.MustParseAddrPort("10.0.1.2:22346"))
	staleDst := common.ConvergeAddrPort(netip.MustParseAddrPort("2.2.2.2:443"))

	freshKey := tuplesKeyFromAddrPorts(freshSrc, freshDst, unix.IPPROTO_TCP)
	staleKey := tuplesKeyFromAddrPorts(staleSrc, staleDst, unix.IPPROTO_TCP)

	var freshState bpfTcpConnState
	freshState.State = 0
	freshState.LastSeenNs = now
	freshState.Meta.Data.Mark = 303
	freshState.Meta.Data.Outbound = 11
	freshState.Meta.Data.Dscp = 12
	freshState.Meta.Data.HasRouting = 1
	freshState.Pid = 52
	copy(freshState.Pname[:], "tcp-fresh")
	copy(freshState.Mac[:], []byte{6, 5, 4, 3, 2, 1})

	staleState := freshState
	staleState.LastSeenNs = staleTimestampNs(now, tcpConnStateTimeoutEstablished+time.Second)
	staleState.Meta.Data.Mark = 404
	staleState.Meta.Data.Outbound = 13
	staleState.Pid = 53
	copy(staleState.Pname[:], "tcp-stale")

	if err := tcpMap.Update(freshKey, &freshState, ebpf.UpdateAny); err != nil {
		t.Fatalf("update fresh tcp conn-state: %v", err)
	}
	if err := tcpMap.Update(staleKey, &staleState, ebpf.UpdateAny); err != nil {
		t.Fatalf("update stale tcp conn-state: %v", err)
	}

	core := &controlPlaneCore{bpf: &bpfObjects{bpfMaps: bpfMaps{TcpConnStateMap: tcpMap}}}
	plane := &ControlPlane{
		log:                  logrus.New(),
		core:                 core,
		connStateJanitorStop: make(chan struct{}),
	}

	stats := plane.cleanupTcpConnStateMap(false)
	if stats.entries != 2 {
		t.Fatalf("cleanupTcpConnStateMap entries = %d, want 2", stats.entries)
	}
	if stats.deleted != 1 {
		t.Fatalf("cleanupTcpConnStateMap deleted = %d, want 1", stats.deleted)
	}

	freshResult, err := core.RetrieveRoutingResult(freshSrc, freshDst, unix.IPPROTO_TCP)
	if err != nil {
		t.Fatalf("RetrieveRoutingResult fresh tcp: %v", err)
	}
	if freshResult.Mark != freshState.Meta.Data.Mark || freshResult.Outbound != freshState.Meta.Data.Outbound {
		t.Fatalf("fresh tcp routing result = %+v, want mark=%d outbound=%d", freshResult, freshState.Meta.Data.Mark, freshState.Meta.Data.Outbound)
	}

	staleResult, err := core.RetrieveRoutingResult(staleSrc, staleDst, unix.IPPROTO_TCP)
	if !stderrors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("RetrieveRoutingResult stale tcp err = %v, want %v", err, ebpf.ErrKeyNotExist)
	}
	if staleResult != nil {
		t.Fatalf("stale tcp routing result = %+v, want nil", staleResult)
	}
}

func TestCleanupRedirectTrackMapUsesIndependentTTL(t *testing.T) {
	redirectMap := newJanitorTestMap(t, "redirect_track")
	now := monotonicNowNs(t)

	freshKey := redirectTupleFromAddrs(netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("10.0.2.1"))
	staleKey := redirectTupleFromAddrs(netip.MustParseAddr("1.1.1.2"), netip.MustParseAddr("10.0.2.2"))

	freshEntry := bpfRedirectEntry{
		Ifindex:    7,
		FromWan:    1,
		LastSeenNs: now,
	}
	copy(freshEntry.Smac[:], []byte{0, 1, 2, 3, 4, 5})
	copy(freshEntry.Dmac[:], []byte{5, 4, 3, 2, 1, 0})

	staleEntry := freshEntry
	staleEntry.Ifindex = 8
	staleEntry.LastSeenNs = staleTimestampNs(now, redirectTrackTimeout+time.Second)

	if err := redirectMap.Update(freshKey, &freshEntry, ebpf.UpdateAny); err != nil {
		t.Fatalf("update fresh redirect_track: %v", err)
	}
	if err := redirectMap.Update(staleKey, &staleEntry, ebpf.UpdateAny); err != nil {
		t.Fatalf("update stale redirect_track: %v", err)
	}

	plane := &ControlPlane{
		log: logrus.New(),
		core: &controlPlaneCore{
			bpf: &bpfObjects{bpfMaps: bpfMaps{RedirectTrack: redirectMap}},
		},
		connStateJanitorStop: make(chan struct{}),
	}

	plane.cleanupRedirectTrackMap()

	var gotFresh bpfRedirectEntry
	if err := redirectMap.Lookup(freshKey, &gotFresh); err != nil {
		t.Fatalf("fresh redirect_track lookup failed: %v", err)
	}
	if gotFresh.Ifindex != freshEntry.Ifindex {
		t.Fatalf("fresh redirect_track ifindex = %d, want %d", gotFresh.Ifindex, freshEntry.Ifindex)
	}

	var gotStale bpfRedirectEntry
	if err := redirectMap.Lookup(staleKey, &gotStale); !stderrors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("stale redirect_track lookup err = %v, want %v", err, ebpf.ErrKeyNotExist)
	}
}

func newJanitorTestMap(t *testing.T, mapName string) *ebpf.Map {
	t.Helper()

	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock failed: %v", err)
	}

	spec, err := loadBpf()
	if err != nil {
		t.Fatalf("loadBpf: %v", err)
	}

	mapSpec, ok := spec.Maps[mapName]
	if !ok || mapSpec == nil {
		t.Fatalf("missing map spec %q", mapName)
	}

	cloned := *mapSpec
	cloned.Pinning = ebpf.PinNone
	m, err := ebpf.NewMap(&cloned)
	if err != nil {
		t.Skipf("creating test map %s requires BPF privileges: %v", mapName, err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m
}

func monotonicNowNs(t *testing.T) uint64 {
	t.Helper()

	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		t.Fatalf("ClockGettime(CLOCK_MONOTONIC): %v", err)
	}
	return uint64(ts.Nano())
}

func staleTimestampNs(now uint64, age time.Duration) uint64 {
	delta := uint64(age.Nanoseconds())
	if now <= delta {
		return 0
	}
	return now - delta
}

func tuplesKeyFromAddrPorts(src, dst netip.AddrPort, l4proto uint8) *bpfTuplesKey {
	src = common.ConvergeAddrPort(src)
	dst = common.ConvergeAddrPort(dst)

	var key bpfTuplesKey
	key.Sip.U6Addr8 = src.Addr().As16()
	key.Dip.U6Addr8 = dst.Addr().As16()
	key.Sport = common.Htons(src.Port())
	key.Dport = common.Htons(dst.Port())
	key.L4proto = l4proto
	return &key
}

func redirectTupleFromAddrs(src, dst netip.Addr) *bpfRedirectTuple {
	src = common.ConvergeAddr(src)
	dst = common.ConvergeAddr(dst)

	var key bpfRedirectTuple
	key.Sip.U6Addr8 = src.As16()
	key.Dip.U6Addr8 = dst.As16()
	return &key
}
