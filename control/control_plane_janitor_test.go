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
	"strings"
	"testing"
	"time"
	"unsafe"

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

func TestTunePlaceholderBpfMaps(t *testing.T) {
	spec := &ebpf.CollectionSpec{
		Maps: map[string]*ebpf.MapSpec{
			"fast_sock": {
				Name:       "fast_sock",
				MaxEntries: 65535,
			},
		},
	}

	if err := tunePlaceholderBpfMaps(spec); err != nil {
		t.Fatalf("tunePlaceholderBpfMaps returned error: %v", err)
	}
	if got := spec.Maps["fast_sock"].MaxEntries; got != fastSockPlaceholderMaxEntries {
		t.Fatalf("fast_sock max_entries = %d, want %d", got, fastSockPlaceholderMaxEntries)
	}
}

func TestConnStateStructSizes(t *testing.T) {
	if got := unsafe.Sizeof(bpfTcpConnState{}); got != 56 {
		t.Fatalf("sizeof(bpfTcpConnState) = %d, want 56", got)
	}
	if got := unsafe.Sizeof(bpfUdpConnState{}); got != 56 {
		t.Fatalf("sizeof(bpfUdpConnState) = %d, want 56", got)
	}
	if got := unsafe.Sizeof(bpfPidPname{}); got != 32 {
		t.Fatalf("sizeof(bpfPidPname) = %d, want 32", got)
	}
}

func TestCustomizeBpfMapSpecs(t *testing.T) {
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
			"fast_sock": {
				Name:       "fast_sock",
				MaxEntries: 65535,
			},
		},
	}

	if err := customizeBpfMapSpecs(spec); err != nil {
		t.Fatalf("customizeBpfMapSpecs returned error: %v", err)
	}
	if got := spec.Maps["tcp_conn_state_map"].Pinning; got != ebpf.PinNone {
		t.Fatalf("tcp_conn_state_map pinning = %v, want %v", got, ebpf.PinNone)
	}
	if got := spec.Maps["udp_conn_state_map"].Pinning; got != ebpf.PinNone {
		t.Fatalf("udp_conn_state_map pinning = %v, want %v", got, ebpf.PinNone)
	}
	if got := spec.Maps["fast_sock"].MaxEntries; got != fastSockPlaceholderMaxEntries {
		t.Fatalf("fast_sock max_entries = %d, want %d", got, fastSockPlaceholderMaxEntries)
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

	staleState := freshState
	staleState.LastSeenNs = staleTimestampNs(now, QuicNatTimeout+time.Second)
	staleState.Meta.Data.Mark = 202
	staleState.Meta.Data.Outbound = 9

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

	staleState := freshState
	staleState.LastSeenNs = staleTimestampNs(now, tcpConnStateTimeoutEstablished+time.Second)
	staleState.Meta.Data.Mark = 404
	staleState.Meta.Data.Outbound = 13

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

func TestCleanupTcpConnStateMapRemovesClosingStateByClosingTimeout(t *testing.T) {
	tcpMap := newJanitorTestMap(t, "tcp_conn_state_map")
	now := monotonicNowNs(t)

	src := common.ConvergeAddrPort(netip.MustParseAddrPort("10.0.2.1:32345"))
	dst := common.ConvergeAddrPort(netip.MustParseAddrPort("3.3.3.3:443"))
	key := tuplesKeyFromAddrPorts(src, dst, unix.IPPROTO_TCP)

	var state bpfTcpConnState
	state.State = 1 // TCP_STATE_CLOSING
	state.LastSeenNs = staleTimestampNs(now, tcpConnStateTimeoutClosing+time.Second)
	state.Meta.Data.Mark = 505
	state.Meta.Data.Outbound = 17
	state.Meta.Data.HasRouting = 1

	if err := tcpMap.Update(key, &state, ebpf.UpdateAny); err != nil {
		t.Fatalf("update closing tcp conn-state: %v", err)
	}

	core := &controlPlaneCore{bpf: &bpfObjects{bpfMaps: bpfMaps{TcpConnStateMap: tcpMap}}}
	plane := &ControlPlane{
		log:                  logrus.New(),
		core:                 core,
		connStateJanitorStop: make(chan struct{}),
	}

	stats := plane.cleanupTcpConnStateMap(false)
	if stats.entries != 1 {
		t.Fatalf("cleanupTcpConnStateMap entries = %d, want 1", stats.entries)
	}
	if stats.deleted != 1 {
		t.Fatalf("cleanupTcpConnStateMap deleted = %d, want 1", stats.deleted)
	}

	result, err := core.RetrieveRoutingResult(src, dst, unix.IPPROTO_TCP)
	if !stderrors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("RetrieveRoutingResult closing tcp err = %v, want %v", err, ebpf.ErrKeyNotExist)
	}
	if result != nil {
		t.Fatalf("closing tcp routing result = %+v, want nil", result)
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

func TestCleanupCookiePidMapRemovesExpiredEntries(t *testing.T) {
	cookieMap := newJanitorTestMap(t, "cookie_pid_map")
	now := monotonicNowNs(t)

	freshKey := uint64(101)
	staleKey := uint64(202)

	fresh := bpfPidPname{
		LastSeenNs: now,
		Pid:        1234,
	}
	stale := bpfPidPname{
		LastSeenNs: staleTimestampNs(now, cookiePidMapTimeout+time.Second),
		Pid:        5678,
	}

	if err := cookieMap.Update(freshKey, &fresh, ebpf.UpdateAny); err != nil {
		t.Fatalf("update fresh cookie_pid_map: %v", err)
	}
	if err := cookieMap.Update(staleKey, &stale, ebpf.UpdateAny); err != nil {
		t.Fatalf("update stale cookie_pid_map: %v", err)
	}

	plane := &ControlPlane{
		log: logrus.New(),
		core: &controlPlaneCore{
			bpf: &bpfObjects{bpfMaps: bpfMaps{CookiePidMap: cookieMap}},
		},
		connStateJanitorStop: make(chan struct{}),
	}

	plane.cleanupCookiePidMap()

	var gotFresh bpfPidPname
	if err := cookieMap.Lookup(freshKey, &gotFresh); err != nil {
		t.Fatalf("fresh cookie_pid_map lookup failed: %v", err)
	}
	var gotStale bpfPidPname
	if err := cookieMap.Lookup(staleKey, &gotStale); !stderrors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("stale cookie_pid_map lookup err = %v, want %v", err, ebpf.ErrKeyNotExist)
	}
}

func TestRetrieveRoutingResultReturnsEmbeddedMetadata(t *testing.T) {
	tcpMap := newJanitorTestMap(t, "tcp_conn_state_map")
	now := monotonicNowNs(t)

	src := common.ConvergeAddrPort(netip.MustParseAddrPort("10.0.3.1:42345"))
	dst := common.ConvergeAddrPort(netip.MustParseAddrPort("4.4.4.4:443"))
	key := tuplesKeyFromAddrPorts(src, dst, unix.IPPROTO_TCP)

	var state bpfTcpConnState
	state.LastSeenNs = now
	state.Meta.Data.Mark = 606
	state.Meta.Data.Outbound = 19
	state.Meta.Data.Must = 1
	state.Meta.Data.Dscp = 22
	state.Meta.Data.HasRouting = 1
	state.Pid = 4242
	copy(state.Pname[:], "embedded-name")
	copy(state.Mac[:], []byte{9, 8, 7, 6, 5, 4})

	if err := tcpMap.Update(key, &state, ebpf.UpdateAny); err != nil {
		t.Fatalf("update tcp conn-state: %v", err)
	}

	core := &controlPlaneCore{
		bpf: &bpfObjects{bpfMaps: bpfMaps{TcpConnStateMap: tcpMap}},
	}

	result, err := core.RetrieveRoutingResult(src, dst, unix.IPPROTO_TCP)
	if err != nil {
		t.Fatalf("RetrieveRoutingResult: %v", err)
	}
	if result.Mark != state.Meta.Data.Mark || result.Outbound != state.Meta.Data.Outbound ||
		result.Must != state.Meta.Data.Must || result.Dscp != state.Meta.Data.Dscp {
		t.Fatalf("RetrieveRoutingResult routing fields = %+v, want mark=%d outbound=%d must=%d dscp=%d",
			result, state.Meta.Data.Mark, state.Meta.Data.Outbound, state.Meta.Data.Must, state.Meta.Data.Dscp)
	}
	if ProcessName2String(result.Pname[:]) != "embedded-name" {
		t.Fatalf("RetrieveRoutingResult pname = %q, want %q", ProcessName2String(result.Pname[:]), "embedded-name")
	}
	if got := result.Mac; got != [6]uint8{9, 8, 7, 6, 5, 4} {
		t.Fatalf("RetrieveRoutingResult mac = %v, want %v", got, [6]uint8{9, 8, 7, 6, 5, 4})
	}
	if result.Pid != state.Pid {
		t.Fatalf("RetrieveRoutingResult pid = %d, want %d", result.Pid, state.Pid)
	}
}

func TestRetrieveRoutingResultFallsBackToRoutingHandoffMap(t *testing.T) {
	handoffMap := newJanitorTestMap(t, "routing_handoff_map")
	now := monotonicNowNs(t)

	src := common.ConvergeAddrPort(netip.MustParseAddrPort("[2001:db8::10]:12345"))
	dst := common.ConvergeAddrPort(netip.MustParseAddrPort("[2606:4700::1111]:53"))
	key := tuplesKeyFromAddrPorts(src, dst, unix.IPPROTO_UDP)

	entry := newRoutingHandoffEntryForTest(now, bpfRoutingResult{
		Mark:     4242,
		Must:     1,
		Outbound: 23,
		Dscp:     10,
		Pid:      2024,
		Mac:      [6]uint8{1, 2, 3, 4, 5, 6},
		Pname:    [16]uint8{'h', 'a', 'n', 'd', 'o', 'f', 'f', '-', 'n', 'a', 'm', 'e'},
	})

	if err := handoffMap.Update(key, &entry, ebpf.UpdateAny); err != nil {
		t.Fatalf("update routing_handoff_map: %v", err)
	}

	core := &controlPlaneCore{
		bpf: &bpfObjects{bpfMaps: bpfMaps{RoutingHandoffMap: handoffMap}},
	}

	result, err := core.RetrieveRoutingResult(src, dst, unix.IPPROTO_UDP)
	if err != nil {
		t.Fatalf("RetrieveRoutingResult fallback: %v", err)
	}
	if result.Mark != entry.Result.Mark || result.Outbound != entry.Result.Outbound ||
		result.Must != entry.Result.Must || result.Dscp != entry.Result.Dscp {
		t.Fatalf("RetrieveRoutingResult fallback routing fields = %+v, want %+v", result, entry.Result)
	}
	if ProcessName2String(result.Pname[:]) != "handoff-name" {
		t.Fatalf("RetrieveRoutingResult fallback pname = %q, want %q", ProcessName2String(result.Pname[:]), "handoff-name")
	}
	if result.Mac != entry.Result.Mac {
		t.Fatalf("RetrieveRoutingResult fallback mac = %v, want %v", result.Mac, entry.Result.Mac)
	}
	if result.Pid != entry.Result.Pid {
		t.Fatalf("RetrieveRoutingResult fallback pid = %d, want %d", result.Pid, entry.Result.Pid)
	}
}

func TestRetrieveRoutingResultRejectsExpiredRoutingHandoffMapEntry(t *testing.T) {
	handoffMap := newJanitorTestMap(t, "routing_handoff_map")
	now := monotonicNowNs(t)

	src := common.ConvergeAddrPort(netip.MustParseAddrPort("10.0.3.1:42345"))
	dst := common.ConvergeAddrPort(netip.MustParseAddrPort("4.4.4.4:443"))
	key := tuplesKeyFromAddrPorts(src, dst, unix.IPPROTO_TCP)

	entry := newRoutingHandoffEntryForTest(
		staleTimestampNs(now, routingHandoffTimeout+time.Second),
		bpfRoutingResult{Outbound: 9},
	)
	if err := handoffMap.Update(key, &entry, ebpf.UpdateAny); err != nil {
		t.Fatalf("update expired routing_handoff_map: %v", err)
	}

	core := &controlPlaneCore{
		bpf: &bpfObjects{bpfMaps: bpfMaps{RoutingHandoffMap: handoffMap}},
	}

	result, err := core.RetrieveRoutingResult(src, dst, unix.IPPROTO_TCP)
	if !stderrors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("RetrieveRoutingResult expired handoff err = %v, want %v", err, ebpf.ErrKeyNotExist)
	}
	if result != nil {
		t.Fatalf("RetrieveRoutingResult expired handoff = %+v, want nil", result)
	}

	var got bpfRoutingHandoffEntry
	if err := handoffMap.Lookup(key, &got); !stderrors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("routing_handoff_map lookup err = %v, want %v", err, ebpf.ErrKeyNotExist)
	}
}

func TestCleanupRoutingHandoffMapRemovesExpiredEntries(t *testing.T) {
	handoffMap := newJanitorTestMap(t, "routing_handoff_map")
	now := monotonicNowNs(t)

	freshSrc := common.ConvergeAddrPort(netip.MustParseAddrPort("10.0.3.1:42345"))
	freshDst := common.ConvergeAddrPort(netip.MustParseAddrPort("4.4.4.4:443"))
	staleSrc := common.ConvergeAddrPort(netip.MustParseAddrPort("10.0.3.2:42346"))
	staleDst := common.ConvergeAddrPort(netip.MustParseAddrPort("4.4.4.5:443"))
	freshKey := tuplesKeyFromAddrPorts(freshSrc, freshDst, unix.IPPROTO_TCP)
	staleKey := tuplesKeyFromAddrPorts(staleSrc, staleDst, unix.IPPROTO_TCP)

	freshEntry := newRoutingHandoffEntryForTest(now, bpfRoutingResult{Outbound: 7})
	staleEntry := newRoutingHandoffEntryForTest(
		staleTimestampNs(now, routingHandoffTimeout+time.Second),
		bpfRoutingResult{Outbound: 8},
	)

	if err := handoffMap.Update(freshKey, &freshEntry, ebpf.UpdateAny); err != nil {
		t.Fatalf("update fresh routing_handoff_map: %v", err)
	}
	if err := handoffMap.Update(staleKey, &staleEntry, ebpf.UpdateAny); err != nil {
		t.Fatalf("update stale routing_handoff_map: %v", err)
	}

	plane := &ControlPlane{
		log: logrus.New(),
		core: &controlPlaneCore{
			bpf: &bpfObjects{bpfMaps: bpfMaps{RoutingHandoffMap: handoffMap}},
		},
		connStateJanitorStop: make(chan struct{}),
	}

	plane.cleanupRoutingHandoffMap()

	var gotFresh bpfRoutingHandoffEntry
	if err := handoffMap.Lookup(freshKey, &gotFresh); err != nil {
		t.Fatalf("fresh routing_handoff_map lookup failed: %v", err)
	}
	var gotStale bpfRoutingHandoffEntry
	if err := handoffMap.Lookup(staleKey, &gotStale); !stderrors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("stale routing_handoff_map lookup err = %v, want %v", err, ebpf.ErrKeyNotExist)
	}
}

func TestRunReloadRetirementCleanupRemovesOnlyEntriesUntouchedSinceCutover(t *testing.T) {
	now := monotonicNowNs(t)
	cutoff := now - uint64((2 * time.Second).Nanoseconds())
	staleNs := cutoff - 1
	freshNs := cutoff + 1

	redirectMap := newJanitorTestMap(t, "redirect_track")
	cookieMap := newJanitorTestMap(t, "cookie_pid_map")
	udpMap := newJanitorTestMap(t, "udp_conn_state_map")
	tcpMap := newJanitorTestMap(t, "tcp_conn_state_map")
	handoffMap := newJanitorTestMap(t, "routing_handoff_map")

	staleRedirectKey := redirectTupleFromAddrs(netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("10.0.0.1"))
	freshRedirectKey := redirectTupleFromAddrs(netip.MustParseAddr("1.1.1.2"), netip.MustParseAddr("10.0.0.2"))
	staleRedirect := bpfRedirectEntry{Ifindex: 7, FromWan: 1, LastSeenNs: staleNs}
	freshRedirect := bpfRedirectEntry{Ifindex: 8, FromWan: 1, LastSeenNs: freshNs}
	if err := redirectMap.Update(staleRedirectKey, &staleRedirect, ebpf.UpdateAny); err != nil {
		t.Fatalf("update stale redirect_track: %v", err)
	}
	if err := redirectMap.Update(freshRedirectKey, &freshRedirect, ebpf.UpdateAny); err != nil {
		t.Fatalf("update fresh redirect_track: %v", err)
	}

	staleCookieKey := uint64(101)
	freshCookieKey := uint64(202)
	staleCookie := bpfPidPname{LastSeenNs: staleNs, Pid: 1234}
	freshCookie := bpfPidPname{LastSeenNs: freshNs, Pid: 5678}
	if err := cookieMap.Update(staleCookieKey, &staleCookie, ebpf.UpdateAny); err != nil {
		t.Fatalf("update stale cookie_pid_map: %v", err)
	}
	if err := cookieMap.Update(freshCookieKey, &freshCookie, ebpf.UpdateAny); err != nil {
		t.Fatalf("update fresh cookie_pid_map: %v", err)
	}

	staleUDPKey := tuplesKeyFromAddrPorts(
		netip.MustParseAddrPort("10.0.1.1:12345"),
		netip.MustParseAddrPort("9.9.9.9:443"),
		unix.IPPROTO_UDP,
	)
	freshUDPKey := tuplesKeyFromAddrPorts(
		netip.MustParseAddrPort("10.0.1.2:12346"),
		netip.MustParseAddrPort("9.9.9.9:443"),
		unix.IPPROTO_UDP,
	)
	staleUDP := bpfUdpConnState{LastSeenNs: staleNs}
	staleUDP.Meta.Data.HasRouting = 1
	staleUDP.Meta.Data.Outbound = 3
	freshUDP := bpfUdpConnState{LastSeenNs: freshNs}
	freshUDP.Meta.Data.HasRouting = 1
	freshUDP.Meta.Data.Outbound = 4
	if err := udpMap.Update(staleUDPKey, &staleUDP, ebpf.UpdateAny); err != nil {
		t.Fatalf("update stale udp_conn_state_map: %v", err)
	}
	if err := udpMap.Update(freshUDPKey, &freshUDP, ebpf.UpdateAny); err != nil {
		t.Fatalf("update fresh udp_conn_state_map: %v", err)
	}

	staleTCPKey := tuplesKeyFromAddrPorts(
		netip.MustParseAddrPort("10.0.2.1:22345"),
		netip.MustParseAddrPort("8.8.8.8:443"),
		unix.IPPROTO_TCP,
	)
	freshTCPKey := tuplesKeyFromAddrPorts(
		netip.MustParseAddrPort("10.0.2.2:22346"),
		netip.MustParseAddrPort("8.8.8.8:443"),
		unix.IPPROTO_TCP,
	)
	staleTCP := bpfTcpConnState{LastSeenNs: staleNs}
	staleTCP.Meta.Data.HasRouting = 1
	staleTCP.Meta.Data.Outbound = 5
	freshTCP := bpfTcpConnState{LastSeenNs: freshNs}
	freshTCP.Meta.Data.HasRouting = 1
	freshTCP.Meta.Data.Outbound = 6
	if err := tcpMap.Update(staleTCPKey, &staleTCP, ebpf.UpdateAny); err != nil {
		t.Fatalf("update stale tcp_conn_state_map: %v", err)
	}
	if err := tcpMap.Update(freshTCPKey, &freshTCP, ebpf.UpdateAny); err != nil {
		t.Fatalf("update fresh tcp_conn_state_map: %v", err)
	}

	staleHandoffKey := tuplesKeyFromAddrPorts(
		netip.MustParseAddrPort("10.0.3.1:32345"),
		netip.MustParseAddrPort("4.4.4.4:443"),
		unix.IPPROTO_TCP,
	)
	freshHandoffKey := tuplesKeyFromAddrPorts(
		netip.MustParseAddrPort("10.0.3.2:32346"),
		netip.MustParseAddrPort("4.4.4.5:443"),
		unix.IPPROTO_TCP,
	)
	staleHandoff := newRoutingHandoffEntryForTest(staleNs, bpfRoutingResult{Outbound: 7})
	freshHandoff := newRoutingHandoffEntryForTest(freshNs, bpfRoutingResult{Outbound: 8})
	if err := handoffMap.Update(staleHandoffKey, &staleHandoff, ebpf.UpdateAny); err != nil {
		t.Fatalf("update stale routing_handoff_map: %v", err)
	}
	if err := handoffMap.Update(freshHandoffKey, &freshHandoff, ebpf.UpdateAny); err != nil {
		t.Fatalf("update fresh routing_handoff_map: %v", err)
	}

	plane := &ControlPlane{
		log: logrus.New(),
		core: &controlPlaneCore{
			bpf: &bpfObjects{bpfMaps: bpfMaps{
				RedirectTrack:     redirectMap,
				CookiePidMap:      cookieMap,
				UdpConnStateMap:   udpMap,
				TcpConnStateMap:   tcpMap,
				RoutingHandoffMap: handoffMap,
			}},
		},
		connStateJanitorStop: make(chan struct{}),
	}

	plane.RunReloadRetirementCleanup(cutoff)

	var gotRedirect bpfRedirectEntry
	if err := redirectMap.Lookup(staleRedirectKey, &gotRedirect); !stderrors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("stale redirect_track lookup err = %v, want %v", err, ebpf.ErrKeyNotExist)
	}
	if err := redirectMap.Lookup(freshRedirectKey, &gotRedirect); err != nil {
		t.Fatalf("fresh redirect_track lookup failed: %v", err)
	}

	var gotCookie bpfPidPname
	if err := cookieMap.Lookup(staleCookieKey, &gotCookie); !stderrors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("stale cookie_pid_map lookup err = %v, want %v", err, ebpf.ErrKeyNotExist)
	}
	if err := cookieMap.Lookup(freshCookieKey, &gotCookie); err != nil {
		t.Fatalf("fresh cookie_pid_map lookup failed: %v", err)
	}

	var gotUDP bpfUdpConnState
	if err := udpMap.Lookup(staleUDPKey, &gotUDP); !stderrors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("stale udp_conn_state_map lookup err = %v, want %v", err, ebpf.ErrKeyNotExist)
	}
	if err := udpMap.Lookup(freshUDPKey, &gotUDP); err != nil {
		t.Fatalf("fresh udp_conn_state_map lookup failed: %v", err)
	}

	var gotTCP bpfTcpConnState
	if err := tcpMap.Lookup(staleTCPKey, &gotTCP); !stderrors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("stale tcp_conn_state_map lookup err = %v, want %v", err, ebpf.ErrKeyNotExist)
	}
	if err := tcpMap.Lookup(freshTCPKey, &gotTCP); err != nil {
		t.Fatalf("fresh tcp_conn_state_map lookup failed: %v", err)
	}

	var gotHandoff bpfRoutingHandoffEntry
	if err := handoffMap.Lookup(staleHandoffKey, &gotHandoff); !stderrors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("stale routing_handoff_map lookup err = %v, want %v", err, ebpf.ErrKeyNotExist)
	}
	if err := handoffMap.Lookup(freshHandoffKey, &gotHandoff); err != nil {
		t.Fatalf("fresh routing_handoff_map lookup failed: %v", err)
	}
}

func newJanitorTestMap(t *testing.T, mapName string) *ebpf.Map {
	t.Helper()

	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock failed: %v", err)
	}

	spec, err := loadBpf()
	if err != nil {
		if strings.Contains(err.Error(), "stub build") {
			t.Skipf("loadBpf: %v", err)
		}
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

func newRoutingHandoffEntryForTest(lastSeenNs uint64, result bpfRoutingResult) bpfRoutingHandoffEntry {
	var entry bpfRoutingHandoffEntry
	entry.LastSeenNs = lastSeenNs
	entry.Result.Mark = result.Mark
	entry.Result.Must = result.Must
	entry.Result.Mac = result.Mac
	entry.Result.Outbound = result.Outbound
	entry.Result.Pname = result.Pname
	entry.Result.Pid = result.Pid
	entry.Result.Dscp = result.Dscp
	return entry
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
