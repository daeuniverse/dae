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
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

// reloadRetirementCleanupFixture wires a minimal ControlPlane whose BPF handle
// owns real (unpinned) janitor-test maps plus a session manager for pinning.
type reloadRetirementCleanupFixture struct {
	plane         *ControlPlane
	manager       *SessionManager
	connState     *ebpf.Map
	redirectTrack *ebpf.Map
	cookiePID     *ebpf.Map
	handoff       *ebpf.Map
}

func newReloadRetirementCleanupFixture(t *testing.T) *reloadRetirementCleanupFixture {
	t.Helper()

	f := &reloadRetirementCleanupFixture{
		connState:     newJanitorTestMap(t, "conn_state_map"),
		redirectTrack: newJanitorTestMap(t, "redirect_track"),
		cookiePID:     newJanitorTestMap(t, "cookie_pid_map"),
		handoff:       newJanitorTestMap(t, "routing_handoff_map"),
	}
	f.manager = NewSessionManager(context.Background())
	t.Cleanup(func() { _ = f.manager.Close() })

	f.plane = &ControlPlane{
		log:            logrus.New(),
		sessionManager: f.manager,
		core:           &controlPlaneCore{},
	}
	f.plane.core.bpf.Store(&bpfObjects{bpfMaps: bpfMaps{
		ConnStateMap:      f.connState,
		RedirectTrack:     f.redirectTrack,
		CookiePidMap:      f.cookiePID,
		RoutingHandoffMap: f.handoff,
	}})
	return f
}

func connStateExists(m *ebpf.Map, key bpfTuplesKey) bool {
	var got bpfConnState
	err := m.Lookup(&key, &got)
	return !stderrors.Is(err, ebpf.ErrKeyNotExist)
}

func redirectTrackExists(m *ebpf.Map, key bpfRedirectTuple) bool {
	var got bpfRedirectEntry
	err := m.Lookup(&key, &got)
	return !stderrors.Is(err, ebpf.ErrKeyNotExist)
}

// TestRunReloadRetirementCleanupForwardsStaleThreshold verifies the retirement
// cleanup forwards the reload-request monotonic timestamp to all four map
// cleanups: entries idle since before the request (and below every TTL) are
// purged immediately, entries refreshed after the request survive, and
// pinned adopted-but-idle entries are exempt in both the conn-state and
// redirect-track maps.
func TestRunReloadRetirementCleanupForwardsStaleThreshold(t *testing.T) {
	f := newReloadRetirementCleanupFixture(t)

	nowNs, err := monotonicNowNano()
	if err != nil {
		t.Fatalf("monotonicNowNano: %v", err)
	}
	// staleNs is 8s old: below the aggressive conn-state TTL (2.5min), the
	// redirect/cookie TTL (5min), and the handoff TTL (10s), so deletion can
	// only be attributed to the forwarded stale threshold.
	staleNs := nowNs - 8_000_000_000
	freshNs := nowNs - 1_000_000_000
	threshold := nowNs - 5_000_000_000

	dst := netip.MustParseAddrPort("198.51.100.20:443")
	udpStale := bpfTuplesKeyFromAddrPorts(
		netip.MustParseAddrPort("192.0.2.10:40001"), dst, unix.IPPROTO_UDP)
	udpFresh := bpfTuplesKeyFromAddrPorts(
		netip.MustParseAddrPort("192.0.2.10:40002"), dst, unix.IPPROTO_UDP)
	udpPinned := bpfTuplesKeyFromAddrPorts(
		netip.MustParseAddrPort("192.0.2.10:40003"), dst, unix.IPPROTO_UDP)
	tcpOrphan := bpfTuplesKeyFromAddrPorts(
		netip.MustParseAddrPort("192.0.2.10:40004"), dst, unix.IPPROTO_TCP)
	tcpFresh := bpfTuplesKeyFromAddrPorts(
		netip.MustParseAddrPort("192.0.2.10:40005"), dst, unix.IPPROTO_TCP)

	seedConnState(t, f.connState, udpStale, staleNs, 0)
	seedConnState(t, f.connState, udpFresh, freshNs, 0)
	seedConnState(t, f.connState, udpPinned, staleNs, 0)
	// State 0 = established; established TCP has no TTL in the janitor, so
	// the orphan below can only be retired via the stale threshold.
	seedConnState(t, f.connState, tcpOrphan, staleNs, 0)
	seedConnState(t, f.connState, tcpFresh, freshNs, 0)

	// Redirect-track entries are keyed by the host-pair (ports are dropped in
	// redirectTupleForFlow), so the stale entry needs a distinct source IP to
	// avoid colliding with the pinned one.
	redirectStale := redirectTupleForFlow(bpfTuplesKeyFromAddrPorts(
		netip.MustParseAddrPort("192.0.2.99:40001"), dst, unix.IPPROTO_UDP))
	redirectPinned := redirectTupleForFlow(udpPinned)
	if err := f.redirectTrack.Update(&redirectStale, &bpfRedirectEntry{LastSeenNs: staleNs}, ebpf.UpdateAny); err != nil {
		t.Fatalf("seed redirect stale: %v", err)
	}
	if err := f.redirectTrack.Update(&redirectPinned, &bpfRedirectEntry{LastSeenNs: staleNs}, ebpf.UpdateAny); err != nil {
		t.Fatalf("seed redirect pinned: %v", err)
	}

	cookieStale, cookieFresh := uint64(0x1111), uint64(0x2222)
	if err := f.cookiePID.Update(&cookieStale, &bpfPidPname{LastSeenNs: staleNs}, ebpf.UpdateAny); err != nil {
		t.Fatalf("seed cookie stale: %v", err)
	}
	if err := f.cookiePID.Update(&cookieFresh, &bpfPidPname{LastSeenNs: freshNs}, ebpf.UpdateAny); err != nil {
		t.Fatalf("seed cookie fresh: %v", err)
	}

	if err := f.handoff.Update(&udpStale, &bpfRoutingHandoffEntry{LastSeenNs: staleNs}, ebpf.UpdateAny); err != nil {
		t.Fatalf("seed handoff stale: %v", err)
	}
	if err := f.handoff.Update(&udpFresh, &bpfRoutingHandoffEntry{LastSeenNs: freshNs}, ebpf.UpdateAny); err != nil {
		t.Fatalf("seed handoff fresh: %v", err)
	}

	// The pinned UDP tuple protects both its conn-state entry and, via the
	// derived redirect tuple, its redirect-track entry.
	f.manager.RetainUdpConnStateTuples([]bpfTuplesKey{udpPinned})

	f.plane.RunReloadRetirementCleanup(threshold)

	// Entries that must survive: refreshed-after-request, or pinned.
	for name, exists := range map[string]bool{
		"udp fresh":       connStateExists(f.connState, udpFresh),
		"udp pinned":      connStateExists(f.connState, udpPinned),
		"tcp fresh":       connStateExists(f.connState, tcpFresh),
		"redirect pinned": redirectTrackExists(f.redirectTrack, redirectPinned),
	} {
		if !exists {
			t.Errorf("%s: entry missing after cleanup", name)
		}
	}
	// Entries that must be retired by the forwarded threshold.
	for name, exists := range map[string]bool{
		"udp stale":      connStateExists(f.connState, udpStale),
		"tcp orphan":     connStateExists(f.connState, tcpOrphan),
		"redirect stale": redirectTrackExists(f.redirectTrack, redirectStale),
	} {
		if exists {
			t.Errorf("%s: entry survived stale-threshold cleanup", name)
		}
	}

	var gotPid bpfPidPname
	if err := f.cookiePID.Lookup(&cookieStale, &gotPid); !stderrors.Is(err, ebpf.ErrKeyNotExist) {
		t.Errorf("cookie stale: entry survived stale-threshold cleanup (err=%v)", err)
	}
	if err := f.cookiePID.Lookup(&cookieFresh, &gotPid); err != nil {
		t.Errorf("cookie fresh: entry missing after cleanup: %v", err)
	}

	var gotHandoff bpfRoutingHandoffEntry
	if err := f.handoff.Lookup(&udpStale, &gotHandoff); !stderrors.Is(err, ebpf.ErrKeyNotExist) {
		t.Errorf("handoff stale: entry survived stale-threshold cleanup (err=%v)", err)
	}
	if err := f.handoff.Lookup(&udpFresh, &gotHandoff); err != nil {
		t.Errorf("handoff fresh: entry missing after cleanup: %v", err)
	}
}

// TestRunReloadRetirementCleanupZeroThresholdSkipsCleanup pins the gate: a
// zero timestamp (no reload attribution) must leave TTL-valid entries alone.
func TestRunReloadRetirementCleanupZeroThresholdSkipsCleanup(t *testing.T) {
	f := newReloadRetirementCleanupFixture(t)

	nowNs, err := monotonicNowNano()
	if err != nil {
		t.Fatalf("monotonicNowNano: %v", err)
	}
	key := bpfTuplesKeyFromAddrPorts(
		netip.MustParseAddrPort("192.0.2.11:41001"),
		netip.MustParseAddrPort("198.51.100.21:443"),
		unix.IPPROTO_UDP,
	)
	seedConnState(t, f.connState, key, nowNs-1_000_000_000, 0)

	f.plane.RunReloadRetirementCleanup(0)

	if !connStateExists(f.connState, key) {
		t.Errorf("TTL-valid entry deleted under zero threshold")
	}
}

func seedConnState(t *testing.T, m *ebpf.Map, key bpfTuplesKey, lastSeenNs uint64, state uint8) {
	t.Helper()
	value := bpfConnState{LastSeenNs: lastSeenNs, State: state}
	value.Meta.Data.HasRouting = 1
	if err := m.Update(&key, &value, ebpf.UpdateAny); err != nil {
		t.Fatalf("seed conn state: %v", err)
	}
}
