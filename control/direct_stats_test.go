/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"errors"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common/consts"
	internal "github.com/daeuniverse/dae/pkg/ebpf_internal"
	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/vishvananda/netlink"
)

func readDirectStatsSource(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("kern/direct_stats.c")
	if err != nil {
		t.Fatalf("read observer source: %v", err)
	}
	return string(raw)
}

// TestDirectStatsObserverIsReadOnly pins the observer contract: it may read
// conn_state_map but must never write or delete it, so counting cannot change
// datapath verdicts or flow lifetimes. It must also stay a pass-through hook:
// no mark writes and no terminal verdict.
func TestDirectStatsObserverIsReadOnly(t *testing.T) {
	source := readDirectStatsSource(t)
	for _, forbidden := range []string{
		"bpf_map_update_elem(&conn_state_map",
		"bpf_map_delete_elem(&conn_state_map",
		"skb->mark",
		"TC_ACT_SHOT",
		"TC_ACT_OK",
	} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("observer contains %q; it must stay read-only and non-terminal", forbidden)
		}
	}
	if !strings.Contains(source, "bpf_map_lookup_elem(&conn_state_map") {
		t.Fatal("observer must read conn_state_map to decide direct passthrough")
	}
	if !strings.Contains(source, "#define DIRECT_STATS_CONTINUE TC_ACT_UNSPEC") {
		t.Fatal("observer must continue the TC chain so it cannot alter a verdict")
	}
}

// TestDirectStatsKeysParityWithKernelSource pins the direct_stats_map key
// domain: every counter Go reads must exist in enum direct_stats_key with the
// same number, and the terminal entry must be the ARRAY capacity.
func TestDirectStatsKeysParityWithKernelSource(t *testing.T) {
	source := readDirectStatsSource(t)
	enum := regexp.MustCompile(`(?s)enum direct_stats_key \{(.*?)\};`).FindStringSubmatch(source)
	if enum == nil {
		t.Fatal("enum direct_stats_key not found in kern/direct_stats.c")
	}
	cKeys := map[string]uint32{}
	for _, match := range regexp.MustCompile(`(?m)^\s*([A-Z_]+)\s*=\s*(\d+),`).FindAllStringSubmatch(enum[1], -1) {
		value, err := strconv.ParseUint(match[2], 10, 32)
		if err != nil {
			t.Fatalf("parse enum entry %s: %v", match[0], err)
		}
		cKeys[match[1]] = uint32(value)
	}
	contract := []struct {
		cName string
		goKey uint32
	}{
		{"DIRECT_STATS_UPLOAD", directStatsKeyUp},
		{"DIRECT_STATS_DOWNLOAD", directStatsKeyDown},
	}
	for _, entry := range contract {
		value, ok := cKeys[entry.cName]
		if !ok {
			t.Errorf("enum direct_stats_key has no %s entry", entry.cName)
			continue
		}
		if value != entry.goKey {
			t.Errorf("direct_stats_map key %s = %d in C but %d in Go", entry.cName, value, entry.goKey)
		}
	}
	if got := cKeys["DIRECT_STATS_KEY_NUM"]; got != uint32(len(contract)) {
		t.Errorf("DIRECT_STATS_KEY_NUM = %d in C but %d keys are covered here", got, len(contract))
	}
	if !strings.Contains(source, "__uint(max_entries, DIRECT_STATS_KEY_NUM)") {
		t.Error("direct_stats_map must size itself from DIRECT_STATS_KEY_NUM")
	}
}

// TestDirectStatsPriorityRunsBeforeTproxy pins the ordering requirement: TCX
// runs smaller priorities first, and tproxy returns a terminal verdict on a
// direct pass-through, so the observer must win the race to the packet.
func TestDirectStatsPriorityRunsBeforeTproxy(t *testing.T) {
	if directStatsPriority != 1 {
		t.Fatalf("directStatsPriority = %d; the observer must own the lowest priority", directStatsPriority)
	}
	for _, want := range []string{"dualPriority = 2", "ingressPriority = 2", "egressPriority = 2"} {
		if !strings.Contains(mustReadBindSource(t), want) {
			t.Errorf("bind source does not set %q; tproxy must yield to the observer when it is on", want)
		}
	}
}

func mustReadBindSource(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("control_plane_core_bind.go")
	if err != nil {
		t.Fatalf("read bind source: %v", err)
	}
	return string(raw)
}

func TestDirectStatsProgramNamesFollowRole(t *testing.T) {
	cases := []struct {
		layer2, wan, dual bool
		ingress, egress   string
	}{
		{false, false, false, "direct_stats_lan_ingress_l3", "direct_stats_lan_egress_l3"},
		{true, false, false, "direct_stats_lan_ingress_l2", "direct_stats_lan_egress_l2"},
		{false, true, false, "direct_stats_wan_ingress_l3", "direct_stats_egress_l3"},
		{true, true, false, "direct_stats_wan_ingress_l2", "direct_stats_egress_l2"},
		{false, false, true, "direct_stats_ingress_l3", "direct_stats_egress_l3"},
		{true, true, true, "direct_stats_ingress_l2", "direct_stats_egress_l2"},
	}
	spec, err := loadDirectstats()
	for _, tc := range cases {
		ingress, egress := directStatsProgramNames(tc.layer2, tc.wan, tc.dual)
		if ingress != tc.ingress || egress != tc.egress {
			t.Errorf("names(l2=%v wan=%v dual=%v) = %s,%s; want %s,%s", tc.layer2, tc.wan, tc.dual, ingress, egress, tc.ingress, tc.egress)
		}
		if err == nil && (spec.Programs[ingress] == nil || spec.Programs[egress] == nil) {
			t.Errorf("object has no program %s or %s", ingress, egress)
		}
	}
}

// TestDirectStatsRoleVariantsSkipUnusedLookups pins the specialisation: the
// role is a literal at each entry point, and each direction's lookup is gated
// on it, so a LAN-only or WAN-only hook does not run the other side's lookups.
func TestDirectStatsRoleVariantsSkipUnusedLookups(t *testing.T) {
	source := readDirectStatsSource(t)
	for _, want := range []string{
		"role != DIRECT_STATS_ROLE_LAN",
		"role != DIRECT_STATS_ROLE_WAN",
		"direct_stats_ingress(skb, 0, DIRECT_STATS_ROLE_LAN)",
		"direct_stats_ingress(skb, 0, DIRECT_STATS_ROLE_WAN)",
		"direct_stats_ingress(skb, 14, DIRECT_STATS_ROLE_BOTH)",
		"direct_stats_lan_egress(skb, 0)",
		"direct_stats_lan_egress(skb, 14)",
		"direct_stats_has_local_socket(skb, &key)",
	} {
		if !strings.Contains(source, want) {
			t.Errorf("observer source lacks %q", want)
		}
	}
}

// The observer's map is per generation; the retired accumulator is what keeps
// the reported totals (and counter_since) process-wide across reloads.
func TestRetiredDirectStatsAccumulatesAcrossGenerations(t *testing.T) {
	directStatsTotals.mu.Lock()
	directStatsTotals.retired = DirectStatsCounters{}
	directStatsTotals.mu.Unlock()
	t.Cleanup(func() {
		directStatsTotals.mu.Lock()
		directStatsTotals.retired = DirectStatsCounters{}
		directStatsTotals.mu.Unlock()
	})

	accumulateDirectStats(DirectStatsCounters{UpBytes: 10, UpPackets: 1})
	accumulateDirectStats(DirectStatsCounters{DownBytes: 5, DownPackets: 2})

	got := retiredDirectStats()
	want := DirectStatsCounters{UpBytes: 10, UpPackets: 1, DownBytes: 5, DownPackets: 2}
	if got != want {
		t.Fatalf("retired totals = %+v, want %+v", got, want)
	}
}

func TestResolveDirectStatsFallsBackToClassicWithoutTCX(t *testing.T) {
	previous := directStatsKernelVersion
	t.Cleanup(func() { directStatsKernelVersion = previous })

	directStatsKernelVersion = func() (internal.Version, error) { return internal.Version{6, 5, 0}, nil }
	if !ResolveDirectStats(nil, true) {
		t.Fatal("observer refused on a kernel that only lacks TCX")
	}
	directStatsKernelVersion = func() (internal.Version, error) { return internal.Version{}, errors.New("unknown") }
	if !ResolveDirectStats(nil, true) {
		t.Fatal("observer refused when the kernel version is unknown")
	}
	directStatsKernelVersion = func() (internal.Version, error) { return internal.Version{6, 6, 0}, nil }
	if !ResolveDirectStats(nil, true) {
		t.Fatal("observer refused on a TCX kernel")
	}
	if ResolveDirectStats(nil, false) {
		t.Fatal("observer enabled without being requested")
	}
}

func TestResolveDirectStatsWarnsOnClassicFallback(t *testing.T) {
	previous := directStatsKernelVersion
	t.Cleanup(func() { directStatsKernelVersion = previous })
	directStatsKernelVersion = func() (internal.Version, error) { return internal.Version{5, 15, 0}, nil }

	logger, hook := logrustest.NewNullLogger()
	if !ResolveDirectStats(logger, true) {
		t.Fatal("observer refused on 5.15; classic TC is still available")
	}
	if len(hook.AllEntries()) != 1 || hook.LastEntry().Level != logrus.WarnLevel {
		t.Fatalf("want one warning, got %v", hook.AllEntries())
	}
}

// A reply without a conn_state match cannot safely be attributed to a LAN host
// through a remote/local-port fallback key. NAT downloads are counted on the
// LAN egress hook after DNAT instead.
func TestDirectStatsOmitsUnattributableNATReplies(t *testing.T) {
	source := readDirectStatsSource(t)
	for _, absent := range []string{"direct_reverse_map", "direct_stats_known", "direct_stats_remember"} {
		if strings.Contains(source, absent) {
			t.Errorf("observer still uses %q for NAT reply attribution", absent)
		}
	}
	if !strings.Contains(source, "if (st->meta.data.has_routing)") {
		t.Fatal("a conn_state entry with routing metadata must not be counted as direct")
	}
	if !strings.Contains(source, "direct_stats_lan_egress") {
		t.Fatal("NAT downloads must be accounted on the LAN egress hook")
	}
	if !strings.Contains(source, "direct_stats_has_local_socket") {
		t.Fatal("WAN ingress must distinguish local delivery from forwarded replies")
	}
}

// Retiring an observer that is not live must not touch the totals, so the
// replace path and the deferred close can both retire the same observer.
func TestRetireDirectStatsObserverIsIdempotent(t *testing.T) {
	directStatsTotals.mu.Lock()
	directStatsTotals.retired = DirectStatsCounters{UpBytes: 7}
	directStatsTotals.mu.Unlock()
	t.Cleanup(func() {
		directStatsTotals.mu.Lock()
		directStatsTotals.retired = DirectStatsCounters{}
		directStatsTotals.mu.Unlock()
	})

	retireDirectStatsObserver(&directStatsObserver{})
	if got := retiredDirectStats().UpBytes; got != 7 {
		t.Fatalf("retired = %d, want 7", got)
	}
}

func TestDirectStatsStatusReportsRecordedError(t *testing.T) {
	core := &controlPlaneCore{}
	core.recordDirectStatsError(errors.New("observer load failed"))
	plane := &ControlPlane{core: core}

	status := plane.DirectStatsStatus()
	if status.Attached || status.Hooks != 0 {
		t.Fatalf("status = %+v, want no attached hooks", status)
	}
	if status.LastError != "observer load failed" {
		t.Fatalf("last error = %q", status.LastError)
	}
}

func TestDirectStatsSnapshotSkipsUnreadableObserver(t *testing.T) {
	directStatsTotals.mu.Lock()
	directStatsTotals.retired = DirectStatsCounters{UpBytes: 5}
	directStatsTotals.live = map[*directStatsObserver]struct{}{}
	directStatsTotals.mu.Unlock()
	t.Cleanup(func() {
		directStatsTotals.mu.Lock()
		directStatsTotals.retired = DirectStatsCounters{}
		directStatsTotals.live = nil
		directStatsTotals.mu.Unlock()
	})

	// A collection without direct_stats_map models a generation whose map
	// disappeared while it was still being drained.
	observer := &directStatsObserver{coll: &ebpf.Collection{}}
	registerDirectStatsObserver(observer)
	plane := &ControlPlane{core: &controlPlaneCore{}}
	got, err := plane.DirectStatsSnapshot()
	if err == nil {
		t.Fatal("snapshot did not report the unreadable observer")
	}
	if got.UpBytes != 5 {
		t.Fatalf("snapshot discarded readable retired counters: %+v", got)
	}
}

func TestStageDirectStatsFailureIsBestEffort(t *testing.T) {
	core := &controlPlaneCore{log: logrus.New()}
	link := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{
		Index: 7, Name: "eth0", EncapType: "ether",
	}}
	// No bpf object is available, so the collection load fails. An optional
	// observer must not turn that into a bind error.
	if err := core.stageDirectStatsHookForLink(link, false, false, false, true, true); err != nil {
		t.Fatalf("stageDirectStatsHookForLink returned %v", err)
	}
	if core.directStatsLastError() == "" {
		t.Fatal("load failure was not recorded in the status")
	}
}

// The observer program name carries the interface role, so the fallback staged
// on an empty bridge is direct_stats_lan_ingress_* or direct_stats_wan_ingress_*,
// not only direct_stats_ingress_*. Removing just the bare prefix left the master
// hook counting the same bytes as the first member port.
func TestDirectStatsMasterRemovalCoversRoleSpecificNames(t *testing.T) {
	for _, tc := range []struct {
		direction string
		names     []string
	}{
		{"ingress", []string{
			consts.AppName + "_direct_stats_ingress_l3",
			consts.AppName + "_direct_stats_lan_ingress_l3",
			consts.AppName + "_direct_stats_wan_ingress_l3",
		}},
		// A WAN bridge keeps its master egress hook, and the WAN program name
		// has no role segment; only the bare and LAN-egress names are removed.
		{"egress", []string{
			consts.AppName + "_direct_stats_egress_l3",
			consts.AppName + "_direct_stats_lan_egress_l3",
		}},
	} {
		for _, name := range tc.names {
			backend := &fakeTCHookBackend{}
			set := newTCHookSetWithBackend(logrus.New(), backend.moduleBackend())
			program := new(ebpf.Program)
			if err := set.beginReplace(); err != nil {
				t.Fatal(err)
			}
			if err := set.stage(namedTCHookSpec(1, name, program)); err != nil {
				t.Fatal(err)
			}
			if err := set.stage(namedTCHookSpec(2, consts.AppName+"_lan_ingress_l3", new(ebpf.Program))); err != nil {
				t.Fatal(err)
			}
			if err := set.commit(); err != nil {
				t.Fatal(err)
			}
			set.finalize()

			core := &controlPlaneCore{tcHooks: set}
			if err := core.removeDirectStatsHooksOnInterface(7, tc.direction); err != nil {
				t.Fatal(err)
			}
			if got := set.countHooksWithPrefix(consts.AppName + "_direct_stats_"); got != 0 {
				t.Errorf("direction %s left %d direct-stats hooks for %q", tc.direction, got, name)
			}
			if got := set.countHooksWithPrefix(consts.AppName + "_lan_ingress_"); got != 1 {
				t.Errorf("direction %s removed the tproxy hook", tc.direction)
			}
		}
	}
}
