/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"net/netip"
	"strconv"
	"testing"
	"time"

	ob "github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

func TestSnapshotConfiguredRules(t *testing.T) {
	rules, fallback := snapshotConfiguredRules([]*config_parser.RoutingRule{{
		AndFunctions: []*config_parser.Function{{
			Name:   "pname",
			Params: []*config_parser.Param{{Val: "curl"}},
		}},
		Outbound: config_parser.Function{Name: "proxy"},
	}}, "direct")
	if len(rules) != 1 {
		t.Fatalf("rules = %d, want 1", len(rules))
	}
	if rules[0].Expression != "pname(curl) -> proxy" || rules[0].Outbound != "proxy" {
		t.Fatalf("rule = %#v", rules[0])
	}
	if fallback != "direct" {
		t.Fatalf("fallback = %q", fallback)
	}
}

func TestFlowHistoryRetentionAndLookup(t *testing.T) {
	manager := NewSessionManager(context.Background())
	now := time.Now()
	manager.appendFlowHistory(SessionFlowSnapshot{ID: "old", Network: "tcp"}, now.Add(-time.Hour))
	manager.appendFlowHistory(SessionFlowSnapshot{ID: "new", Network: "udp"}, now)

	entries, _ := manager.FlowHistorySnapshots()
	if len(entries) != 1 || entries[0].ID != "new" {
		t.Fatalf("entries = %#v, want only the fresh flow", entries)
	}
	if entry, ok := manager.FlowHistoryEntryByID("new"); !ok || entry.ID != "new" {
		t.Fatalf("lookup = %#v %v", entry, ok)
	}
	if _, ok := manager.FlowHistoryEntryByID("old"); ok {
		t.Fatal("expired flow must not be retained")
	}
}

func TestTCPSnapshotCarriesRouteMetadata(t *testing.T) {
	src := netip.MustParseAddrPort("192.168.1.2:1234")
	dst := netip.MustParseAddrPort("1.1.1.1:443")
	startedAt := time.Now()
	group := &ob.DialerGroup{Name: "proxy"}
	flow := &FlowRuntime{
		network:   "tcp",
		src:       src,
		dst:       dst,
		startedAt: startedAt,
		binding: TcpFlowBinding{Egress: TcpEgressBinding{
			Outbound:      group,
			SniffedDomain: "example.com",
		}},
	}
	flow.uploadBytes.Add(10)
	flow.downloadBytes.Add(20)
	snapshot := flow.snapshot()
	if want := flowIDOf("tcp", src, dst, startedAt); snapshot.ID != want {
		t.Fatalf("snapshot id = %q, want %q", snapshot.ID, want)
	}
	if snapshot.Network != "tcp" || snapshot.Domain != "example.com" {
		t.Fatalf("snapshot = %#v", snapshot)
	}
	if snapshot.Outbound != "proxy" || !snapshot.HasBytes || snapshot.UploadBytes != 10 || snapshot.DownloadBytes != 20 {
		t.Fatalf("snapshot counters = %#v", snapshot)
	}
	if snapshot.Src != src || snapshot.Dst != dst {
		t.Fatalf("snapshot endpoints = %#v", snapshot)
	}
}

// TestFlowByteCountersWalk pins the cheap counter walk a windowed listing uses:
// TCP flows report their live counters without materialising full snapshots,
// and UDP flows, which carry no counters, are absent.
func TestFlowByteCountersWalk(t *testing.T) {
	manager := NewSessionManager(context.Background())
	flow := &FlowRuntime{network: "tcp", startedAt: time.Now()}
	flow.uploadBytes.Add(10)
	flow.downloadBytes.Add(20)
	manager.flows.Store(struct{}{}, flow)
	manager.udpFlows.Store(struct{}{}, &UDPFlowRuntime{startedAt: time.Now()})

	var counters []FlowByteCounter
	manager.FlowByteCounters(func(counter FlowByteCounter) { counters = append(counters, counter) })
	if len(counters) != 1 {
		t.Fatalf("counters = %#v, want only the TCP flow", counters)
	}
	if counters[0].ID != flow.flowID() || counters[0].UploadBytes != 10 || counters[0].DownloadBytes != 20 {
		t.Fatalf("counter = %#v", counters[0])
	}
}

func TestActiveFlowSnapshotsIncludeUDP(t *testing.T) {
	manager := NewSessionManager(context.Background())
	flow := &UDPFlowRuntime{
		src:       netip.MustParseAddrPort("192.168.1.2:5353"),
		dst:       netip.MustParseAddrPort("8.8.8.8:53"),
		startedAt: time.Now(),
		binding:   UdpFlowBinding{Route: UdpRouteBinding{Mark: 7}},
	}
	manager.udpFlows.Store(struct{}{}, flow)
	snapshots := manager.ActiveFlowSnapshots()
	if len(snapshots) != 1 || snapshots[0].ID != flow.flowID() || snapshots[0].Network != "udp" || snapshots[0].Mark != 7 {
		t.Fatalf("snapshots = %#v", snapshots)
	}
}

// TestSnapshotConfiguredRulesKeepsConfiguredForm pins the /rules contract: the
// resource reports the rules as written, not the optimizer-expanded tree that
// turns one geosite line into six figures of suffixes.
func TestSnapshotConfiguredRulesKeepsConfiguredForm(t *testing.T) {
	expanded := make([]*config_parser.Param, 0, 2000)
	for i := range 2000 {
		expanded = append(expanded, &config_parser.Param{Key: "suffix", Val: "d" + strconv.Itoa(i) + ".example.com"})
	}
	configured := []*config_parser.RoutingRule{{
		AndFunctions: []*config_parser.Function{{
			Name:   "domain",
			Params: []*config_parser.Param{{Key: "geosite", Val: "category-ads-all"}},
		}},
		Outbound: config_parser.Function{Name: "block"},
	}}

	rules, _ := snapshotConfiguredRules(configured, "proxy")
	if len(rules) != 1 {
		t.Fatalf("rules = %d, want 1", len(rules))
	}
	if got := rules[0].Expression; got != "domain(geosite: category-ads-all) -> block" {
		t.Fatalf("expression = %q, want the configured form", got)
	}
	if rules[0].Outbound != "block" {
		t.Fatalf("outbound = %q", rules[0].Outbound)
	}

	// The same rule after expansion must never be what the API exports.
	expandedRule := []*config_parser.RoutingRule{{
		AndFunctions: []*config_parser.Function{{Name: "domain", Params: expanded}},
		Outbound:     config_parser.Function{Name: "block"},
	}}
	expandedRules, _ := snapshotConfiguredRules(expandedRule, "proxy")
	if len(expandedRules[0].Expression) < 10000 {
		t.Fatalf("expanded expression = %d bytes, expected the fixture to be large", len(expandedRules[0].Expression))
	}
}
