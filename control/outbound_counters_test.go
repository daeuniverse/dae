/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"testing"

	ob "github.com/daeuniverse/dae/component/outbound"
)

func TestCounterRegistryRetainsByNameAcrossGenerations(t *testing.T) {
	registry := ob.NewCounterRegistry()
	since := registry.Since()
	if since.IsZero() {
		t.Fatal("registry must have a counter_since boundary")
	}

	first := &ControlPlane{}
	first.outbounds = []*ob.DialerGroup{{Name: "direct"}, {Name: "block"}, {Name: "proxy"}}
	first.attachOutboundCounters(registry)

	first.outboundCountersForIndex(2).ConnectionEstablished()
	first.outboundCountersForIndex(2).AddUpload(100)
	first.outboundCountersForIndex(2).AddDownload(200)

	// A reload builds a fresh plane with the same group names; the counters
	// must continue from where the previous generation left them.
	second := &ControlPlane{}
	second.outbounds = []*ob.DialerGroup{{Name: "direct"}, {Name: "block"}, {Name: "proxy"}}
	second.attachOutboundCounters(registry)
	if second.outboundCountersForIndex(2) != first.outboundCountersForIndex(2) {
		t.Fatal("same group name must reuse the same counter pointer")
	}
	second.outboundCountersForIndex(2).ConnectionEstablished()

	snapshot := second.SnapshotOutboundCounters()
	if !snapshot.CounterSince.Equal(since) {
		t.Fatalf("counter_since = %v, want %v", snapshot.CounterSince, since)
	}
	if len(snapshot.Outbounds) != 3 {
		t.Fatalf("outbounds = %d, want 3", len(snapshot.Outbounds))
	}
	if snapshot.Outbounds[0].Kind != "builtin" || snapshot.Outbounds[2].Kind != "group" {
		t.Fatalf("kinds = %q, %q", snapshot.Outbounds[0].Kind, snapshot.Outbounds[2].Kind)
	}
	proxy := snapshot.Outbounds[2]
	if proxy.ActiveConnections != 2 || proxy.TotalConnections != 2 {
		t.Fatalf("proxy connections = active %d total %d, want 2/2", proxy.ActiveConnections, proxy.TotalConnections)
	}
	if proxy.UploadBytes != 100 || proxy.DownloadBytes != 200 {
		t.Fatalf("proxy bytes = %d/%d", proxy.UploadBytes, proxy.DownloadBytes)
	}

	// Finishing a flow decrements only the active gauge.
	second.outboundCountersForIndex(2).ConnectionFinished()
	if got := second.SnapshotOutboundCounters().Outbounds[2].ActiveConnections; got != 1 {
		t.Fatalf("active after finish = %d, want 1", got)
	}
	if got := second.SnapshotOutboundCounters().Outbounds[2].TotalConnections; got != 2 {
		t.Fatalf("total after finish = %d, want 2", got)
	}
}

func TestTrafficRecordersForAttributeToOutbound(t *testing.T) {
	plane := &ControlPlane{runtimeStats: newRuntimeStats()}
	counters := &ob.Counters{}
	download, upload := plane.trafficRecordersFor(counters)

	upload(10)
	download(20)

	if got := counters.UploadBytes(); got != 10 {
		t.Fatalf("upload = %d, want 10", got)
	}
	if got := counters.DownloadBytes(); got != 20 {
		t.Fatalf("download = %d, want 20", got)
	}
	if got := plane.runtimeStats.uploadTotal.Load(); got != 10 {
		t.Fatalf("global upload total = %d, want 10", got)
	}
	if got := plane.runtimeStats.downloadTotal.Load(); got != 20 {
		t.Fatalf("global download total = %d, want 20", got)
	}

	// Non-positive writes are no-ops, matching RecordUploadTraffic.
	upload(0)
	upload(-1)
	if got := counters.UploadBytes(); got != 10 {
		t.Fatalf("upload after no-op = %d, want 10", got)
	}
}

func TestOutboundDialErrorsExcludeBlock(t *testing.T) {
	registry := ob.NewCounterRegistry()
	plane := &ControlPlane{}
	plane.outbounds = []*ob.DialerGroup{{Name: "direct"}, {Name: "block"}, {Name: "proxy"}}
	plane.attachOutboundCounters(registry)

	plane.noteOutboundDialError(&proxyDialResult{OutboundIndex: 1})
	if got := plane.outboundCountersForIndex(1).Errors(); got != 0 {
		t.Fatalf("block errors = %d, want 0 (policy blocks are not failures)", got)
	}

	plane.noteOutboundDialError(&proxyDialResult{OutboundIndex: 2})
	plane.noteOutboundDialError(nil)
	if got := plane.outboundCountersForIndex(2).Errors(); got != 1 {
		t.Fatalf("proxy errors = %d, want 1", got)
	}
}

// The egress runtime replaces a flow's group with SnapshotForEstablishedFlow.
// If that view dropped the counter pointer, every established flow would
// silently count against nil.
func TestEstablishedFlowSnapshotCarriesCounters(t *testing.T) {
	group := &ob.DialerGroup{Name: "proxy"}
	counters := &ob.Counters{}
	group.SetCounters(counters)

	view := group.SnapshotForEstablishedFlow(nil)
	if view == nil {
		t.Fatal("snapshot is nil")
	}
	if view.Counters() != counters {
		t.Fatal("established-flow snapshot must retain the group's counters")
	}
}
