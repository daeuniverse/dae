/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/nativeapi"
	"github.com/daeuniverse/dae/control"
)

func uint64Ptr(value uint64) *uint64 { return &value }

func TestNativeAPIMemoryMapping(t *testing.T) {
	observed := time.Unix(1700000000, 0).UTC()
	snapshot := control.MemorySnapshot{
		ObservedAt: observed,
		RSSBytes:   uint64Ptr(1024),
		Cgroup: &control.CgroupMemorySnapshot{
			Scope:        "service",
			CurrentBytes: uint64Ptr(2048),
			LimitBytes:   nil,
			Events: &control.CgroupMemoryEvents{
				OOMKill: uint64Ptr(3),
			},
		},
		Kernel: &control.KernelMemorySnapshot{EbpfBytes: uint64Ptr(4096), SampledAt: observed},
	}

	memory := nativeAPIMemory(snapshot)
	if memory.ObservedAt != "2023-11-14T22:13:20Z" {
		t.Fatalf("observed_at = %q", memory.ObservedAt)
	}
	if memory.Process == nil || memory.Process.RSSBytes == nil || *memory.Process.RSSBytes != "1024" {
		t.Fatalf("process = %#v", memory.Process)
	}
	if memory.Cgroup == nil || memory.Cgroup.Scope != "service" {
		t.Fatalf("cgroup = %#v", memory.Cgroup)
	}
	if memory.Cgroup.CurrentBytes == nil || *memory.Cgroup.CurrentBytes != "2048" {
		t.Fatalf("current = %#v", memory.Cgroup.CurrentBytes)
	}
	if memory.Cgroup.LimitBytes != nil {
		t.Fatalf("limit = %#v, want nil", memory.Cgroup.LimitBytes)
	}
	if memory.Cgroup.Events == nil || memory.Cgroup.Events.OOMKill == nil || *memory.Cgroup.Events.OOMKill != "3" {
		t.Fatalf("events = %#v", memory.Cgroup.Events)
	}
	if memory.Kernel == nil || memory.Kernel.EbpfBytes == nil || *memory.Kernel.EbpfBytes != "4096" {
		t.Fatalf("kernel = %#v", memory.Kernel)
	}
}

func TestNativeAPIEbpfDetailMapping(t *testing.T) {
	checked := time.Unix(1700000000, 0).UTC()
	detail := nativeAPIEbpfDetail(control.EbpfSnapshot{
		Backend:      "real",
		Programs:     "loaded",
		Hooks:        "attached",
		RoutingState: "published",
		GenerationID: "42",
		Epoch:        "7",
		Health:       "healthy",
		CheckedAt:    checked,
		Attachments: []control.EbpfAttachmentSnapshot{
			{Name: "tproxy_ingress", Kind: "interface", Interface: "eth0", Direction: "ingress", State: "attached"},
			{Name: "wan_egress", Kind: "other", Hook: "dae-netns", Direction: "egress", State: "attached"},
		},
		ConnStateOccupancy: &control.MapOccupancySnapshot{
			Occupancy:      uint64Ptr(12),
			Capacity:       100,
			OccupancyKnown: true,
		},
	})

	if detail.Backend != "real" || detail.Programs != "loaded" || detail.Hooks != "attached" {
		t.Fatalf("summary = %#v", detail.EbpfSummary)
	}
	if detail.Routing.GenerationID == nil || *detail.Routing.GenerationID != "42" {
		t.Fatalf("generation = %#v", detail.Routing.GenerationID)
	}
	if detail.Routing.Epoch == nil || *detail.Routing.Epoch != "7" {
		t.Fatalf("epoch = %#v", detail.Routing.Epoch)
	}
	if len(detail.Attachments) != 2 {
		t.Fatalf("attachments = %d", len(detail.Attachments))
	}
	if detail.Attachments[0].Interface != "eth0" || detail.Attachments[0].Hook != "" {
		t.Fatalf("interface attachment = %#v", detail.Attachments[0])
	}
	if detail.Attachments[1].Hook != "dae-netns" || detail.Attachments[1].Interface != "" {
		t.Fatalf("other attachment = %#v", detail.Attachments[1])
	}
	if detail.Maps == nil || detail.Maps.State != "ready" {
		t.Fatalf("maps = %#v", detail.Maps)
	}
	if detail.Maps.ConnState == nil || detail.Maps.ConnState.Capacity != 100 || !detail.Maps.ConnState.OccupancyKnown {
		t.Fatalf("conn_state = %#v", detail.Maps.ConnState)
	}
}

func TestNativeAPIEbpfDetailUnknownOccupancy(t *testing.T) {
	detail := nativeAPIEbpfDetail(control.EbpfSnapshot{
		CheckedAt:          time.Now(),
		ConnStateOccupancy: &control.MapOccupancySnapshot{Capacity: 100},
	})
	if detail.Maps == nil || detail.Maps.State != "partial" {
		t.Fatalf("maps = %#v", detail.Maps)
	}
	if detail.Maps.ConnState.Occupancy != nil || detail.Maps.ConnState.OccupancyKnown {
		t.Fatalf("conn_state = %#v", detail.Maps.ConnState)
	}
}

func TestNativeAPISafeUIntClampsNegative(t *testing.T) {
	if got := nativeAPISafeUInt(-5); got != 0 {
		t.Fatalf("negative = %d, want 0", got)
	}
	if got := nativeAPISafeUInt(9); got != 9 {
		t.Fatalf("positive = %d, want 9", got)
	}
}

func TestAddDecimalBytes(t *testing.T) {
	for _, tc := range []struct {
		existing string
		delta    uint64
		want     string
	}{
		{"0", 0, "0"},
		{"0", 1234, "1234"},
		{"500", 250, "750"},
		{"not-a-number", 10, "not-a-number"},
		{"18446744073709551615", 1, "18446744073709551615"},
	} {
		if got := addDecimalBytes(tc.existing, tc.delta); got != tc.want {
			t.Errorf("addDecimalBytes(%q, %d) = %q, want %q", tc.existing, tc.delta, got, tc.want)
		}
	}
}

func TestAttributeDirectStatsDisabledIsNoop(t *testing.T) {
	previous := control.DirectStatsEnabled()
	control.ConfigureDirectStats(false)
	t.Cleanup(func() { control.ConfigureDirectStats(previous) })

	outbounds := []nativeapi.OutboundCounters{{Name: "direct", Kind: "builtin", UploadBytes: "7", DownloadBytes: "9"}}
	attributeDirectStats(nil, outbounds)
	if outbounds[0].UploadBytes != "7" || outbounds[0].DownloadBytes != "9" {
		t.Fatalf("disabled observer changed the row: %#v", outbounds[0])
	}
}

func TestMergeDirectStatsCountersAddsToDirectRow(t *testing.T) {
	outbounds := []nativeapi.OutboundCounters{
		{Name: "direct", Kind: "builtin", UploadBytes: "7", DownloadBytes: "9"},
		{Name: "proxy", Kind: "group", UploadBytes: "1", DownloadBytes: "2"},
	}
	mergeDirectStatsCounters(outbounds, control.DirectStatsCounters{
		UpBytes: 100, DownBytes: 200, UpPackets: 3, DownPackets: 4,
	})
	if outbounds[0].UploadBytes != "107" || outbounds[0].DownloadBytes != "209" {
		t.Fatalf("direct row = %#v", outbounds[0])
	}
	if outbounds[1].UploadBytes != "1" || outbounds[1].DownloadBytes != "2" {
		t.Fatalf("proxy row changed: %#v", outbounds[1])
	}
}

func TestProjectOutboundCountersOmitsBlock(t *testing.T) {
	previous := control.DirectStatsEnabled()
	control.ConfigureDirectStats(false)
	t.Cleanup(func() { control.ConfigureDirectStats(previous) })

	snapshot := control.OutboundCountersSnapshot{
		Outbounds: []control.OutboundCounterSnapshot{
			{Name: "direct", Kind: "builtin", UploadBytes: 11, DownloadBytes: 22},
			{Name: "block", Kind: "builtin"},
			{Name: "proxy", Kind: "group", UploadBytes: 33, DownloadBytes: 44},
		},
	}
	rows := projectOutboundCounters(snapshot, nil)
	if len(rows) != 2 {
		t.Fatalf("rows = %#v, want direct and proxy only", rows)
	}
	for _, row := range rows {
		if row.Name == "block" {
			t.Fatalf("block row leaked into the API: %#v", rows)
		}
	}
	if rows[0].Name != "direct" || rows[0].UploadBytes != "11" || rows[1].Name != "proxy" || rows[1].DownloadBytes != "44" {
		t.Fatalf("rows = %#v", rows)
	}
}

func TestSnapshotDirectStatsDisabledIsAZeroState(t *testing.T) {
	previous := control.DirectStatsEnabled()
	control.ConfigureDirectStats(false)
	t.Cleanup(func() { control.ConfigureDirectStats(previous) })

	provider := &nativeAPIProvider{}
	stats, err := provider.SnapshotDirectStats(context.Background())
	if err != nil {
		t.Fatalf("disabled snapshot returned error: %v", err)
	}
	if stats.Enabled || stats.Attached {
		t.Fatalf("disabled snapshot = %+v", stats)
	}
	if stats.UpBytes != "0" || stats.DownBytes != "0" || stats.CounterSince != "" {
		t.Fatalf("disabled counters = %+v", stats)
	}
}
