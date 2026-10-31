/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"testing"
	"time"

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
