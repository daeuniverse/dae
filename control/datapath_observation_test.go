/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"os"
	"strings"
	"testing"
)

// TestDatapathKeepsNoTrafficAccounting pins the shape the traffic rework
// depends on: pass-through accounting lives in userspace only, so the datapath
// must not carry per-packet byte carriers or a flow index for it.
func TestDatapathKeepsNoTrafficAccounting(t *testing.T) {
	raw, err := os.ReadFile("kern/tproxy.c")
	if err != nil {
		t.Fatalf("read kernel source: %v", err)
	}
	source := string(raw)
	for _, banned := range []string{
		"direct_traffic_map",
		"direct_reverse_map",
		"account_direct_traffic",
		"remember_direct_flow",
		"is_known_direct_flow",
		"counted_as_download",
	} {
		if strings.Contains(source, banned) {
			t.Fatalf("datapath still carries %q; pass-through accounting must stay in userspace", banned)
		}
	}
}

// TestPerPacketCountersArePercpu pins the cacheline argument: the counters that
// fire per packet must not be a shared ARRAY, or every CPU contends for one
// line on the stateless-passthrough path.
func TestPerPacketCountersArePercpu(t *testing.T) {
	raw, err := os.ReadFile("kern/tproxy.c")
	if err != nil {
		t.Fatalf("read kernel source: %v", err)
	}
	source := string(raw)
	start := strings.Index(source, "bpf_stats_map SEC(\".maps\")")
	if start < 0 {
		t.Fatal("bpf_stats_map not found")
	}
	declaration := source[:start]
	blockStart := strings.LastIndex(declaration, "struct {")
	if blockStart < 0 {
		t.Fatal("bpf_stats_map declaration not found")
	}
	if !strings.Contains(declaration[blockStart:], "BPF_MAP_TYPE_PERCPU_ARRAY") {
		t.Fatal("bpf_stats_map must be a PERCPU array: per-packet increments cannot share one cacheline")
	}
}
