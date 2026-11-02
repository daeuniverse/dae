/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
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
		{"DIRECT_STATS_UPLOAD_BYTES", directStatsKeyUpBytes},
		{"DIRECT_STATS_UPLOAD_PACKETS", directStatsKeyUpPackets},
		{"DIRECT_STATS_DOWNLOAD_BYTES", directStatsKeyDownBytes},
		{"DIRECT_STATS_DOWNLOAD_PACKETS", directStatsKeyDownPackets},
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
	for _, want := range []string{"dualPriority = 2", "ingressPriority = 2"} {
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
