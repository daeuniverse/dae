//go:build dae_stub_ebpf

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"regexp"
	"strconv"
	"testing"
)

var directTrafficEnumPattern = regexp.MustCompile(`enum\s+direct_traffic_key\s*\{([^}]*)\}`)

var directTrafficMapPattern = regexp.MustCompile(`struct\s*\{[^}]*BPF_MAP_TYPE_PERCPU_ARRAY[^}]*\}\s*direct_traffic_map`)

// TestDirectTrafficKeysParityWithKernelSource pins the direct_traffic_map key
// domain. A direction read under the wrong key would report upload traffic as
// download, which no other assertion in the suite would catch.
func TestDirectTrafficKeysParityWithKernelSource(t *testing.T) {
	m := directTrafficEnumPattern.FindStringSubmatch(tproxySource)
	if m == nil {
		t.Fatal("enum direct_traffic_key not found in kern/tproxy.c")
	}
	cKeys := map[string]uint32{}
	for _, em := range enumEntryPattern.FindAllStringSubmatch(m[1], -1) {
		value, err := strconv.ParseUint(em[2], 10, 32)
		if err != nil {
			t.Fatalf("parse enum entry %s: %v", em[0], err)
		}
		cKeys[em[1]] = uint32(value)
	}

	contract := []struct {
		cName string
		goKey uint32
	}{
		{"DIRECT_TRAFFIC_UPLOAD_BYTES", directTrafficUploadBytes},
		{"DIRECT_TRAFFIC_DOWNLOAD_BYTES", directTrafficDownloadBytes},
	}
	for _, entry := range contract {
		value, ok := cKeys[entry.cName]
		if !ok {
			t.Errorf("%s missing from enum direct_traffic_key", entry.cName)
			continue
		}
		if value != entry.goKey {
			t.Errorf("%s = %d in C but %d in Go; userspace would read the wrong direction",
				entry.cName, value, entry.goKey)
		}
	}
	if len(cKeys) != len(contract)+1 {
		t.Errorf("enum direct_traffic_key declares %d entries but Go mirrors %d data keys plus the terminal capacity",
			len(cKeys), len(contract))
	}
	if cKeys["DIRECT_TRAFFIC_MAX"] != uint32(len(contract)) {
		t.Errorf("DIRECT_TRAFFIC_MAX = %d, want %d (the ARRAY capacity must be the terminal enum entry)",
			cKeys["DIRECT_TRAFFIC_MAX"], len(contract))
	}

	// The accounting sits on the highest-PPS path, so sharing one cacheline
	// between CPUs is the thing that must not silently reappear.
	if !directTrafficMapPattern.MatchString(tproxySource) {
		t.Error("direct_traffic_map is not a PERCPU_ARRAY; per-CPU is what keeps the hot path free of cacheline contention")
	}
}

// TestDirectTrafficAccountantAdvance covers the three states of the delta
// conversion: baseline adoption, a normal interval, and a map that was
// recreated underneath the accountant.
func TestDirectTrafficAccountantAdvance(t *testing.T) {
	var a directTrafficAccountant

	if up, down := a.advance(directTrafficSnapshot{UploadBytes: 1000, DownloadBytes: 2000}); up != 0 || down != 0 {
		t.Fatalf("first sample must not be reported as an interval, got up=%d down=%d", up, down)
	}
	if up, down := a.advance(directTrafficSnapshot{UploadBytes: 1500, DownloadBytes: 2600}); up != 500 || down != 600 {
		t.Fatalf("delta = up=%d down=%d, want 500/600", up, down)
	}
	if up, down := a.advance(directTrafficSnapshot{UploadBytes: 10, DownloadBytes: 20}); up != 10 || down != 20 {
		t.Fatalf("after a map reset delta = up=%d down=%d, want 10/20 (rebase, not underflow)", up, down)
	}
	if up, down := a.advance(directTrafficSnapshot{UploadBytes: 10, DownloadBytes: 20}); up != 0 || down != 0 {
		t.Fatalf("steady sample delta = up=%d down=%d, want 0/0", up, down)
	}
}

// TestReadDirectTrafficCountersWithoutMap asserts the observational contract:
// a missing map reads as zero instead of panicking on the maintenance tick.
func TestReadDirectTrafficCountersWithoutMap(t *testing.T) {
	if snap := readDirectTrafficCounters(nil); snap != (directTrafficSnapshot{}) {
		t.Fatalf("nil bpf must read as zero, got %+v", snap)
	}
	if snap := readDirectTrafficCounters(&bpfObjects{}); snap != (directTrafficSnapshot{}) {
		t.Fatalf("nil map must read as zero, got %+v", snap)
	}
}
