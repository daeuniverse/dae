//go:build !dae_stub_ebpf

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"testing"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func TestBpfMapBatchDeleteAllDeletesLargeMapInChunks(t *testing.T) {
	domainMap := newJanitorTestMap(t, "domain_routing_map")

	const totalEntries = bpfMapBatchDeleteAllChunkSize*2 + bpfMapBatchDeleteAllLookupSize + 7
	populateDomainRoutingMapForTest(t, domainMap, totalEntries)

	if got := countMapEntriesForTest[[4]uint32, bpfDomainRouting](t, domainMap); got != totalEntries {
		t.Fatalf("domain_routing_map entry count before cleanup = %d, want %d", got, totalEntries)
	}

	if err := BpfMapBatchDeleteAll[[4]uint32, bpfDomainRouting](domainMap); err != nil {
		t.Fatalf("BpfMapBatchDeleteAll returned error: %v", err)
	}

	if got := countMapEntriesForTest[[4]uint32, bpfDomainRouting](t, domainMap); got != 0 {
		t.Fatalf("domain_routing_map entry count after cleanup = %d, want 0", got)
	}
}

func TestBpfMapBatchDeleteAllFallsBackWhenBatchLookupUnsupported(t *testing.T) {
	domainMap := newJanitorTestMap(t, "domain_routing_map")
	populateDomainRoutingMapForTest(t, domainMap, 64)

	oldLookup := bpfMapBatchLookup
	lookupCalled := false
	bpfMapBatchLookup = func(_ *ebpf.Map, _ *ebpf.MapBatchCursor, _ interface{}, _ interface{}) (int, error) {
		lookupCalled = true
		return 0, unix.EOPNOTSUPP
	}
	t.Cleanup(func() {
		bpfMapBatchLookup = oldLookup
	})

	if err := BpfMapBatchDeleteAll[[4]uint32, bpfDomainRouting](domainMap); err != nil {
		t.Fatalf("BpfMapBatchDeleteAll fallback returned error: %v", err)
	}

	if !lookupCalled && !SimulateBatchDelete {
		t.Fatal("expected batch lookup to be attempted when batch delete simulation is disabled")
	}

	if got := countMapEntriesForTest[[4]uint32, bpfDomainRouting](t, domainMap); got != 0 {
		t.Fatalf("domain_routing_map entry count after fallback cleanup = %d, want 0", got)
	}
}

func populateDomainRoutingMapForTest(t *testing.T, m *ebpf.Map, entries int) {
	t.Helper()
	var value bpfDomainRouting
	for i := range entries {
		key := [4]uint32{uint32(i + 1), uint32((i + 1) * 3), 0, 0}
		if err := m.Update(&key, &value, ebpf.UpdateAny); err != nil {
			t.Fatalf("update domain_routing_map entry %d: %v", i, err)
		}
	}
}

func countMapEntriesForTest[K any, V any](t *testing.T, m *ebpf.Map) int {
	t.Helper()
	var (
		key   K
		value V
	)
	count := 0
	iter := m.Iterate()
	for iter.Next(&key, &value) {
		count++
	}
	if err := iter.Err(); err != nil {
		t.Fatalf("iterate map: %v", err)
	}
	return count
}
