/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net/netip"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
)

func TestReserveLpmRingSlotsReturnsCurrentIndexForZeroCount(t *testing.T) {
	old := globalNextLpmIndex.Load()
	globalNextLpmIndex.Store(123)
	t.Cleanup(func() {
		globalNextLpmIndex.Store(old)
	})

	got, err := reserveLpmRingSlots(0)
	if err != nil {
		t.Fatalf("reserveLpmRingSlots(0) error = %v", err)
	}
	if got != 123 {
		t.Fatalf("reserveLpmRingSlots(0) = %d, want 123", got)
	}
}

func TestReserveLpmRingSlotsWrapsAroundRing(t *testing.T) {
	old := globalNextLpmIndex.Load()
	maxEntries := uint32(consts.MaxMatchSetLen)
	globalNextLpmIndex.Store(maxEntries - 2)
	t.Cleanup(func() {
		globalNextLpmIndex.Store(old)
	})

	got, err := reserveLpmRingSlots(4)
	if err != nil {
		t.Fatalf("reserveLpmRingSlots(4) error = %v", err)
	}
	if got != maxEntries-2 {
		t.Fatalf("reserveLpmRingSlots(4) start = %d, want %d", got, maxEntries-2)
	}
	if next := globalNextLpmIndex.Load(); next != 2 {
		t.Fatalf("globalNextLpmIndex = %d after wrap, want 2", next)
	}
}

func TestReserveLpmRingSlotsRejectsOversizeAllocation(t *testing.T) {
	if _, err := reserveLpmRingSlots(uint32(consts.MaxMatchSetLen) + 1); err == nil {
		t.Fatal("reserveLpmRingSlots() error = nil, want oversize allocation error")
	}
}

func TestRoutingKernspaceSnapshotRetainsBuilderStateAfterRelease(t *testing.T) {
	builder := &RoutingMatcherBuilder{
		rules: []bpfMatchSet{
			{Type: uint8(consts.MatchType_Fallback)},
		},
		simulatedLpmTries: [][]netip.Prefix{
			{netip.MustParsePrefix("192.0.2.0/24")},
		},
		lpmDedup: map[uint64]lpmDedupEntry{
			1: {index: 0, prefixes: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}},
		},
	}

	snapshot := builder.KernspaceSnapshot()
	builder.rules = nil
	builder.simulatedLpmTries = nil
	builder.lpmDedup = nil

	if snapshot == nil {
		t.Fatal("KernspaceSnapshot() = nil, want snapshot")
	}
	if got := len(snapshot.rules); got != 1 {
		t.Fatalf("len(snapshot.rules) = %d, want 1", got)
	}
	if got := len(snapshot.simulatedLpmTries); got != 1 {
		t.Fatalf("len(snapshot.simulatedLpmTries) = %d, want 1", got)
	}
	if snapshot.dedupCount != 1 {
		t.Fatalf("snapshot.dedupCount = %d, want 1", snapshot.dedupCount)
	}
}
