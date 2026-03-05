/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"encoding/binary"
	"math"
	"reflect"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
)

func TestReserveLpmRingSlotsWrapAndBounds(t *testing.T) {
	maxEntries := uint32(consts.MaxMatchSetLen)
	if maxEntries < 3 {
		t.Fatalf("unexpected MaxMatchSetLen: %d", maxEntries)
	}

	old := globalNextLpmIndex.Load()
	defer globalNextLpmIndex.Store(old)

	globalNextLpmIndex.Store(maxEntries - 2)
	start, err := reserveLpmRingSlots(3)
	if err != nil {
		t.Fatalf("reserveLpmRingSlots: %v", err)
	}
	if start != maxEntries-2 {
		t.Fatalf("unexpected start: %d", start)
	}
	if got := globalNextLpmIndex.Load(); got != 1 {
		t.Fatalf("unexpected next index: %d", got)
	}

	if _, err = reserveLpmRingSlots(maxEntries + 1); err == nil {
		t.Fatalf("expected too-many-lpm error")
	}
}

func TestRewriteKernRulesWithRingLpmIndex(t *testing.T) {
	maxEntries := uint32(consts.MaxMatchSetLen)
	allocStartIdx := maxEntries - 1

	makeLpmRule := func(matchType consts.MatchType, lpmIdx uint32) bpfMatchSet {
		r := bpfMatchSet{Type: uint8(matchType)}
		binary.LittleEndian.PutUint32(r.Value[:4], lpmIdx)
		return r
	}

	rules := []bpfMatchSet{
		makeLpmRule(consts.MatchType_IpSet, 0),
		makeLpmRule(consts.MatchType_SourceIpSet, 1),
		makeLpmRule(consts.MatchType_Mac, 2),
		{Type: uint8(consts.MatchType_Port), Value: [16]byte{9, 8, 7, 6}},
	}
	origin := make([]bpfMatchSet, len(rules))
	copy(origin, rules)

	rewritten, err := rewriteKernRulesWithRingLpmIndex(rules, allocStartIdx, 3)
	if err != nil {
		t.Fatalf("rewriteKernRulesWithRingLpmIndex: %v", err)
	}

	if got := binary.LittleEndian.Uint32(rewritten[0].Value[:4]); got != (allocStartIdx+0)%maxEntries {
		t.Fatalf("bad ipset lpm index: %d", got)
	}
	if got := binary.LittleEndian.Uint32(rewritten[1].Value[:4]); got != (allocStartIdx+1)%maxEntries {
		t.Fatalf("bad source ipset lpm index: %d", got)
	}
	if got := binary.LittleEndian.Uint32(rewritten[2].Value[:4]); got != (allocStartIdx+2)%maxEntries {
		t.Fatalf("bad mac lpm index: %d", got)
	}
	if rewritten[3].Value != rules[3].Value {
		t.Fatalf("non-lpm rule should not be rewritten")
	}

	if !reflect.DeepEqual(rules, origin) {
		t.Fatalf("rewrite should not mutate source rules")
	}
}

func TestRewriteKernRulesWithRingLpmIndexRejectsBadIndex(t *testing.T) {
	rule := bpfMatchSet{Type: uint8(consts.MatchType_IpSet)}
	binary.LittleEndian.PutUint32(rule.Value[:4], 1)
	_, err := rewriteKernRulesWithRingLpmIndex([]bpfMatchSet{rule}, 0, 1)
	if err == nil {
		t.Fatalf("expected error for out-of-range lpm index")
	}
}

func TestReserveLpmRingSlotsUint32Overflow(t *testing.T) {
	maxEntries := uint32(consts.MaxMatchSetLen)
	if maxEntries < 5 {
		t.Fatalf("unexpected MaxMatchSetLen: %d", maxEntries)
	}

	old := globalNextLpmIndex.Load()
	defer globalNextLpmIndex.Store(old)

	globalNextLpmIndex.Store(^uint32(0) - 2)
	start, err := reserveLpmRingSlots(5)
	if err != nil {
		t.Fatalf("reserveLpmRingSlots: %v", err)
	}
	if start != ^uint32(0)-2 {
		t.Fatalf("unexpected start near MaxUint32: got %d, want %d", start, ^uint32(0)-2)
	}
	next := globalNextLpmIndex.Load()
	expectedNext := uint32(2)
	if next != expectedNext {
		t.Fatalf("unexpected next after overflow: got %d, want %d", next, expectedNext)
	}
}

func TestReserveLpmRingSlotsConcurrentSafety(t *testing.T) {
	const goroutines = 100
	const slotsPerGoroutine = 3

	old := globalNextLpmIndex.Load()
	defer globalNextLpmIndex.Store(old)

	globalNextLpmIndex.Store(0)

	results := make(chan uint32, goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			start, err := reserveLpmRingSlots(slotsPerGoroutine)
			if err != nil {
				t.Errorf("reserveLpmRingSlots failed: %v", err)
				results <- math.MaxUint32 // error sentinel; valid starts are in [0, MaxMatchSetLen)
				return
			}
			results <- start
		}()
	}

	seen := make(map[uint32]bool)
	for i := 0; i < goroutines; i++ {
		start := <-results
		if start == math.MaxUint32 {
			continue // error path; t.Errorf already called above
		}
		for j := uint32(0); j < slotsPerGoroutine; j++ {
			slot := (start + j) % uint32(consts.MaxMatchSetLen)
			if seen[slot] {
				t.Errorf("slot %d allocated twice", slot)
			}
			seen[slot] = true
		}
	}

	expected := goroutines * slotsPerGoroutine
	if len(seen) != expected {
		t.Errorf("expected %d unique slots, got %d", expected, len(seen))
	}
}
