/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"fmt"
	"testing"
)

func TestPacketSnifferFlowFamilyReleaseRemovesLastEntry(t *testing.T) {
	pool := &PacketSnifferPool{}
	key := NewPacketSnifferKey(
		mustParseAddrPort("192.0.2.10:40000"),
		mustParseAddrPort("198.51.100.20:443"),
		makeLikelyQuicInitialPayload(0x51),
	)

	pool.retainFlowFamily(key)
	if !pool.HasFlowFamilySession(key) {
		t.Fatal("expected retained flow family session to be visible")
	}

	pool.releaseFlowFamily(key)
	if pool.HasFlowFamilySession(key) {
		t.Fatal("expected released flow family session to disappear")
	}
	if _, ok := pool.flowFamilies.Load(key.FlowFamilyKey()); ok {
		t.Fatal("expected last flow family entry to be removed from the map")
	}
}

func TestPacketSnifferFlowFamilyReleaseKeepsEntryWhileRefsRemain(t *testing.T) {
	pool := &PacketSnifferPool{}
	key := NewPacketSnifferKey(
		mustParseAddrPort("192.0.2.12:40002"),
		mustParseAddrPort("198.51.100.22:443"),
		makeLikelyQuicInitialPayload(0x71),
	)

	pool.retainFlowFamily(key)
	pool.retainFlowFamily(key)
	pool.releaseFlowFamily(key)

	if !pool.HasFlowFamilySession(key) {
		t.Fatal("expected flow family session to remain after releasing one of two refs")
	}
	value, ok := pool.flowFamilies.Load(key.FlowFamilyKey())
	if !ok {
		t.Fatal("expected flow family entry to stay in the map while refs remain")
	}
	if got := value.(*packetSnifferFlowFamilyRef).refs.Load(); got != 1 {
		t.Fatalf("refs = %d, want 1", got)
	}
}

func TestPacketSnifferFlowFamilyRetainReplacesDrainingEntry(t *testing.T) {
	pool := &PacketSnifferPool{}
	key := NewPacketSnifferKey(
		mustParseAddrPort("192.0.2.11:40001"),
		mustParseAddrPort("198.51.100.21:443"),
		makeLikelyQuicInitialPayload(0x61),
	)

	draining := &packetSnifferFlowFamilyRef{}
	draining.refs.Store(packetSnifferFlowFamilyRefDraining)
	pool.flowFamilies.Store(key.FlowFamilyKey(), draining)

	pool.retainFlowFamily(key)

	value, ok := pool.flowFamilies.Load(key.FlowFamilyKey())
	if !ok {
		t.Fatal("expected retainFlowFamily to restore the flow family entry")
	}
	ref := value.(*packetSnifferFlowFamilyRef)
	if ref == draining {
		t.Fatal("expected retainFlowFamily to replace the draining entry")
	}
	if got := ref.refs.Load(); got != 1 {
		t.Fatalf("refs = %d, want 1", got)
	}
}

func TestPacketSnifferPool_GetOrCreateRegistersFlowFamilyMembers(t *testing.T) {
	pool := NewPacketSnifferPool()
	defer pool.Close()

	src := mustParseAddrPort("192.0.2.31:41001")
	dst := mustParseAddrPort("198.51.100.31:443")
	key1 := NewPacketSnifferKey(src, dst, makeLikelyQuicInitialPayload(0x21))
	key2 := NewPacketSnifferKey(src, dst, makeLikelyQuicInitialPayload(0x41))

	sniffer1, isNew := pool.GetOrCreate(key1, nil)
	if !isNew || sniffer1 == nil {
		t.Fatal("expected first GetOrCreate to create a sniffer")
	}
	sniffer2, isNew := pool.GetOrCreate(key2, nil)
	if !isNew || sniffer2 == nil {
		t.Fatal("expected second GetOrCreate to create a second sniffer")
	}

	family := pool.loadFlowFamily(key1)
	if family == nil {
		t.Fatal("expected flow family index to exist")
	}
	entries := family.snapshotMembers()
	if len(entries) != 2 {
		t.Fatalf("flow family member count = %d, want 2", len(entries))
	}

	got := map[PacketSnifferKey]*PacketSniffer{}
	for _, entry := range entries {
		got[entry.key] = entry.sniffer
	}
	if got[key1] != sniffer1 {
		t.Fatal("expected flow family index to include first sniffer")
	}
	if got[key2] != sniffer2 {
		t.Fatal("expected flow family index to include second sniffer")
	}
}

func TestPacketSnifferPool_RemoveFlowFamilySessionsRemovesOnlyMatchingFamily(t *testing.T) {
	pool := NewPacketSnifferPool()
	defer pool.Close()

	src := mustParseAddrPort("192.0.2.41:42001")
	dst := mustParseAddrPort("198.51.100.41:443")
	otherSrc := mustParseAddrPort("192.0.2.42:42002")
	otherDst := mustParseAddrPort("198.51.100.42:443")

	key1 := NewPacketSnifferKey(src, dst, makeLikelyQuicInitialPayload(0x51))
	key2 := NewPacketSnifferKey(src, dst, makeLikelyQuicInitialPayload(0x61))
	keyOther := NewPacketSnifferKey(otherSrc, otherDst, makeLikelyQuicInitialPayload(0x71))

	if _, isNew := pool.GetOrCreate(key1, nil); !isNew {
		t.Fatal("expected first family member to be created")
	}
	if _, isNew := pool.GetOrCreate(key2, nil); !isNew {
		t.Fatal("expected second family member to be created")
	}
	if _, isNew := pool.GetOrCreate(keyOther, nil); !isNew {
		t.Fatal("expected other-family member to be created")
	}

	removed := pool.RemoveFlowFamilySessions(key1)
	if removed != 2 {
		t.Fatalf("RemoveFlowFamilySessions() removed %d entries, want 2", removed)
	}
	if got := pool.Get(key1); got != nil {
		t.Fatal("expected first same-family sniffer to be removed")
	}
	if got := pool.Get(key2); got != nil {
		t.Fatal("expected second same-family sniffer to be removed")
	}
	if got := pool.Get(keyOther); got == nil {
		t.Fatal("expected other-family sniffer to remain")
	}
	if pool.HasFlowFamilySession(key1) {
		t.Fatal("expected removed flow family session to disappear")
	}
	if !pool.HasFlowFamilySession(keyOther) {
		t.Fatal("expected unrelated flow family session to remain")
	}
	if _, ok := pool.flowFamilies.Load(key1.FlowFamilyKey()); ok {
		t.Fatal("expected removed flow family entry to be deleted")
	}
	if _, ok := pool.flowFamilies.Load(keyOther.FlowFamilyKey()); !ok {
		t.Fatal("expected unrelated flow family entry to remain")
	}
}

func BenchmarkPacketSnifferPool_ObserveFlowFamilyQuicInitial(b *testing.B) {
	pool := NewPacketSnifferPool()
	defer pool.Close()

	targetSrc := mustParseAddrPort("192.0.2.51:43001")
	targetDst := mustParseAddrPort("198.51.100.51:443")
	targetPayload := makeLikelyQuicInitialPayload(0x81)
	targetKey := NewPacketSnifferKey(targetSrc, targetDst, targetPayload)

	if _, isNew := pool.GetOrCreate(targetKey, nil); !isNew {
		b.Fatal("expected target sniffer to be created")
	}

	for i := 0; i < 2048; i++ {
		src := mustParseAddrPort(fmt.Sprintf("192.0.2.60:%d", 44000+i))
		dst := mustParseAddrPort(fmt.Sprintf("198.51.100.60:%d", 45000+i))
		key := NewPacketSnifferKey(src, dst, makeLikelyQuicInitialPayload(byte(i%200+1)))
		if _, isNew := pool.GetOrCreate(key, nil); !isNew {
			b.Fatalf("expected unrelated sniffer %d to be created", i)
		}
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		observed, changed := pool.ObserveFlowFamilyQuicInitial(targetKey, targetPayload)
		if !observed || changed {
			b.Fatalf("ObserveFlowFamilyQuicInitial() = (%v, %v), want (true, false)", observed, changed)
		}
	}
}

func BenchmarkPacketSnifferPool_RemoveFlowFamilySessions(b *testing.B) {
	pool := NewPacketSnifferPool()
	defer pool.Close()

	targetSrc := mustParseAddrPort("192.0.2.71:46001")
	targetDst := mustParseAddrPort("198.51.100.71:443")

	for i := 0; i < 2048; i++ {
		src := mustParseAddrPort(fmt.Sprintf("192.0.2.80:%d", 47000+i))
		dst := mustParseAddrPort(fmt.Sprintf("198.51.100.80:%d", 48000+i))
		key := NewPacketSnifferKey(src, dst, makeLikelyQuicInitialPayload(byte(i%200+1)))
		if _, isNew := pool.GetOrCreate(key, nil); !isNew {
			b.Fatalf("expected unrelated sniffer %d to be created", i)
		}
	}

	repopulate := func() PacketSnifferKey {
		var firstKey PacketSnifferKey
		for i := 0; i < 4; i++ {
			key := NewPacketSnifferKey(targetSrc, targetDst, makeLikelyQuicInitialPayload(byte(0xa0+i)))
			if i > 0 {
				key.DCID[0] += byte(i)
			}
			if _, isNew := pool.GetOrCreate(key, nil); !isNew {
				b.Fatalf("expected target sniffer %d to be created", i)
			}
			if i == 0 {
				firstKey = key
			}
		}
		return firstKey
	}

	key := repopulate()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		removed := pool.RemoveFlowFamilySessions(key)
		if removed != 4 {
			b.Fatalf("RemoveFlowFamilySessions() removed %d entries, want 4", removed)
		}

		b.StopTimer()
		key = repopulate()
		b.StartTimer()
	}
}
