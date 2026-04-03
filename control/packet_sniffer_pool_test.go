/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import "testing"

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
