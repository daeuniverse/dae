/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@daeuniverse.org>
 */

package control

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

func mustParsePacketSnifferAddrPort(t *testing.T, s string) netip.AddrPort {
	t.Helper()
	return netip.MustParseAddrPort(s)
}

func testPacketSnifferKey(t *testing.T, dcid []byte, seq uint16) PacketSnifferKey {
	t.Helper()

	var key PacketSnifferKey
	key.LAddr = mustParsePacketSnifferAddrPort(t, "192.0.2.10:40000")
	key.RAddr = netip.AddrPortFrom(mustParsePacketSnifferAddrPort(t, "198.51.100.20:443").Addr(), 443+seq)
	if len(dcid) > 0 {
		key.DCIDLen = uint8(len(dcid))
		copy(key.DCID[:], dcid)
	}
	return key
}

func cacheEntryForKey(cache *failedQuicDcidCache, key PacketSnifferKey) (failedQuicDcidCacheEntry, bool) {
	shard := cache.shardFor(key)
	shard.mu.RLock()
	defer shard.mu.RUnlock()
	entry, ok := shard.entries[key]
	return entry, ok
}

func TestFailedQuicDcidCache_SkipsKeysWithoutDCID(t *testing.T) {
	cache := newFailedQuicDcidCache(failedQuicDcidCacheShardCount)
	key := testPacketSnifferKey(t, nil, 0)
	now := time.Unix(1000, 0)

	cache.MarkFailed(key, quicDcidFailureReasonSoftBypass, now)

	if cache.Len() != 0 {
		t.Fatalf("Len() = %d, want 0 for non-DCID keys", cache.Len())
	}
	if cache.IsFailed(key, now) {
		t.Fatal("IsFailed() = true, want false for non-DCID keys")
	}
}

func TestFailedQuicDcidCache_SoftBypassBackoff(t *testing.T) {
	cache := newFailedQuicDcidCache(failedQuicDcidCacheShardCount)
	key := testPacketSnifferKey(t, []byte{1, 2, 3, 4}, 0)
	now := time.Unix(2000, 0)

	cache.MarkFailed(key, quicDcidFailureReasonSoftBypass, now)
	first, ok := cacheEntryForKey(cache, key)
	if !ok {
		t.Fatal("expected cache entry after first mark")
	}
	if got := time.Duration(first.expiresAtUnixNano - now.UnixNano()); got != failedQuicDcidSoftBypassTtl {
		t.Fatalf("first TTL = %v, want %v", got, failedQuicDcidSoftBypassTtl)
	}

	now2 := now.Add(time.Second)
	cache.MarkFailed(key, quicDcidFailureReasonSoftBypass, now2)
	second, ok := cacheEntryForKey(cache, key)
	if !ok {
		t.Fatal("expected cache entry after second mark")
	}
	if got := time.Duration(second.expiresAtUnixNano - now2.UnixNano()); got != failedQuicDcidSoftBypassTtl*2 {
		t.Fatalf("second TTL = %v, want %v", got, failedQuicDcidSoftBypassTtl*2)
	}
	if second.expiresAtUnixNano < first.expiresAtUnixNano {
		t.Fatal("second mark should not shorten an active suppression window")
	}
}

func TestFailedQuicDcidCache_CleanupExpired(t *testing.T) {
	cache := newFailedQuicDcidCache(failedQuicDcidCacheShardCount)
	key := testPacketSnifferKey(t, []byte{5, 6, 7, 8}, 0)
	now := time.Unix(3000, 0)

	cache.MarkFailed(key, quicDcidFailureReasonDecryptFailure, now)
	cache.CleanupExpired(now.Add(failedQuicDcidDecryptFailTtl + time.Second))

	if cache.Len() != 0 {
		t.Fatalf("Len() = %d, want 0 after cleanup", cache.Len())
	}
	if cache.IsFailed(key, now.Add(failedQuicDcidDecryptFailTtl+time.Second)) {
		t.Fatal("IsFailed() = true after expiry cleanup")
	}
}

func TestFailedQuicDcidCache_HardCapacity(t *testing.T) {
	cache := newFailedQuicDcidCache(failedQuicDcidCacheShardCount)
	now := time.Unix(4000, 0)

	for i := 0; i < 1000; i++ {
		var dcid [4]byte
		binary.BigEndian.PutUint32(dcid[:], uint32(i+1))
		key := testPacketSnifferKey(t, dcid[:], uint16(i%1024))
		cache.MarkFailed(key, quicDcidFailureReasonDecryptFailure, now)
	}

	if got := cache.Len(); got > failedQuicDcidCacheShardCount {
		t.Fatalf("Len() = %d, want <= %d", got, failedQuicDcidCacheShardCount)
	}
}
