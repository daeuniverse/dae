/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@daeuniverse.org>
 */

package control

import (
	"sync"
	"testing"
	"time"

	dnsmessage "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// TestDnsCache_GetStaleResponse tests the GetStaleResponse method
func TestDnsCache_GetStaleResponse(t *testing.T) {
	// Create cache that expires in 1 second
	deadline := time.Now().Add(1 * time.Second)
	answers := []dnsmessage.RR{
		&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{
				Name:   "stale.example.com.",
				Rrtype: dnsmessage.TypeA,
				Class:  dnsmessage.ClassINET,
				Ttl:    1,
			},
			A: []byte{93, 184, 216, 34},
		},
	}

	cache := &DnsCache{
		DomainBitmap:     []uint32{1},
		Answer:           answers,
		Deadline:         deadline,
		OriginalDeadline: deadline,
	}

	if err := cache.PrepackResponse("stale.example.com.", dnsmessage.TypeA); err != nil {
		t.Fatal(err)
	}

	// Before expiry: GetStaleResponse should return nil
	resp := cache.GetStaleResponse(time.Now(), 60)
	require.Nil(t, resp, "GetStaleResponse should return nil for non-expired cache")

	// Wait for expiry
	time.Sleep(1100 * time.Millisecond)

	// After expiry (within 60s window): GetStaleResponse should return stale response
	resp = cache.GetStaleResponse(time.Now(), 60)
	require.NotNil(t, resp, "GetStaleResponse should return stale response within 60s window")

	// Test with staleTtl=0 (never expire)
	resp = cache.GetStaleResponse(time.Now(), 0)
	require.NotNil(t, resp, "GetStaleResponse with staleTtl=0 should always return stale response")
}

// TestDnsController_OptimisticCache_Enabled tests optimistic cache with optimistic_cache=true
func TestDnsController_OptimisticCache_Enabled(t *testing.T) {
	controller := &DnsController{
		optimisticCacheEnabled: true,
		dnsCache:               sync.Map{},
		dnsForwarderCache:      sync.Map{},
		log:                    nil,
		janitorStop:            make(chan struct{}),
		janitorDone:            make(chan struct{}),
		evictorDone:            make(chan struct{}),
		evictorQ:               make(chan *DnsCache, 512),
	}

	// Create cache that expires in 1 second
	deadline := time.Now().Add(1 * time.Second)
	answers := []dnsmessage.RR{
		&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{
				Name:   "optimistic.example.com.",
				Rrtype: dnsmessage.TypeA,
				Class:  dnsmessage.ClassINET,
				Ttl:    1,
			},
			A: []byte{93, 184, 216, 34},
		},
	}

	cache := &DnsCache{
		DomainBitmap:     []uint32{1},
		Answer:           answers,
		Deadline:         deadline,
		OriginalDeadline: deadline,
	}

	if err := cache.PrepackResponse("optimistic.example.com.", dnsmessage.TypeA); err != nil {
		t.Fatal(err)
	}

	cacheKey := "optimistic.example.com.:1"
	controller.dnsCache.Store(cacheKey, cache)

	// Before expiry: should return fresh response
	msg := &dnsmessage.Msg{
		Question: []dnsmessage.Question{
			{Name: "optimistic.example.com.", Qtype: dnsmessage.TypeA, Qclass: dnsmessage.ClassINET},
		},
	}
	resp, needRefresh := controller.LookupDnsRespCache_(msg, cacheKey, false)
	require.NotNil(t, resp, "should return fresh response before expiry")
	require.False(t, needRefresh, "should not need refresh for fresh response")

	// Wait for expiry
	time.Sleep(1100 * time.Millisecond)

	// After expiry (within 60s window): should return stale response and trigger refresh
	msg = &dnsmessage.Msg{
		Question: []dnsmessage.Question{
			{Name: "optimistic.example.com.", Qtype: dnsmessage.TypeA, Qclass: dnsmessage.ClassINET},
		},
	}
	resp, needRefresh = controller.LookupDnsRespCache_(msg, cacheKey, false)
	require.NotNil(t, resp, "optimistic cache should return stale response within 60s window")
	require.True(t, needRefresh, "should trigger background refresh for stale response")
	require.True(t, cache.IsRefreshing(), "cache should be marked as refreshing")

	// Second lookup: should return stale response but not trigger refresh again
	msg = &dnsmessage.Msg{
		Question: []dnsmessage.Question{
			{Name: "optimistic.example.com.", Qtype: dnsmessage.TypeA, Qclass: dnsmessage.ClassINET},
		},
	}
	resp, needRefresh = controller.LookupDnsRespCache_(msg, cacheKey, false)
	require.NotNil(t, resp, "optimistic cache should return stale response on second lookup")
	require.False(t, needRefresh, "should not trigger refresh again")
}

// TestDnsController_OptimisticCache_Disabled tests optimistic cache with optimistic_cache=false
func TestDnsController_OptimisticCache_Disabled(t *testing.T) {
	controller := &DnsController{
		optimisticCacheEnabled: false,
		dnsCache:               sync.Map{},
		dnsForwarderCache:      sync.Map{},
		log:                    nil,
		janitorStop:            make(chan struct{}),
		janitorDone:            make(chan struct{}),
		evictorDone:            make(chan struct{}),
		evictorQ:               make(chan *DnsCache, 512),
	}

	// Create cache that expires in 1 second
	deadline := time.Now().Add(1 * time.Second)
	answers := []dnsmessage.RR{
		&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{
				Name:   "no-optimistic.example.com.",
				Rrtype: dnsmessage.TypeA,
				Class:  dnsmessage.ClassINET,
				Ttl:    1,
			},
			A: []byte{93, 184, 216, 34},
		},
	}

	cache := &DnsCache{
		DomainBitmap:     []uint32{1},
		Answer:           answers,
		Deadline:         deadline,
		OriginalDeadline: deadline,
	}

	if err := cache.PrepackResponse("no-optimistic.example.com.", dnsmessage.TypeA); err != nil {
		t.Fatal(err)
	}

	cacheKey := "no-optimistic.example.com.:1"
	controller.dnsCache.Store(cacheKey, cache)

	// Before expiry: should return fresh response
	msg := &dnsmessage.Msg{
		Question: []dnsmessage.Question{
			{Name: "no-optimistic.example.com.", Qtype: dnsmessage.TypeA, Qclass: dnsmessage.ClassINET},
		},
	}
	resp, needRefresh := controller.LookupDnsRespCache_(msg, cacheKey, false)
	require.NotNil(t, resp, "should return fresh response before expiry")
	require.False(t, needRefresh, "should not need refresh for fresh response")

	// Wait for expiry
	time.Sleep(1100 * time.Millisecond)

	// After expiry: should return nil immediately (optimistic cache disabled)
	msg = &dnsmessage.Msg{
		Question: []dnsmessage.Question{
			{Name: "no-optimistic.example.com.", Qtype: dnsmessage.TypeA, Qclass: dnsmessage.ClassINET},
		},
	}
	resp, needRefresh = controller.LookupDnsRespCache_(msg, cacheKey, false)
	require.Nil(t, resp, "should return nil when optimistic cache is disabled")
	require.False(t, needRefresh, "should not need refresh when response is nil")
}

// TestDnsController_OptimisticCache_TooStale tests that stale responses beyond 60s are rejected
func TestDnsController_OptimisticCache_TooStale(t *testing.T) {
	controller := &DnsController{
		optimisticCacheEnabled: true,
		optimisticCacheTtl:     60,
		dnsCache:               sync.Map{},
		dnsForwarderCache:      sync.Map{},
		log:                    nil,
		janitorStop:            make(chan struct{}),
		janitorDone:            make(chan struct{}),
		evictorDone:            make(chan struct{}),
		evictorQ:               make(chan *DnsCache, 512),
	}

	// Create cache that expired 61 seconds ago (beyond stale window)
	deadline := time.Now().Add(-61 * time.Second)
	answers := []dnsmessage.RR{
		&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{
				Name:   "too-stale.example.com.",
				Rrtype: dnsmessage.TypeA,
				Class:  dnsmessage.ClassINET,
				Ttl:    0,
			},
			A: []byte{93, 184, 216, 34},
		},
	}

	cache := &DnsCache{
		DomainBitmap:     []uint32{1},
		Answer:           answers,
		Deadline:         deadline,
		OriginalDeadline: deadline,
	}

	if err := cache.PrepackResponse("too-stale.example.com.", dnsmessage.TypeA); err != nil {
		t.Fatal(err)
	}

	cacheKey := "too-stale.example.com.:1"
	controller.dnsCache.Store(cacheKey, cache)

	// Should return nil (too stale)
	msg := &dnsmessage.Msg{
		Question: []dnsmessage.Question{
			{Name: "too-stale.example.com.", Qtype: dnsmessage.TypeA, Qclass: dnsmessage.ClassINET},
		},
	}
	resp, needRefresh := controller.LookupDnsRespCache_(msg, cacheKey, false)
	require.Nil(t, resp, "should return nil for cache beyond stale window")
	require.False(t, needRefresh, "should not need refresh for too-stale cache")
}

// TestDnsController_OptimisticCache_NeverExpire tests optimistic cache with optimistic_cache_ttl=0 (never expire)
func TestDnsController_OptimisticCache_NeverExpire(t *testing.T) {
	controller := &DnsController{
		optimisticCacheEnabled: true,
		optimisticCacheTtl:     0, // never expire
		maxCacheSize:           1000,
		dnsCache:               sync.Map{},
		dnsForwarderCache:      sync.Map{},
		log:                    nil,
		janitorStop:            make(chan struct{}),
		janitorDone:            make(chan struct{}),
		evictorDone:            make(chan struct{}),
		evictorQ:               make(chan *DnsCache, 512),
	}

	// Create cache that expired 10 minutes ago
	deadline := time.Now().Add(-10 * time.Minute)
	answers := []dnsmessage.RR{
		&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{
				Name:   "never-expire.example.com.",
				Rrtype: dnsmessage.TypeA,
				Class:  dnsmessage.ClassINET,
				Ttl:    0,
			},
			A: []byte{93, 184, 216, 34},
		},
	}

	cache := &DnsCache{
		DomainBitmap:     []uint32{1},
		Answer:           answers,
		Deadline:         deadline,
		OriginalDeadline: deadline,
	}

	if err := cache.PrepackResponse("never-expire.example.com.", dnsmessage.TypeA); err != nil {
		t.Fatal(err)
	}

	cacheKey := "never-expire.example.com.:1"
	controller.dnsCache.Store(cacheKey, cache)

	// Should return stale response even after 10 minutes (because optimistic_cache_ttl=0 means never expire)
	msg := &dnsmessage.Msg{
		Question: []dnsmessage.Question{
			{Name: "never-expire.example.com.", Qtype: dnsmessage.TypeA, Qclass: dnsmessage.ClassINET},
		},
	}
	resp, needRefresh := controller.LookupDnsRespCache_(msg, cacheKey, false)
	require.NotNil(t, resp, "should return stale response when optimistic_cache_ttl=0 (never expire)")
	require.True(t, needRefresh, "should trigger background refresh")
}

// TestDnsController_LRUEviction tests LRU eviction when cache is full
func TestDnsController_LRUEviction(t *testing.T) {
	controller := &DnsController{
		optimisticCacheEnabled: true,
		optimisticCacheTtl:     0, // never expire (rely on LRU)
		maxCacheSize:           3, // only 3 entries allowed
		dnsCache:               sync.Map{},
		dnsForwarderCache:      sync.Map{},
		log:                    nil,
		janitorStop:            make(chan struct{}),
		janitorDone:            make(chan struct{}),
		evictorDone:            make(chan struct{}),
		evictorQ:               make(chan *DnsCache, 512),
	}

	// Create 3 cache entries (all expired but never-expire policy)
	now := time.Now()
	for i := 0; i < 3; i++ {
		cache := &DnsCache{
			DomainBitmap:     []uint32{1},
			Answer: []dnsmessage.RR{
				&dnsmessage.A{
					Hdr: dnsmessage.RR_Header{
						Name:   "lru.example.com.",
						Rrtype: dnsmessage.TypeA,
						Class:  dnsmessage.ClassINET,
						Ttl:    0,
					},
					A: []byte{93, 184, 216, byte(i)},
				},
			},
			Deadline:         now.Add(-time.Duration(i+1) * time.Minute),
			OriginalDeadline: now.Add(-time.Duration(i+1) * time.Minute),
		}
		
		domain := string(rune('a' + i)) + ".example.com."
		if err := cache.PrepackResponse(domain, dnsmessage.TypeA); err != nil {
			t.Fatal(err)
		}
		
		cacheKey := domain + ":1"
		cache.lastAccessNano.Store(now.Add(-time.Duration(3-i) * time.Minute).UnixNano())
		controller.dnsCache.Store(cacheKey, cache)
	}
	
	// Verify we have 3 entries
	var count int
	controller.dnsCache.Range(func(_, _ interface{}) bool {
		count++
		return true
	})
	require.Equal(t, 3, count, "should have 3 cache entries")
	
	// Trigger LRU eviction by calling evictExpiredDnsCache
	controller.evictExpiredDnsCache(now)
	
	// Should still have 3 entries (no time-based eviction with ttl=0)
	count = 0
	controller.dnsCache.Range(func(_, _ interface{}) bool {
		count++
		return true
	})
	require.Equal(t, 3, count, "should still have 3 entries (no time-based eviction)")
	
	// Add one more entry to trigger LRU eviction
	cache4 := &DnsCache{
		DomainBitmap:     []uint32{1},
		Answer: []dnsmessage.RR{
			&dnsmessage.A{
				Hdr: dnsmessage.RR_Header{
					Name:   "d.example.com.",
					Rrtype: dnsmessage.TypeA,
					Class:  dnsmessage.ClassINET,
					Ttl:    0,
				},
				A: []byte{93, 184, 216, 3},
			},
		},
		Deadline:         now,
		OriginalDeadline: now,
	}
	if err := cache4.PrepackResponse("d.example.com.", dnsmessage.TypeA); err != nil {
		t.Fatal(err)
	}
	cache4.lastAccessNano.Store(now.UnixNano())
	controller.dnsCache.Store("d.example.com.:1", cache4)
	
	// Trigger LRU eviction
	controller.evictExpiredDnsCache(now)
	
	// Should have 3 entries (LRU eviction removed oldest one)
	count = 0
	controller.dnsCache.Range(func(_, _ interface{}) bool {
		count++
		return true
	})
	require.Equal(t, 3, count, "should have 3 entries after LRU eviction")
	
	// Verify oldest entry was evicted (a.example.com has oldest access time)
	_, exists := controller.dnsCache.Load("a.example.com.:1")
	require.False(t, exists, "oldest entry should be evicted by LRU")
	
	// Verify newest entry still exists
	_, exists = controller.dnsCache.Load("d.example.com.:1")
	require.True(t, exists, "newest entry should still exist")
}

// TestDnsController_OptimisticCache_CustomTtl tests optimistic cache with custom TTL (30s)
func TestDnsController_OptimisticCache_CustomTtl(t *testing.T) {
	controller := &DnsController{
		optimisticCacheEnabled: true,
		optimisticCacheTtl:     30, // custom 30s window
		dnsCache:               sync.Map{},
		dnsForwarderCache:      sync.Map{},
		log:                    nil,
		janitorStop:            make(chan struct{}),
		janitorDone:            make(chan struct{}),
		evictorDone:            make(chan struct{}),
		evictorQ:               make(chan *DnsCache, 512),
	}

	// Create cache that expires in 1 second
	deadline := time.Now().Add(1 * time.Second)
	answers := []dnsmessage.RR{
		&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{
				Name:   "custom-ttl.example.com.",
				Rrtype: dnsmessage.TypeA,
				Class:  dnsmessage.ClassINET,
				Ttl:    1,
			},
			A: []byte{93, 184, 216, 34},
		},
	}

	cache := &DnsCache{
		DomainBitmap:     []uint32{1},
		Answer:           answers,
		Deadline:         deadline,
		OriginalDeadline: deadline,
	}

	if err := cache.PrepackResponse("custom-ttl.example.com.", dnsmessage.TypeA); err != nil {
		t.Fatal(err)
	}

	cacheKey := "custom-ttl.example.com.:1"
	controller.dnsCache.Store(cacheKey, cache)

	// Wait for expiry
	time.Sleep(1100 * time.Millisecond)

	// After expiry (within 30s window): should return stale response
	msg := &dnsmessage.Msg{
		Question: []dnsmessage.Question{
			{Name: "custom-ttl.example.com.", Qtype: dnsmessage.TypeA, Qclass: dnsmessage.ClassINET},
		},
	}
	resp, needRefresh := controller.LookupDnsRespCache_(msg, cacheKey, false)
	require.NotNil(t, resp, "should return stale response within 30s window")
	require.True(t, needRefresh, "should trigger background refresh")
}
