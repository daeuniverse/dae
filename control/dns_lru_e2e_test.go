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

// TestDnsController_LRUE2E tests end-to-end LRU eviction scenario
// This simulates real-world usage where cache entries are accessed via LookupDnsRespCache_
func TestDnsController_LRUE2E(t *testing.T) {
	controller := &DnsController{
		optimisticCacheEnabled: true,
		optimisticCacheTtl:     0,   // never expire
		maxCacheSize:           5,   // only 5 entries allowed
		dnsCache:               sync.Map{},
		dnsForwarderCache:      sync.Map{},
		log:                    nil,
		janitorStop:            make(chan struct{}),
		janitorDone:            make(chan struct{}),
		evictorDone:            make(chan struct{}),
		evictorQ:               make(chan *DnsCache, 512),
	}
	defer close(controller.janitorStop)

	// Create 5 expired cache entries
	domains := []string{"a.", "b.", "c.", "d.", "e."}
	now := time.Now()
	
	for i, suffix := range domains {
		domain := suffix + "example.com."
		cache := &DnsCache{
			DomainBitmap: []uint32{1},
			Answer: []dnsmessage.RR{
				&dnsmessage.A{
					Hdr: dnsmessage.RR_Header{
						Name:   domain,
						Rrtype: dnsmessage.TypeA,
						Class:  dnsmessage.ClassINET,
						Ttl:    0,
					},
					A: []byte{93, 184, 216, byte(i)},
				},
			},
			Deadline:         now.Add(-time.Hour),
			OriginalDeadline: now.Add(-time.Hour),
		}
		if err := cache.PrepackResponse(domain, dnsmessage.TypeA); err != nil {
			t.Fatal(err)
		}
		
		cacheKey := domain + ":1"
		controller.dnsCache.Store(cacheKey, cache)
	}
	
	// Verify we have 5 entries
	var count int
	controller.dnsCache.Range(func(_, _ interface{}) bool {
		count++
		return true
	})
	require.Equal(t, 5, count, "should have 5 cache entries initially")
	
	// Access entries in this order: b, d, a, e, c (update lastAccessNano)
	// After these accesses: b is oldest (accessed first), c is newest (accessed last)
	accessOrder := []string{"b.example.com.", "d.example.com.", "a.example.com.", "e.example.com.", "c.example.com."}
	for _, domain := range accessOrder {
		msg := &dnsmessage.Msg{
			Question: []dnsmessage.Question{
				{Name: domain, Qtype: dnsmessage.TypeA, Qclass: dnsmessage.ClassINET},
			},
		}
		cacheKey := domain + ":1"
		controller.LookupDnsRespCache_(msg, cacheKey, false)
		time.Sleep(100 * time.Millisecond) // 100ms delay to ensure different timestamps
	}
	
	// Add a new entry (f.example.com), should trigger LRU eviction
	now2 := time.Now()
	cacheNew := &DnsCache{
		DomainBitmap: []uint32{1},
		Answer: []dnsmessage.RR{
			&dnsmessage.A{
				Hdr: dnsmessage.RR_Header{
					Name:   "f.example.com.",
					Rrtype: dnsmessage.TypeA,
					Class:  dnsmessage.ClassINET,
					Ttl:    0,
				},
				A: []byte{93, 184, 216, 5},
			},
		},
		Deadline:         now2,
		OriginalDeadline: now2,
	}
	if err := cacheNew.PrepackResponse("f.example.com.", dnsmessage.TypeA); err != nil {
		t.Fatal(err)
	}
	// Initialize lastAccessNano to current time (simulates cache access)
	cacheNew.lastAccessNano.Store(now2.UnixNano())
	controller.dnsCache.Store("f.example.com.:1", cacheNew)
	
	// Trigger LRU eviction
	controller.evictExpiredDnsCache(now)
	
	// Should still have 5 entries (LRU evicted 1, added 1)
	count = 0
	controller.dnsCache.Range(func(_, _ interface{}) bool {
		count++
		return true
	})
	require.Equal(t, 5, count, "should have 5 entries after LRU eviction")
	
	// Verify b.example.com was evicted (oldest, accessed first)
	_, exists := controller.dnsCache.Load("b.example.com.:1")
	
	// Debug: print all entries and their access times
	t.Log("=== Debug: remaining cache entries ===")
	controller.dnsCache.Range(func(key, value interface{}) bool {
		cacheKey := key.(string)
		cache := value.(*DnsCache)
		lastAccess := time.Unix(0, cache.lastAccessNano.Load())
		t.Logf("  %s: lastAccess=%v", cacheKey, lastAccess)
		return true
	})
	
	require.False(t, exists, "oldest entry 'b' should be evicted by LRU")
	
	// Verify newest entry exists
	_, exists = controller.dnsCache.Load("f.example.com.:1")
	require.True(t, exists, "newest entry 'f' should exist")
	
	// Verify other recently accessed entries still exist
	for _, domain := range []string{"c.example.com.", "e.example.com.", "a.example.com.", "d.example.com."} {
		_, exists := controller.dnsCache.Load(domain + ":1")
		require.True(t, exists, "recently accessed entry %s should exist", domain)
	}
}

// TestDnsController_LRUMultipleEvictions tests multiple LRU evictions
func TestDnsController_LRUMultipleEvictions(t *testing.T) {
	controller := &DnsController{
		optimisticCacheEnabled: true,
		optimisticCacheTtl:     0,  // never expire
		maxCacheSize:           3,  // only 3 entries allowed
		dnsCache:               sync.Map{},
		dnsForwarderCache:      sync.Map{},
		log:                    nil,
		janitorStop:            make(chan struct{}),
		janitorDone:            make(chan struct{}),
		evictorDone:            make(chan struct{}),
		evictorQ:               make(chan *DnsCache, 512),
	}
	defer close(controller.janitorStop)

	now := time.Now()
	
	// Add entries 1-10, but only 3 can stay (7 evictions)
	for i := 0; i < 10; i++ {
		domain := string(rune('a'+i)) + ".example.com."
		cache := &DnsCache{
			DomainBitmap: []uint32{1},
			Answer: []dnsmessage.RR{
				&dnsmessage.A{
					Hdr: dnsmessage.RR_Header{
						Name:   domain,
						Rrtype: dnsmessage.TypeA,
						Class:  dnsmessage.ClassINET,
						Ttl:    0,
					},
					A: []byte{93, 184, 216, byte(i)},
				},
			},
			Deadline:         now,
			OriginalDeadline: now,
		}
		if err := cache.PrepackResponse(domain, dnsmessage.TypeA); err != nil {
			t.Fatal(err)
		}
		// Initialize lastAccessNano with incrementing timestamps
		cache.lastAccessNano.Store(now.Add(time.Duration(i) * time.Millisecond).UnixNano())
		controller.dnsCache.Store(domain+":1", cache)
		
		// Trigger eviction after each addition
		controller.evictExpiredDnsCache(now)
	}
	
	// Should have exactly 3 entries
	var count int
	controller.dnsCache.Range(func(_, _ interface{}) bool {
		count++
		return true
	})
	require.Equal(t, 3, count, "should have exactly 3 entries after multiple evictions")
	
	// Verify only the 3 newest entries remain (h, i, j)
	_, existsH := controller.dnsCache.Load("h.example.com.:1")
	_, existsI := controller.dnsCache.Load("i.example.com.:1")
	_, existsJ := controller.dnsCache.Load("j.example.com.:1")
	
	require.True(t, existsH, "entry 'h' should exist")
	require.True(t, existsI, "entry 'i' should exist")
	require.True(t, existsJ, "entry 'j' should exist")
	
	// Verify older entries were evicted
	for i := 0; i < 7; i++ {
		domain := string(rune('a'+i)) + ".example.com."
		_, exists := controller.dnsCache.Load(domain + ":1")
		require.False(t, exists, "old entry %s should be evicted", domain)
	}
}
