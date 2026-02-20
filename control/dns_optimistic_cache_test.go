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
	resp := cache.GetStaleResponse(time.Now())
	require.Nil(t, resp, "GetStaleResponse should return nil for non-expired cache")

	// Wait for expiry
	time.Sleep(1100 * time.Millisecond)

	// After expiry (within 60s window): GetStaleResponse should return stale response
	resp = cache.GetStaleResponse(time.Now())
	require.NotNil(t, resp, "GetStaleResponse should return stale response within 60s window")

	// After 61s: GetStaleResponse should return nil (too stale)
	time.Sleep(60 * time.Second)
	resp = cache.GetStaleResponse(time.Now())
	require.Nil(t, resp, "GetStaleResponse should return nil after 60s window")
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
