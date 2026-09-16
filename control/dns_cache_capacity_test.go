/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"testing"
	"time"

	dnsmessage "github.com/miekg/dns"
)

func newCapacityTestDnsController(maxEntries int) *DnsController {
	controller := newTestDnsController()
	setTestDnsControllerRuntime(controller, func(rt *dnsControllerRuntimeState) {
		rt.maxCacheSize = maxEntries
		rt.routeProjectionEpoch = 1
		rt.newCache = func(_ string, answers, ns, extra []dnsmessage.RR, deadline, originalDeadline time.Time) (*DnsCache, error) {
			return &DnsCache{
				Answer:           answers,
				NS:               ns,
				Extra:            extra,
				Deadline:         deadline,
				OriginalDeadline: originalDeadline,
			}, nil
		}
	})
	return controller
}

func TestDnsCacheCapacityIsEnforcedAtPublication(t *testing.T) {
	controller := newCapacityTestDnsController(2)
	for _, host := range []string{"one.example", "two.example", "three.example"} {
		if err := controller.UpdateDnsCacheTtl(host, dnsmessage.TypeA, nil, nil, nil, 60); err != nil {
			t.Fatalf("UpdateDnsCacheTtl(%q) error = %v", host, err)
		}
	}

	if got := countDnsCacheEntries(controller); got != 2 {
		t.Fatalf("DNS cache entries = %d, want 2", got)
	}
	if got := controller.dnsCacheSize.Load(); got != 2 {
		t.Fatalf("tracked DNS cache size = %d, want 2", got)
	}
	if _, ok := controller.dnsCache.Load(controller.cacheKey("three.example.", dnsmessage.TypeA)); !ok {
		t.Fatal("newly admitted cache entry was evicted")
	}
}

func TestDnsCacheCapacityTrimsImmediatelyAfterRuntimeLimitReduction(t *testing.T) {
	controller := newCapacityTestDnsController(4)
	for _, host := range []string{"one.example", "two.example", "three.example", "four.example"} {
		if err := controller.UpdateDnsCacheTtl(host, dnsmessage.TypeA, nil, nil, nil, 60); err != nil {
			t.Fatalf("UpdateDnsCacheTtl(%q) error = %v", host, err)
		}
	}
	rt := controller.runtime()
	if err := controller.TryUpdateRuntime(&DnsControllerOption{
		MaxCacheSize:         2,
		RouteProjectionEpoch: rt.routeProjectionEpoch,
		NewCache:             rt.newCache,
	}, nil); err != nil {
		t.Fatalf("TryUpdateRuntime() error = %v", err)
	}
	if got := countDnsCacheEntries(controller); got != 2 {
		t.Fatalf("DNS cache entries immediately after limit reduction = %d, want 2", got)
	}
	if err := controller.UpdateDnsCacheTtl("five.example", dnsmessage.TypeA, nil, nil, nil, 60); err != nil {
		t.Fatalf("UpdateDnsCacheTtl() after limit reduction error = %v", err)
	}

	if got := countDnsCacheEntries(controller); got != 2 {
		t.Fatalf("DNS cache entries after limit reduction = %d, want 2", got)
	}
}

func TestDnsCacheCapacityExplicitUnlimited(t *testing.T) {
	controller := newCapacityTestDnsController(0)
	for _, host := range []string{"one.example", "two.example", "three.example"} {
		if err := controller.UpdateDnsCacheTtl(host, dnsmessage.TypeA, nil, nil, nil, 60); err != nil {
			t.Fatalf("UpdateDnsCacheTtl(%q) error = %v", host, err)
		}
	}
	if got := countDnsCacheEntries(controller); got != 3 {
		t.Fatalf("unlimited DNS cache entries = %d, want 3", got)
	}
}

func TestDnsCacheLRUScratchDoesNotRetainCacheSizedPeak(t *testing.T) {
	controller := newCapacityTestDnsController(1)
	controller.putLRUScratch(make([]cacheEntry, 5000))
	if got := cap(controller.lruScratch); got != 0 {
		t.Fatalf("oversized LRU scratch capacity retained = %d, want 0", got)
	}
	controller.putLRUScratch(make([]cacheEntry, 128))
	if got := cap(controller.lruScratch); got != 128 {
		t.Fatalf("small LRU scratch capacity retained = %d, want 128", got)
	}
}

func countDnsCacheEntries(controller *DnsController) int {
	count := 0
	controller.dnsCache.Range(func(_, _ any) bool {
		count++
		return true
	})
	return count
}
