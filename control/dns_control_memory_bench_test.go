/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	dnsmessage "github.com/miekg/dns"
)

func BenchmarkDnsController_OnDnsCacheEvicted_Spill(b *testing.B) {
	controller := &DnsController{
		cacheRemoveCallback: func(cache *DnsCache) error { return nil },
		evictorQ:            make(chan *DnsCache, 1),
		evictorWake:         make(chan struct{}, 1),
	}
	// Keep the primary queue full so the benchmark exercises the spill path.
	controller.evictorQ <- &DnsCache{}

	cache := &DnsCache{}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		controller.onDnsCacheEvicted(cache)
		if (i+1)%1024 == 0 {
			b.StopTimer()
			controller.drainEvictorSpill()
			b.StartTimer()
		}
	}

	b.StopTimer()
	controller.drainEvictorSpill()
}

func BenchmarkStaleDnsSideEffects_SharedIp(b *testing.B) {
	prev := &DnsCache{
		Answer: []dnsmessage.RR{
			benchmarkARecord("bench.example.", "1.1.1.1"),
			benchmarkARecord("bench.example.", "2.2.2.2"),
		},
	}
	next := &DnsCache{
		Answer: []dnsmessage.RR{
			benchmarkARecord("bench.example.", "2.2.2.2"),
			benchmarkARecord("bench.example.", "3.3.3.3"),
		},
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		cache := staleDnsSideEffects(prev, next)
		if cache == nil || len(cache.Answer) != 1 {
			b.Fatal("expected exactly one stale IP answer")
		}
	}
}

func BenchmarkDnsController_UpdateDnsCacheTtl_Replace(b *testing.B) {
	controller := &DnsController{
		cacheAccessCallback: func(cache *DnsCache) error { return nil },
		cacheRemoveCallback: func(cache *DnsCache) error { return nil },
		newCache: func(fqdn string, answers, ns, extra []dnsmessage.RR, deadline time.Time, originalDeadline time.Time) (*DnsCache, error) {
			return &DnsCache{
				Answer:           answers,
				NS:               ns,
				Extra:            extra,
				Deadline:         deadline,
				OriginalDeadline: originalDeadline,
			}, nil
		},
		dnsCache: sync.Map{},
	}

	answerSetA := []dnsmessage.RR{
		benchmarkARecord("bench.example.", "1.1.1.1"),
		benchmarkARecord("bench.example.", "2.2.2.2"),
	}
	answerSetB := []dnsmessage.RR{
		benchmarkARecord("bench.example.", "2.2.2.2"),
		benchmarkARecord("bench.example.", "3.3.3.3"),
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		answers := answerSetA
		if i&1 == 1 {
			answers = answerSetB
		}
		if err := controller.UpdateDnsCacheTtl("bench.example.", dnsmessage.TypeA, answers, nil, nil, 60); err != nil {
			b.Fatalf("UpdateDnsCacheTtl failed: %v", err)
		}
	}
}

func BenchmarkDnsController_EvictLRUIfFull(b *testing.B) {
	const maxCacheSize = 1024
	const extraKeys = maxCacheSize * 4

	controller := &DnsController{
		maxCacheSize: maxCacheSize,
		dnsCache:     sync.Map{},
	}

	keys := make([]string, maxCacheSize+extraKeys)
	caches := make([]*DnsCache, maxCacheSize+extraKeys)
	for i := range keys {
		domain := "lru-" + strconv.Itoa(i) + ".example.com."
		keys[i] = domain + ":1"
		caches[i] = &DnsCache{
			Answer: []dnsmessage.RR{
				benchmarkARecord(domain, "10.0.0.1"),
			},
		}
		caches[i].lastAccessNano.Store(int64(i + 1))
	}

	for i := 0; i < maxCacheSize; i++ {
		controller.dnsCache.Store(keys[i], caches[i])
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		b.StopTimer()
		idx := maxCacheSize + (i % extraKeys)
		caches[idx].lastAccessNano.Store(int64(maxCacheSize + i + 1))
		controller.dnsCache.Store(keys[idx], caches[idx])
		b.StartTimer()
		controller.evictLRUIfFull()
	}
}

func benchmarkARecord(name, ip string) *dnsmessage.A {
	return &dnsmessage.A{
		Hdr: dnsmessage.RR_Header{
			Name:   name,
			Rrtype: dnsmessage.TypeA,
			Class:  dnsmessage.ClassINET,
			Ttl:    60,
		},
		A: net.ParseIP(ip).To4(),
	}
}
