/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@daeuniverse.org>
 */

package control

import (
	"fmt"
	"sync"
	"testing"
	"time"

	dnsmessage "github.com/miekg/dns"
)

// BenchmarkLRUEviction_Current benchmarks the current implementation
// with double traversal (count + collect)
func BenchmarkLRUEviction_Current(b *testing.B) {
	controller := &DnsController{
		optimisticCacheEnabled: true,
		optimisticCacheTtl:     0,
		maxCacheSize:           100,
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
	
	// Pre-populate cache with 1000 entries (10x maxCacheSize)
	for i := 0; i < 1000; i++ {
		domain := fmt.Sprintf("domain%d.example.com.", i)
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
					A: []byte{93, 184, 216, byte(i % 256)},
				},
			},
			Deadline:         now,
			OriginalDeadline: now,
		}
		if err := cache.PrepackResponse(domain, dnsmessage.TypeA); err != nil {
			b.Fatal(err)
		}
		cache.lastAccessNano.Store(now.Add(time.Duration(i) * time.Microsecond).UnixNano())
		controller.dnsCache.Store(domain+":1", cache)
	}

	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		// Reset cache to 1000 entries before each iteration
		if i > 0 {
			for j := 0; j < 1000; j++ {
				domain := fmt.Sprintf("domain%d.example.com.", j)
				controller.dnsCache.Delete(domain + ":1")
			}
			for j := 0; j < 1000; j++ {
				domain := fmt.Sprintf("domain%d.example.com.", j)
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
							A: []byte{93, 184, 216, byte(j % 256)},
						},
					},
					Deadline:         now,
					OriginalDeadline: now,
				}
				if err := cache.PrepackResponse(domain, dnsmessage.TypeA); err != nil {
					b.Fatal(err)
				}
				cache.lastAccessNano.Store(now.Add(time.Duration(j) * time.Microsecond).UnixNano())
				controller.dnsCache.Store(domain+":1", cache)
			}
		}
		
		controller.evictLRUIfFull(now)
	}
}

// BenchmarkLRUEviction_Optimized benchmarks an optimized implementation
// with single traversal
func BenchmarkLRUEviction_Optimized(b *testing.B) {
	controller := &DnsController{
		optimisticCacheEnabled: true,
		optimisticCacheTtl:     0,
		maxCacheSize:           100,
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
	
	// Pre-populate cache with 1000 entries (10x maxCacheSize)
	for i := 0; i < 1000; i++ {
		domain := fmt.Sprintf("domain%d.example.com.", i)
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
					A: []byte{93, 184, 216, byte(i % 256)},
				},
			},
			Deadline:         now,
			OriginalDeadline: now,
		}
		if err := cache.PrepackResponse(domain, dnsmessage.TypeA); err != nil {
			b.Fatal(err)
		}
		cache.lastAccessNano.Store(now.Add(time.Duration(i) * time.Microsecond).UnixNano())
		controller.dnsCache.Store(domain+":1", cache)
	}

	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		// Reset cache to 1000 entries before each iteration
		if i > 0 {
			for j := 0; j < 1000; j++ {
				domain := fmt.Sprintf("domain%d.example.com.", j)
				controller.dnsCache.Delete(domain + ":1")
			}
			for j := 0; j < 1000; j++ {
				domain := fmt.Sprintf("domain%d.example.com.", j)
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
							A: []byte{93, 184, 216, byte(j % 256)},
						},
					},
					Deadline:         now,
					OriginalDeadline: now,
				}
				if err := cache.PrepackResponse(domain, dnsmessage.TypeA); err != nil {
					b.Fatal(err)
				}
				cache.lastAccessNano.Store(now.Add(time.Duration(j) * time.Microsecond).UnixNano())
				controller.dnsCache.Store(domain+":1", cache)
			}
		}
		
		// Optimized: single traversal
		controller.evictLRUIfFull_Optimized(now)
	}
}

// evictLRUIfFull_Optimized is an optimized version with single traversal
func (c *DnsController) evictLRUIfFull_Optimized(now time.Time) {
	type cacheEntry struct {
		key        string
		lastAccess int64
	}
	
	var entries []cacheEntry
	
	// Single traversal: count and collect simultaneously
	c.dnsCache.Range(func(key, value interface{}) bool {
		cacheKey, ok := key.(string)
		if !ok {
			return true
		}
		cache, ok := value.(*DnsCache)
		if !ok {
			return true
		}
		entries = append(entries, cacheEntry{
			key:        cacheKey,
			lastAccess: cache.lastAccessNano.Load(),
		})
		return true
	})
	
	// Check if eviction is needed
	if len(entries) <= c.maxCacheSize {
		return
	}
	
	// Find and evict oldest entries
	numToEvict := len(entries) - c.maxCacheSize
	
	// Sort by last access time (oldest first)
	for i := 1; i < len(entries); i++ {
		for j := i; j > 0 && entries[j].lastAccess < entries[j-1].lastAccess; j-- {
			entries[j], entries[j-1] = entries[j-1], entries[j]
		}
	}
	
	// Evict oldest entries
	evicted := 0
	for _, entry := range entries {
		if evicted >= numToEvict {
			break
		}
		
		if val, ok := c.dnsCache.Load(entry.key); ok {
			if cache, ok := val.(*DnsCache); ok {
				c.evictDnsRespCacheIfSame(entry.key, cache)
				evicted++
			}
		}
	}
}

// BenchmarkLastAccessUpdate benchmarks the overhead of lastAccessNano updates
func BenchmarkLastAccessUpdate(b *testing.B) {
	cache := &DnsCache{
		DomainBitmap: []uint32{1},
		Deadline:     time.Now(),
	}
	
	now := time.Now()
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		cache.lastAccessNano.Store(now.UnixNano())
	}
}

// BenchmarkLastAccessRead benchmarks reading lastAccessNano
func BenchmarkLastAccessRead(b *testing.B) {
	cache := &DnsCache{
		DomainBitmap: []uint32{1},
		Deadline:     time.Now(),
	}
	
	now := time.Now()
	cache.lastAccessNano.Store(now.UnixNano())
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		_ = cache.lastAccessNano.Load()
	}
}

// BenchmarkSyncMapRange benchmarks sync.Map Range performance
func BenchmarkSyncMapRange(b *testing.B) {
	var m sync.Map
	
	// Pre-populate with 1000 entries
	for i := 0; i < 1000; i++ {
		m.Store(fmt.Sprintf("key%d", i), i)
	}
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		count := 0
		m.Range(func(_, _ interface{}) bool {
			count++
			return true
		})
	}
}

// BenchmarkSyncMapRangeWithCollect benchmarks sync.Map Range with collecting data
func BenchmarkSyncMapRangeWithCollect(b *testing.B) {
	var m sync.Map
	
	type entry struct {
		key   string
		value int
	}
	
	// Pre-populate with 1000 entries
	for i := 0; i < 1000; i++ {
		m.Store(fmt.Sprintf("key%d", i), i)
	}
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		var entries []entry
		m.Range(func(key, value interface{}) bool {
			entries = append(entries, entry{
				key:   key.(string),
				value: value.(int),
			})
			return true
		})
	}
}
