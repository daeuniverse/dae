/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/sync/singleflight"
)

// BenchmarkAsyncCacheWithSingleflight measures performance of async caching
// with singleflight protection under various concurrency levels
func BenchmarkAsyncCacheWithSingleflight(b *testing.B) {
	log := logrus.New()
	log.SetLevel(logrus.WarnLevel)
	
	scenarios := []struct {
		name       string
		concurrent int
	}{
		{"1-concurrent", 1},
		{"10-concurrent", 10},
		{"100-concurrent", 100},
		{"1000-concurrent", 1000},
	}
	
	for _, scenario := range scenarios {
		b.Run(scenario.name, func(b *testing.B) {
			controller := &DnsController{
				log: log,
			}
			controller.dnsCache = sync.Map{}
			
			var sf singleflight.Group
			var upstreamCallCount atomic.Int32
			
			b.ResetTimer()
			
			for i := 0; i < b.N; i++ {
				var wg sync.WaitGroup
				
				for j := 0; j < scenario.concurrent; j++ {
					wg.Add(1)
					go func() {
						defer wg.Done()
						
						cacheKey := "example.com1"
						
						// Check cache
						if _, ok := controller.dnsCache.Load(cacheKey); ok {
							return // Cache hit
						}
						
						// Use singleflight
						_, _, _ = sf.Do(cacheKey, func() (interface{}, error) {
							upstreamCallCount.Add(1)
							
							// Simulate upstream
							time.Sleep(10 * time.Millisecond)
							
							// Async cache
							go func() {
								cache := &DnsCache{
									Deadline: time.Now().Add(300 * time.Second),
								}
								controller.dnsCache.Store(cacheKey, cache)
							}()
							
							return nil, nil
						})
					}()
				}
				
				wg.Wait()
				
				// Clear cache for next iteration
				controller.dnsCache.Delete("example.com1")
			}
			
			b.ReportMetric(float64(upstreamCallCount.Load())/float64(b.N), "upstream_calls/op")
		})
	}
}

// BenchmarkAsyncCacheVsSyncCache compares async vs sync caching performance
func BenchmarkAsyncCacheVsSyncCache(b *testing.B) {
	log := logrus.New()
	log.SetLevel(logrus.WarnLevel)
	
	slowCacheDuration := 1 * time.Millisecond // Simulate BPF update
	
	b.Run("AsyncCache", func(b *testing.B) {
		var cache sync.Map
		
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			// Send response (instant)
			
			// Async cache (should not block)
			go func(key int) {
				time.Sleep(slowCacheDuration)
				cache.Store(key, "cached")
			}(i)
		}
	})
	
	b.Run("SyncCache", func(b *testing.B) {
		var cache sync.Map
		
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			// Send response (instant)
			
			// Sync cache (blocks)
			time.Sleep(slowCacheDuration)
			cache.Store(i, "cached")
		}
	})
}

// BenchmarkSingleflightOverhead measures the overhead of singleflight
func BenchmarkSingleflightOverhead(b *testing.B) {
	log := logrus.New()
	log.SetLevel(logrus.WarnLevel)
	
	var sf singleflight.Group
	
	b.Run("WithSingleflight", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				_, _, _ = sf.Do(fmt.Sprintf("key%d", i%10), func() (interface{}, error) {
					return nil, nil
				})
				i++
			}
		})
	})
	
	b.Run("WithoutSingleflight", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				_ = fmt.Sprintf("key%d", i%10)
				i++
			}
		})
	})
}

// BenchmarkRealisticDnsQuery simulates realistic DNS query pattern
// Mix of cache hits and misses, with varying concurrency
func BenchmarkRealisticDnsQuery(b *testing.B) {
	log := logrus.New()
	log.SetLevel(logrus.WarnLevel)
	
	controller := &DnsController{
		log: log,
	}
	controller.dnsCache = sync.Map{}
	
	var sf singleflight.Group
	var upstreamCallCount atomic.Int32
	
	// Pre-populate 50% cache
	domains := make([]string, 100)
	for i := 0; i < 100; i++ {
		domains[i] = fmt.Sprintf("domain%d.com", i)
		if i < 50 {
			cache := &DnsCache{
				Deadline: time.Now().Add(300 * time.Second),
			}
			controller.dnsCache.Store(domains[i]+"1", cache)
		}
	}
	
	b.ResetTimer()
	
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			domain := domains[i%100]
			cacheKey := domain + "1"
			
			// Check cache
			if _, ok := controller.dnsCache.Load(cacheKey); ok {
				// Cache hit
				i++
				continue
			}
			
			// Cache miss - use singleflight
			_, _, _ = sf.Do(cacheKey, func() (interface{}, error) {
				upstreamCallCount.Add(1)
				
				// Simulate upstream (50ms latency)
				time.Sleep(50 * time.Millisecond)
				
				// Async cache
				go func() {
					cache := &DnsCache{
						Deadline: time.Now().Add(300 * time.Second),
					}
					controller.dnsCache.Store(cacheKey, cache)
				}()
				
				return nil, nil
			})
			
			i++
		}
	})
	
	// Calculate cache hit rate
	totalOps := b.N
	hits := totalOps / 2 // Roughly 50% due to pre-population
	hitRate := float64(hits) / float64(totalOps) * 100
	
	b.ReportMetric(hitRate, "cache_hit_rate_%")
	b.ReportMetric(float64(upstreamCallCount.Load()), "total_upstream_calls")
}

// BenchmarkHighQpsScenario tests extreme QPS scenario
func BenchmarkHighQpsScenario(b *testing.B) {
	log := logrus.New()
	log.SetLevel(logrus.WarnLevel)
	
	controller := &DnsController{
		log: log,
	}
	controller.dnsCache = sync.Map{}
	
	var sf singleflight.Group
	var upstreamCallCount atomic.Int32
	var requestCount atomic.Int32
	
	// Simulate 10 unique domains
	domains := []string{"a.com", "b.com", "c.com", "d.com", "e.com", 
		"f.com", "g.com", "h.com", "i.com", "j.com"}
	
	b.ResetTimer()
	
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			reqNum := requestCount.Add(1)
			domain := domains[int(reqNum)%len(domains)]
			cacheKey := domain + "1"
			
			// Check cache
			if _, ok := controller.dnsCache.Load(cacheKey); ok {
				continue // Cache hit
			}
			
			// Cache miss - use singleflight
			_, _, _ = sf.Do(cacheKey, func() (interface{}, error) {
				upstreamCallCount.Add(1)
				
				// Fast upstream (10ms)
				time.Sleep(10 * time.Millisecond)
				
				// Async cache
				go func() {
					cache := &DnsCache{
						Deadline: time.Now().Add(300 * time.Second),
					}
					controller.dnsCache.Store(cacheKey, cache)
				}()
				
				return nil, nil
			})
		}
	})
	
	// Calculate deduplication rate
	upstreamCalls := upstreamCallCount.Load()
	dedupRate := float64(int(b.N)-int(upstreamCalls)) / float64(b.N) * 100
	
	b.ReportMetric(dedupRate, "deduplication_rate_%")
	b.ReportMetric(float64(upstreamCalls), "upstream_calls")
}
