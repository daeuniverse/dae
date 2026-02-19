/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// BenchmarkCacheHit_AsyncBpfUpdate measures cache hit latency with async BPF updates.
func BenchmarkCacheHit_AsyncBpfUpdate(b *testing.B) {
	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)

	var updateCount atomic.Int32

	controller, err := NewDnsController(nil, &DnsControllerOption{
		Log:              log,
		ConcurrencyLimit: 16384,
		CacheAccessCallback: func(cache *DnsCache) error {
			// Simulate BPF update work
			updateCount.Add(1)
			return nil
		},
		NewCache: func(fqdn string, answers []dnsmessage.RR, deadline time.Time, originalDeadline time.Time) (*DnsCache, error) {
			return &DnsCache{
				Answer:           answers,
				Deadline:         deadline,
				OriginalDeadline: originalDeadline,
			}, nil
		},
	})
	if err != nil {
		b.Fatalf("Failed to create controller: %v", err)
	}
	defer controller.Close()

	// Pre-populate cache
	cacheKey := "example.com.A"
	cache := &DnsCache{
		Answer: []dnsmessage.RR{
			&dnsmessage.A{
				Hdr: dnsmessage.RR_Header{
					Name:   "example.com.",
					Rrtype: dnsmessage.TypeA,
					Class:  dnsmessage.ClassINET,
					Ttl:    300,
				},
				A: []byte{1, 2, 3, 4},
			},
		},
		Deadline: time.Now().Add(300 * time.Second),
	}
	controller.dnsCache.Store(cacheKey, cache)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			result := controller.LookupDnsRespCache(cacheKey, false)
			if result == nil {
				b.Error("Expected cache hit")
			}
		}
	})
}

// BenchmarkCacheHit_SlowBpfUpdate measures cache hit latency with slow async BPF updates.
func BenchmarkCacheHit_SlowBpfUpdate(b *testing.B) {
	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)

	controller, err := NewDnsController(nil, &DnsControllerOption{
		Log:              log,
		ConcurrencyLimit: 16384,
		CacheAccessCallback: func(cache *DnsCache) error {
			// Simulate slow BPF update (1ms)
			time.Sleep(time.Millisecond)
			return nil
		},
		NewCache: func(fqdn string, answers []dnsmessage.RR, deadline time.Time, originalDeadline time.Time) (*DnsCache, error) {
			return &DnsCache{
				Answer:           answers,
				Deadline:         deadline,
				OriginalDeadline: originalDeadline,
			}, nil
		},
	})
	if err != nil {
		b.Fatalf("Failed to create controller: %v", err)
	}
	defer controller.Close()

	// Pre-populate cache
	cacheKey := "example.com.A"
	cache := &DnsCache{
		Answer: []dnsmessage.RR{
			&dnsmessage.A{
				Hdr: dnsmessage.RR_Header{
					Name:   "example.com.",
					Rrtype: dnsmessage.TypeA,
					Class:  dnsmessage.ClassINET,
					Ttl:    300,
				},
				A: []byte{1, 2, 3, 4},
			},
		},
		Deadline: time.Now().Add(300 * time.Second),
	}
	controller.dnsCache.Store(cacheKey, cache)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			result := controller.LookupDnsRespCache(cacheKey, false)
			if result == nil {
				b.Error("Expected cache hit")
			}
		}
	})
}

// BenchmarkConcurrencySemaphore_AcquireRelease measures semaphore overhead.
func BenchmarkConcurrencySemaphore_AcquireRelease(b *testing.B) {
	limiter := make(chan struct{}, 16384)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		limiter <- struct{}{}
		<-limiter
	}
}

// BenchmarkConcurrencySemaphore_Parallel measures parallel semaphore acquisition.
func BenchmarkConcurrencySemaphore_Parallel(b *testing.B) {
	limiter := make(chan struct{}, 16384)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			select {
			case limiter <- struct{}{}:
				<-limiter
			default:
				// Would be rejected in real scenario
			}
		}
	})
}

// BenchmarkCacheHitVsMiss compares cache hit vs miss latency.
func BenchmarkCacheHitVsMiss(b *testing.B) {
	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)

	controller, err := NewDnsController(nil, &DnsControllerOption{
		Log:              log,
		ConcurrencyLimit: 16384,
	})
	if err != nil {
		b.Fatalf("Failed to create controller: %v", err)
	}
	defer controller.Close()

	// Pre-populate cache
	cacheKey := "cached.example.com.A"
	cache := &DnsCache{
		Answer: []dnsmessage.RR{
			&dnsmessage.A{
				Hdr: dnsmessage.RR_Header{
					Name:   "cached.example.com.",
					Rrtype: dnsmessage.TypeA,
					Class:  dnsmessage.ClassINET,
					Ttl:    300,
				},
				A: []byte{1, 2, 3, 4},
			},
		},
		Deadline: time.Now().Add(300 * time.Second),
	}
	controller.dnsCache.Store(cacheKey, cache)

	b.Run("Hit", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			controller.LookupDnsRespCache(cacheKey, false)
		}
	})

	b.Run("Miss", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			controller.LookupDnsRespCache("uncached.example.com.A", false)
		}
	})
}

// BenchmarkAsyncBpfUpdate_QueueThroughput measures async queue throughput.
func BenchmarkAsyncBpfUpdate_QueueThroughput(b *testing.B) {
	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)

	controller, err := NewDnsController(nil, &DnsControllerOption{
		Log:              log,
		ConcurrencyLimit: 16384,
		CacheAccessCallback: func(cache *DnsCache) error {
			// Minimal work
			return nil
		},
		NewCache: func(fqdn string, answers []dnsmessage.RR, deadline time.Time, originalDeadline time.Time) (*DnsCache, error) {
			return &DnsCache{
				Answer:           answers,
				Deadline:         deadline,
				OriginalDeadline: originalDeadline,
			}, nil
		},
	})
	if err != nil {
		b.Fatalf("Failed to create controller: %v", err)
	}
	defer controller.Close()

	// Create caches that will trigger route refresh
	caches := make([]*DnsCache, 100)
	for i := range caches {
		caches[i] = &DnsCache{
			Answer: []dnsmessage.RR{
				&dnsmessage.A{
					Hdr: dnsmessage.RR_Header{
						Name:   "example.com.",
						Rrtype: dnsmessage.TypeA,
						Class:  dnsmessage.ClassINET,
						Ttl:    300,
					},
					A: []byte{1, 2, 3, 4},
				},
			},
			Deadline: time.Now().Add(300 * time.Second),
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache := caches[i%len(caches)]
		cacheKey := "domain" + string(rune('0'+i%10)) + ".com.A"
		controller.dnsCache.Store(cacheKey, cache)
		controller.LookupDnsRespCache(cacheKey, false)
	}
}

// BenchmarkHighConcurrency_CacheHit simulates high QPS cache hit scenario.
func BenchmarkHighConcurrency_CacheHit(b *testing.B) {
	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)

	controller, err := NewDnsController(nil, &DnsControllerOption{
		Log:              log,
		ConcurrencyLimit: 16384,
		CacheAccessCallback: func(cache *DnsCache) error {
			return nil
		},
		NewCache: func(fqdn string, answers []dnsmessage.RR, deadline time.Time, originalDeadline time.Time) (*DnsCache, error) {
			return &DnsCache{
				Answer:           answers,
				Deadline:         deadline,
				OriginalDeadline: originalDeadline,
			}, nil
		},
	})
	if err != nil {
		b.Fatalf("Failed to create controller: %v", err)
	}
	defer controller.Close()

	// Pre-populate multiple cache entries
	numCaches := 1000
	cacheKeys := make([]string, numCaches)
	for i := 0; i < numCaches; i++ {
		cacheKeys[i] = "domain" + string(rune('a'+i%26)) + string(rune('a'+(i/26)%26)) + ".com.A"
		cache := &DnsCache{
			Answer: []dnsmessage.RR{
				&dnsmessage.A{
					Hdr: dnsmessage.RR_Header{
						Name:   cacheKeys[i],
						Rrtype: dnsmessage.TypeA,
						Class:  dnsmessage.ClassINET,
						Ttl:    300,
					},
					A: []byte{byte(i % 256), 2, 3, 4},
				},
			},
			Deadline: time.Now().Add(300 * time.Second),
		}
		controller.dnsCache.Store(cacheKeys[i], cache)
	}

	var counter atomic.Int64

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := int(counter.Add(1) - 1)
		for pb.Next() {
			cacheKey := cacheKeys[i%numCaches]
			result := controller.LookupDnsRespCache(cacheKey, false)
			if result == nil {
				b.Error("Expected cache hit")
			}
			i++
		}
	})
}

// BenchmarkComparison_SyncVsAsyncBpf compares sync vs async BPF update latency.
func BenchmarkComparison_SyncVsAsyncBpf(b *testing.B) {
	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)

	cache := &DnsCache{
		Answer: []dnsmessage.RR{
			&dnsmessage.A{
				Hdr: dnsmessage.RR_Header{
					Name:   "example.com.",
					Rrtype: dnsmessage.TypeA,
					Class:  dnsmessage.ClassINET,
					Ttl:    300,
				},
				A: []byte{1, 2, 3, 4},
			},
		},
		Deadline: time.Now().Add(300 * time.Second),
	}

	// Simulated sync callback
	syncCallback := func(c *DnsCache) error {
		time.Sleep(100 * time.Microsecond) // Simulate BPF work
		return nil
	}

	// Async setup
	asyncQueue := make(chan *DnsCache, 256)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range asyncQueue {
			time.Sleep(100 * time.Microsecond)
		}
	}()

	b.Run("Sync", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			syncCallback(cache)
		}
	})

	b.Run("Async", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			select {
			case asyncQueue <- cache:
			default:
				// Drop if full
			}
		}
	})

	close(asyncQueue)
	wg.Wait()
}

// BenchmarkDifferentialBpfUpdate_HashComputation measures hash computation overhead.
func BenchmarkDifferentialBpfUpdate_HashComputation(b *testing.B) {
	cache := &DnsCache{
		DomainBitmap: []uint32{1, 2, 3, 4, 5},
		Answer: []dnsmessage.RR{
			&dnsmessage.A{
				Hdr: dnsmessage.RR_Header{
					Name:   "example.com.",
					Rrtype: dnsmessage.TypeA,
					Class:  dnsmessage.ClassINET,
					Ttl:    300,
				},
				A: []byte{1, 2, 3, 4},
			},
			&dnsmessage.AAAA{
				Hdr: dnsmessage.RR_Header{
					Name:   "example.com.",
					Rrtype: dnsmessage.TypeAAAA,
					Class:  dnsmessage.ClassINET,
					Ttl:    300,
				},
				AAAA: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.ComputeBpfDataHash()
	}
}

// BenchmarkDifferentialBpfUpdate_NeedsUpdate measures update check overhead.
func BenchmarkDifferentialBpfUpdate_NeedsUpdate(b *testing.B) {
	cache := &DnsCache{
		DomainBitmap: []uint32{1, 2, 3, 4, 5},
		Answer: []dnsmessage.RR{
			&dnsmessage.A{
				Hdr: dnsmessage.RR_Header{
					Name:   "example.com.",
					Rrtype: dnsmessage.TypeA,
					Class:  dnsmessage.ClassINET,
					Ttl:    300,
				},
				A: []byte{1, 2, 3, 4},
			},
		},
		Deadline: time.Now().Add(300 * time.Second),
	}

	// Mark as recently updated
	cache.MarkBpfUpdated(time.Now())

	now := time.Now()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.NeedsBpfUpdate(now)
	}
}

// BenchmarkDifferentialBpfUpdate_NeedsUpdate_DataChanged measures check when data changed.
func BenchmarkDifferentialBpfUpdate_NeedsUpdate_DataChanged(b *testing.B) {
	cache := &DnsCache{
		DomainBitmap: []uint32{1, 2, 3, 4, 5},
		Answer: []dnsmessage.RR{
			&dnsmessage.A{
				Hdr: dnsmessage.RR_Header{
					Name:   "example.com.",
					Rrtype: dnsmessage.TypeA,
					Class:  dnsmessage.ClassINET,
					Ttl:    300,
				},
				A: []byte{1, 2, 3, 4},
			},
		},
		Deadline: time.Now().Add(300 * time.Second),
	}

	// Mark as updated in the past (simulate data change scenario)
	cache.MarkBpfUpdated(time.Now().Add(-MinBpfUpdateInterval - time.Second))

	now := time.Now()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.NeedsBpfUpdate(now)
	}
}

// BenchmarkDifferentialVsTimeBased compares differential vs time-based update checks.
func BenchmarkDifferentialVsTimeBased(b *testing.B) {
	cache := &DnsCache{
		DomainBitmap: []uint32{1, 2, 3, 4, 5},
		Answer: []dnsmessage.RR{
			&dnsmessage.A{
				Hdr: dnsmessage.RR_Header{
					Name:   "example.com.",
					Rrtype: dnsmessage.TypeA,
					Class:  dnsmessage.ClassINET,
					Ttl:    300,
				},
				A: []byte{1, 2, 3, 4},
			},
		},
		Deadline: time.Now().Add(300 * time.Second),
	}

	// Mark as recently updated
	cache.MarkBpfUpdated(time.Now())
	now := time.Now()

	b.Run("Differential_SkipUpdate", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			cache.NeedsBpfUpdate(now)
		}
	})

	b.Run("TimeBased_SkipUpdate", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			cache.ShouldRefreshRouteBinding(now, 10*time.Second)
		}
	})
}
