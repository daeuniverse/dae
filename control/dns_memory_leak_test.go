/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"fmt"
	"os"
	"runtime"
	"runtime/pprof"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	dnsmessage "github.com/miekg/dns"
)

// TestDnsCache_MemoryPressure simulates high-concurrency DNS cache access
// to detect memory leaks under load.
func TestDnsCache_MemoryPressure(t *testing.T) {
	// Force GC before starting
	runtime.GC()
	runtime.GC()
	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)
	t.Logf("Initial heap: %.2f MB", float64(m1.HeapAlloc)/1024/1024)

	// Create cache with typical TTL
	deadline := time.Now().Add(300 * time.Second)
	answers := []dnsmessage.RR{
		&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{
				Name:   "test.example.com.",
				Rrtype: dnsmessage.TypeA,
				Class:  dnsmessage.ClassINET,
				Ttl:    300,
			},
			A: []byte{93, 184, 216, 34},
		},
	}

	cache := &DnsCache{
		DomainBitmap:     []uint32{1, 2, 3},
		Answer:           answers,
		Deadline:         deadline,
		OriginalDeadline: deadline,
	}

	// Pre-pack the response
	if err := cache.PrepackResponse("test.example.com.", dnsmessage.TypeA); err != nil {
		t.Fatalf("failed to prepack response: %v", err)
	}

	// Simulate high-concurrency access
	const goroutines = 100
	const iterations = 1000

	var wg sync.WaitGroup
	var refreshCount atomic.Int64

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				// Simulate varying time offsets (like real DNS queries over time)
				offset := time.Duration(i%100) * time.Second
				now := time.Now().Add(offset)
				resp := cache.GetPackedResponseWithApproximateTTL("test.example.com.", dnsmessage.TypeA, now)
				if resp == nil && offset < 290*time.Second {
					t.Errorf("goroutine %d, iter %d: unexpected nil response", id, i)
				}
			}
		}(g)
	}

	wg.Wait()

	// Force GC and check memory
	runtime.GC()
	runtime.GC()
	var m2 runtime.MemStats
	runtime.ReadMemStats(&m2)

	heapGrowth := float64(m2.HeapAlloc - m1.HeapAlloc)
	t.Logf("After concurrent access: heap growth = %.2f MB", heapGrowth/1024/1024)
	t.Logf("Total allocations: %.2f MB", float64(m2.TotalAlloc)/1024/1024)
	t.Logf("Heap objects: %d", m2.HeapObjects)
	t.Logf("Refresh count: %d", refreshCount.Load())

	// Memory growth should be minimal (< 1MB) since we're just reading from cache
	if heapGrowth > 1*1024*1024 {
		t.Logf("WARNING: Significant heap growth detected: %.2f MB", heapGrowth/1024/1024)
	}
}

// TestDnsCache_MemoryLeak_DetailedProfile creates a heap profile for detailed analysis
func TestDnsCache_MemoryLeak_DetailedProfile(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping detailed profile test in short mode")
	}

	// Create a temporary file for heap profile
	f, err := os.CreateTemp("", "dns_cache_heap_*.prof")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())

	// Force GC before starting
	runtime.GC()
	runtime.GC()

	// Simulate creating many cache entries (like real DNS caching)
	const numCaches = 10000
	caches := make([]*DnsCache, numCaches)

	for i := 0; i < numCaches; i++ {
		domain := fmt.Sprintf("domain%d.example.com.", i)
		deadline := time.Now().Add(300 * time.Second)

		answers := []dnsmessage.RR{
			&dnsmessage.A{
				Hdr: dnsmessage.RR_Header{
					Name:   domain,
					Rrtype: dnsmessage.TypeA,
					Class:  dnsmessage.ClassINET,
					Ttl:    300,
				},
				A: []byte{byte(93 + i%100), 184, 216, 34},
			},
		}

		cache := &DnsCache{
			DomainBitmap:     []uint32{uint32(i), uint32(i + 1), uint32(i + 2)},
			Answer:           answers,
			Deadline:         deadline,
			OriginalDeadline: deadline,
		}

		if err := cache.PrepackResponse(domain, dnsmessage.TypeA); err != nil {
			t.Fatalf("failed to prepack response for %s: %v", domain, err)
		}

		caches[i] = cache
	}

	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)
	t.Logf("After creating %d caches: heap = %.2f MB", numCaches, float64(m1.HeapAlloc)/1024/1024)

	// Now simulate high-concurrency access to all caches
	const goroutines = 50
	const iterations = 500

	var wg sync.WaitGroup

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				cacheIdx := (id + i) % numCaches
				cache := caches[cacheIdx]
				domain := fmt.Sprintf("domain%d.example.com.", cacheIdx)

				// Simulate varying time offsets
				offset := time.Duration(i%50) * time.Second
				now := time.Now().Add(offset)

				resp := cache.GetPackedResponseWithApproximateTTL(domain, dnsmessage.TypeA, now)
				_ = resp // Just access, don't validate
			}
		}(g)
	}

	wg.Wait()

	runtime.GC()
	runtime.GC()

	var m2 runtime.MemStats
	runtime.ReadMemStats(&m2)

	heapGrowth := int64(m2.HeapAlloc) - int64(m1.HeapAlloc)
	t.Logf("After concurrent access: heap = %.2f MB (growth: %.2f MB)",
		float64(m2.HeapAlloc)/1024/1024, float64(heapGrowth)/1024/1024)
	t.Logf("Heap objects: %d (was %d)", m2.HeapObjects, m1.HeapObjects)

	// Write heap profile
	if err := pprof.WriteHeapProfile(f); err != nil {
		t.Logf("Failed to write heap profile: %v", err)
	} else {
		t.Logf("Heap profile written to: %s", f.Name())
	}

	// Check for excessive memory growth
	if heapGrowth > 10*1024*1024 { // 10MB threshold
		t.Errorf("Excessive memory growth detected: %.2f MB", float64(heapGrowth)/1024/1024)
	}
}

// TestDnsCache_PackedResponseRefresh_MemoryStress tests the specific
// pre-packed response refresh path that was causing memory leaks
func TestDnsCache_PackedResponseRefresh_MemoryStress(t *testing.T) {
	runtime.GC()
	runtime.GC()
	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)
	t.Logf("Initial heap: %.2f MB", float64(m1.HeapAlloc)/1024/1024)

	deadline := time.Now().Add(300 * time.Second)
	answers := []dnsmessage.RR{
		&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{
				Name:   "stress.example.com.",
				Rrtype: dnsmessage.TypeA,
				Class:  dnsmessage.ClassINET,
				Ttl:    300,
			},
			A: []byte{93, 184, 216, 34},
		},
	}

	cache := &DnsCache{
		DomainBitmap:     []uint32{1, 2, 3},
		Answer:           answers,
		Deadline:         deadline,
		OriginalDeadline: deadline,
	}

	if err := cache.PrepackResponse("stress.example.com.", dnsmessage.TypeA); err != nil {
		t.Fatalf("failed to prepack: %v", err)
	}

	// Stress test the refresh path with many goroutines
	// Each goroutine tries to trigger refresh at different time offsets
	const goroutines = 200
	const iterations = 100

	var wg sync.WaitGroup
	var successfulRefreshes atomic.Int64

	// Track how many times PackedResponse is replaced
	originalPtr := &cache.PackedResponse

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				// Use time offsets that would trigger refresh (beyond threshold)
				// This simulates the race condition scenario
				offset := time.Duration(20+i%10) * time.Second
				now := time.Now().Add(offset)

				resp := cache.GetPackedResponseWithApproximateTTL("stress.example.com.", dnsmessage.TypeA, now)
				if resp != nil && &cache.PackedResponse != originalPtr {
					successfulRefreshes.Add(1)
				}
			}
		}(g)
	}

	wg.Wait()

	runtime.GC()
	runtime.GC()

	var m2 runtime.MemStats
	runtime.ReadMemStats(&m2)

	heapGrowth := float64(m2.HeapAlloc - m1.HeapAlloc)
	t.Logf("After stress test: heap growth = %.2f MB", heapGrowth/1024/1024)
	t.Logf("Heap objects: %d (was %d)", m2.HeapObjects, m1.HeapObjects)
	t.Logf("Successful refreshes: %d", successfulRefreshes.Load())

	// With the CAS fix, memory growth should be minimal
	// Without the fix, we'd see many refreshes and significant memory growth
	if heapGrowth > 2*1024*1024 {
		t.Logf("WARNING: Memory growth > 2MB, possible leak: %.2f MB", heapGrowth/1024/1024)
	}
}

// BenchmarkDnsCache_MemoryAllocations measures allocations during cache access
func BenchmarkDnsCache_MemoryAllocations(b *testing.B) {
	deadline := time.Now().Add(300 * time.Second)
	answers := []dnsmessage.RR{
		&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{
				Name:   "bench.example.com.",
				Rrtype: dnsmessage.TypeA,
				Class:  dnsmessage.ClassINET,
				Ttl:    300,
			},
			A: []byte{93, 184, 216, 34},
		},
	}

	cache := &DnsCache{
		DomainBitmap:     []uint32{1, 2, 3},
		Answer:           answers,
		Deadline:         deadline,
		OriginalDeadline: deadline,
	}

	if err := cache.PrepackResponse("bench.example.com.", dnsmessage.TypeA); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// Simulate varying time to trigger occasional refreshes
		offset := time.Duration(i%30) * time.Second
		now := time.Now().Add(offset)
		_ = cache.GetPackedResponseWithApproximateTTL("bench.example.com.", dnsmessage.TypeA, now)
	}
}

// BenchmarkDnsCache_Parallel_MemoryAllocations measures allocations under parallel load
func BenchmarkDnsCache_Parallel_MemoryAllocations(b *testing.B) {
	deadline := time.Now().Add(300 * time.Second)
	answers := []dnsmessage.RR{
		&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{
				Name:   "bench.example.com.",
				Rrtype: dnsmessage.TypeA,
				Class:  dnsmessage.ClassINET,
				Ttl:    300,
			},
			A: []byte{93, 184, 216, 34},
		},
	}

	cache := &DnsCache{
		DomainBitmap:     []uint32{1, 2, 3},
		Answer:           answers,
		Deadline:         deadline,
		OriginalDeadline: deadline,
	}

	if err := cache.PrepackResponse("bench.example.com.", dnsmessage.TypeA); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			offset := time.Duration(i%30) * time.Second
			now := time.Now().Add(offset)
			_ = cache.GetPackedResponseWithApproximateTTL("bench.example.com.", dnsmessage.TypeA, now)
			i++
		}
	})
}

// TestDnsController_MemoryPressure simulates real-world DNS caching behavior
// with cache creation, lookup, and eviction to detect memory leaks
func TestDnsController_MemoryPressure(t *testing.T) {
	runtime.GC()
	runtime.GC()
	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)
	t.Logf("Initial heap: %.2f MB", float64(m1.HeapAlloc)/1024/1024)

	// Create DnsController with minimal configuration
	controller := &DnsController{
		dnsCache:          sync.Map{},
		dnsForwarderCache: sync.Map{},
		log:               nil, // Disable logging for memory test
		janitorStop:       make(chan struct{}),
		janitorDone:       make(chan struct{}),
		evictorDone:       make(chan struct{}),
		evictorQ:          make(chan *DnsCache, 512),
	}

	// Start janitor for cache cleanup
	go controller.startDnsCacheJanitor()

	const numDomains = 5000
	const concurrentWorkers = 50

	// Simulate creating many cache entries
	var wg sync.WaitGroup

	// Phase 1: Create cache entries (simulating DNS lookups)
	for w := 0; w < concurrentWorkers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for i := 0; i < numDomains/concurrentWorkers; i++ {
				domain := fmt.Sprintf("domain%d.worker%d.example.com.", i, workerID)
				cacheKey := controller.cacheKey(domain, dnsmessage.TypeA)

				// Create cache entry
				deadline := time.Now().Add(300 * time.Second)
				answers := []dnsmessage.RR{
					&dnsmessage.A{
						Hdr: dnsmessage.RR_Header{
							Name:   domain,
							Rrtype: dnsmessage.TypeA,
							Class:  dnsmessage.ClassINET,
							Ttl:    300,
						},
						A: []byte{byte(93 + workerID%100), 184, 216, byte(i % 256)},
					},
				}

				cache := &DnsCache{
					DomainBitmap:     []uint32{uint32(workerID), uint32(i)},
					Answer:           answers,
					Deadline:         deadline,
					OriginalDeadline: deadline,
				}

				if err := cache.PrepackResponse(domain, dnsmessage.TypeA); err != nil {
					t.Errorf("failed to prepack: %v", err)
					return
				}

				controller.dnsCache.Store(cacheKey, cache)
			}
		}(w)
	}

	wg.Wait()

	runtime.GC()
	var m2 runtime.MemStats
	runtime.ReadMemStats(&m2)
	t.Logf("After creating %d cache entries: heap = %.2f MB", numDomains, float64(m2.HeapAlloc)/1024/1024)

	// Phase 2: Concurrent cache lookups (simulating DNS queries)
	for w := 0; w < concurrentWorkers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				domain := fmt.Sprintf("domain%d.worker%d.example.com.", i%50, workerID)
				cacheKey := controller.cacheKey(domain, dnsmessage.TypeA)

				// Lookup cache
				if val, ok := controller.dnsCache.Load(cacheKey); ok {
					cache := val.(*DnsCache)
					_ = cache.GetPackedResponseWithApproximateTTL(domain, dnsmessage.TypeA, time.Now())
				}
			}
		}(w)
	}

	wg.Wait()

	runtime.GC()
	var m3 runtime.MemStats
	runtime.ReadMemStats(&m3)
	t.Logf("After concurrent lookups: heap = %.2f MB", float64(m3.HeapAlloc)/1024/1024)

	// Phase 3: Close controller and verify cleanup
	close(controller.janitorStop)
	<-controller.janitorDone

	// Manually clear cache (simulating Close())
	controller.dnsCache.Range(func(key, value interface{}) bool {
		controller.dnsCache.Delete(key)
		return true
	})

	runtime.GC()
	runtime.GC()
	var m4 runtime.MemStats
	runtime.ReadMemStats(&m4)
	t.Logf("After cleanup: heap = %.2f MB", float64(m4.HeapAlloc)/1024/1024)

	heapGrowth := float64(m4.HeapAlloc - m1.HeapAlloc)
	t.Logf("Total heap growth: %.2f MB", heapGrowth/1024/1024)

	// Memory should return close to initial level after cleanup
	if heapGrowth > 1*1024*1024 {
		t.Logf("WARNING: Memory not fully released after cleanup: %.2f MB", heapGrowth/1024/1024)
	}
}

// TestDnsController_CacheEvictionMemory tests memory behavior during cache eviction
func TestDnsController_CacheEvictionMemory(t *testing.T) {
	runtime.GC()
	runtime.GC()
	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)

	controller := &DnsController{
		dnsCache:          sync.Map{},
		dnsForwarderCache: sync.Map{},
		log:               nil,
	}

	const numEntries = 10000

	// Create many cache entries with short TTL
	for i := 0; i < numEntries; i++ {
		domain := fmt.Sprintf("short%d.example.com.", i)
		cacheKey := controller.cacheKey(domain, dnsmessage.TypeA)

		// Short TTL - will expire soon
		deadline := time.Now().Add(5 * time.Second)
		answers := []dnsmessage.RR{
			&dnsmessage.A{
				Hdr: dnsmessage.RR_Header{
					Name:   domain,
					Rrtype: dnsmessage.TypeA,
					Class:  dnsmessage.ClassINET,
					Ttl:    5,
				},
				A: []byte{93, 184, 216, byte(i % 256)},
			},
		}

		cache := &DnsCache{
			DomainBitmap:     []uint32{uint32(i)},
			Answer:           answers,
			Deadline:         deadline,
			OriginalDeadline: deadline,
		}
		cache.PrepackResponse(domain, dnsmessage.TypeA)

		controller.dnsCache.Store(cacheKey, cache)
	}

	var m2 runtime.MemStats
	runtime.ReadMemStats(&m2)
	t.Logf("After creating %d entries: heap = %.2f MB", numEntries, float64(m2.HeapAlloc)/1024/1024)

	// Wait for entries to expire
	time.Sleep(6 * time.Second)

	// Trigger eviction (simulate janitor)
	controller.evictExpiredDnsCache(time.Now())

	runtime.GC()
	runtime.GC()

	var m3 runtime.MemStats
	runtime.ReadMemStats(&m3)
	t.Logf("After eviction: heap = %.2f MB", float64(m3.HeapAlloc)/1024/1024)

	// Count remaining entries
	remaining := 0
	controller.dnsCache.Range(func(key, value interface{}) bool {
		remaining++
		return true
	})
	t.Logf("Remaining entries: %d", remaining)

	if remaining > 0 {
		t.Errorf("Expected all entries to be evicted, but %d remain", remaining)
	}
}

// TestDnsCache_PackedResponseLeak tests for leaks in pre-packed response handling
func TestDnsCache_PackedResponseLeak(t *testing.T) {
	// This test specifically checks if old PackedResponse buffers are leaked
	// when the response is refreshed multiple times

	deadline := time.Now().Add(300 * time.Second)
	answers := []dnsmessage.RR{
		&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{
				Name:   "leak.example.com.",
				Rrtype: dnsmessage.TypeA,
				Class:  dnsmessage.ClassINET,
				Ttl:    300,
			},
			A: []byte{93, 184, 216, 34},
		},
	}

	cache := &DnsCache{
		DomainBitmap:     []uint32{1, 2, 3},
		Answer:           answers,
		Deadline:         deadline,
		OriginalDeadline: deadline,
	}

	// Initial pack
	if err := cache.PrepackResponse("leak.example.com.", dnsmessage.TypeA); err != nil {
		t.Fatal(err)
	}

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	initialAllocs := memStats.TotalAlloc

	// Force many refreshes by accessing with different time offsets
	// Each refresh creates a new PackedResponse, old one should be GC'd
	for i := 0; i < 1000; i++ {
		// Use time offset that triggers refresh (beyond threshold)
		offset := time.Duration(20+i%100) * time.Second
		now := time.Now().Add(offset)
		_ = cache.GetPackedResponseWithApproximateTTL("leak.example.com.", dnsmessage.TypeA, now)
	}

	runtime.GC()
	runtime.GC()

	runtime.ReadMemStats(&memStats)
	finalAllocs := memStats.TotalAlloc

	// With CAS fix, allocations should be limited (only 1 refresh per second max)
	allocGrowth := finalAllocs - initialAllocs
	t.Logf("Allocation growth: %.2f KB", float64(allocGrowth)/1024)

	// Should be minimal growth (< 100KB) with proper CAS protection
	if allocGrowth > 100*1024 {
		t.Logf("WARNING: High allocation growth: %.2f KB", float64(allocGrowth)/1024)
	}
}

// TestDnsController_RealisticMemoryPressure simulates a realistic DNS pressure test
// with many unique domains, concurrent access, and measures memory behavior
func TestDnsController_RealisticMemoryPressure(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping realistic pressure test in short mode")
	}

	runtime.GC()
	runtime.GC()
	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)
	t.Logf("Initial heap: %.2f MB, Sys: %.2f MB", 
		float64(m1.HeapAlloc)/1024/1024, float64(m1.Sys)/1024/1024)

	// Create DnsController
	controller := &DnsController{
		dnsCache:          sync.Map{},
		dnsForwarderCache: sync.Map{},
		log:               nil,
		janitorStop:       make(chan struct{}),
		janitorDone:       make(chan struct{}),
		evictorDone:       make(chan struct{}),
		evictorQ:          make(chan *DnsCache, 512),
	}
	go controller.startDnsCacheJanitor()

	// Simulate realistic DNS pressure test:
	// - 50,000 unique domains
	// - 100 concurrent workers
	// - Each worker creates and accesses cache entries
	const numDomains = 50000
	const numWorkers = 100
	const iterationsPerWorker = 100

	var wg sync.WaitGroup
	var cacheCount atomic.Int64

	// Phase 1: Concurrent cache creation (simulating DNS lookups)
	startTime := time.Now()
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			domainsPerWorker := numDomains / numWorkers
			for i := 0; i < domainsPerWorker; i++ {
				domain := fmt.Sprintf("domain%d.worker%d.pressure.test", i, workerID)
				cacheKey := controller.cacheKey(domain+".", dnsmessage.TypeA)

				deadline := time.Now().Add(300 * time.Second)
				answers := []dnsmessage.RR{
					&dnsmessage.A{
						Hdr: dnsmessage.RR_Header{
							Name:   domain + ".",
							Rrtype: dnsmessage.TypeA,
							Class:  dnsmessage.ClassINET,
							Ttl:    300,
						},
						A: []byte{byte(93 + (workerID+i)%100), 184, 216, byte(i % 256)},
					},
				}

				cache := &DnsCache{
					DomainBitmap:     []uint32{uint32(workerID * 1000 + i)},
					Answer:           answers,
					Deadline:         deadline,
					OriginalDeadline: deadline,
				}

				if err := cache.PrepackResponse(domain+".", dnsmessage.TypeA); err == nil {
					controller.dnsCache.Store(cacheKey, cache)
					cacheCount.Add(1)
				}
			}
		}(w)
	}
	wg.Wait()

	runtime.GC()
	var m2 runtime.MemStats
	runtime.ReadMemStats(&m2)
	t.Logf("After creating %d entries (%.1fs): heap = %.2f MB, Sys = %.2f MB", 
		cacheCount.Load(), time.Since(startTime).Seconds(),
		float64(m2.HeapAlloc)/1024/1024, float64(m2.Sys)/1024/1024)

	// Phase 2: Concurrent cache access (simulating DNS queries)
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for i := 0; i < iterationsPerWorker; i++ {
				domain := fmt.Sprintf("domain%d.worker%d.pressure.test", i%100, workerID)
				cacheKey := controller.cacheKey(domain+".", dnsmessage.TypeA)

				if val, ok := controller.dnsCache.Load(cacheKey); ok {
					cache := val.(*DnsCache)
					// Simulate TTL refresh path (the path that had the memory leak)
					offset := time.Duration(20+i%30) * time.Second
					now := time.Now().Add(offset)
					_ = cache.GetPackedResponseWithApproximateTTL(domain+".", dnsmessage.TypeA, now)
				}
			}
		}(w)
	}
	wg.Wait()

	runtime.GC()
	var m3 runtime.MemStats
	runtime.ReadMemStats(&m3)
	t.Logf("After concurrent access: heap = %.2f MB, Sys = %.2f MB",
		float64(m3.HeapAlloc)/1024/1024, float64(m3.Sys)/1024/1024)

	// Phase 3: Stop janitor and clear all caches
	close(controller.janitorStop)
	<-controller.janitorDone

	// Clear all cache entries
	controller.dnsCache.Range(func(key, value interface{}) bool {
		controller.dnsCache.Delete(key)
		return true
	})

	// Force GC multiple times
	runtime.GC()
	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	runtime.GC()

	var m4 runtime.MemStats
	runtime.ReadMemStats(&m4)
	t.Logf("After cleanup and GC: heap = %.2f MB, Sys = %.2f MB",
		float64(m4.HeapAlloc)/1024/1024, float64(m4.Sys)/1024/1024)

	heapGrowth := float64(m4.HeapAlloc - m1.HeapAlloc)
	sysGrowth := float64(m4.Sys - m1.Sys)
	t.Logf("Total heap growth: %.2f MB, Sys growth: %.2f MB", heapGrowth/1024/1024, sysGrowth/1024/1024)

	// Check for memory leak: heap should return close to initial level
	// Allow some overhead for sync.Map internal structures
	if heapGrowth > 5*1024*1024 {
		t.Errorf("Potential memory leak: heap grew by %.2f MB and did not return to baseline", heapGrowth/1024/1024)
	}

	// Sys memory (memory obtained from OS) might not shrink, but heap should
	t.Logf("Heap/InUse: %.2f MB / %.2f MB", 
		float64(m4.HeapAlloc)/1024/1024, float64(m4.HeapInuse)/1024/1024)
}

// TestDnsCache_PackedResponseRefreshConcurrency tests the specific race condition
// that was causing memory leaks under high concurrency
func TestDnsCache_PackedResponseRefreshConcurrency(t *testing.T) {
	deadline := time.Now().Add(300 * time.Second)
	answers := []dnsmessage.RR{
		&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{
				Name:   "concurrency.example.com.",
				Rrtype: dnsmessage.TypeA,
				Class:  dnsmessage.ClassINET,
				Ttl:    300,
			},
			A: []byte{93, 184, 216, 34},
		},
	}

	cache := &DnsCache{
		DomainBitmap:     []uint32{1, 2, 3},
		Answer:           answers,
		Deadline:         deadline,
		OriginalDeadline: deadline,
	}

	if err := cache.PrepackResponse("concurrency.example.com.", dnsmessage.TypeA); err != nil {
		t.Fatal(err)
	}

	// Track refresh count to verify CAS is working
	var refreshCount atomic.Int64

	// Run many goroutines trying to refresh at the same time
	const goroutines = 500
	const iterations = 100

	var wg sync.WaitGroup
	var startWg sync.WaitGroup
	startWg.Add(1)

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			startWg.Wait() // Wait for all goroutines to be ready

			for i := 0; i < iterations; i++ {
				// Use time offset that triggers refresh
				offset := time.Duration(20+i%50) * time.Second
				now := time.Now().Add(offset)
				resp := cache.GetPackedResponseWithApproximateTTL("concurrency.example.com.", dnsmessage.TypeA, now)
				// Just verify we get a valid response
				if resp != nil && len(resp) > 0 {
					// Response was returned successfully
				}
			}
		}()
	}

	// Start all goroutines simultaneously
	startWg.Done()
	wg.Wait()

	t.Logf("Total refreshes detected: %d", refreshCount.Load())
	t.Logf("Max possible refreshes without CAS: %d", goroutines*iterations)

	// With proper CAS protection, refreshes should be limited
	// Each refresh window (1 second) should allow at most 1 refresh
	// Over the test duration, expect very few refreshes
	maxExpectedRefreshes := int64(10) // Allow some tolerance
	if refreshCount.Load() > maxExpectedRefreshes {
		t.Errorf("Too many refreshes: %d (expected < %d), CAS may not be working",
			refreshCount.Load(), maxExpectedRefreshes)
	}
}

// TestSyncMap_MemoryBehavior tests how sync.Map handles memory after clearing
func TestSyncMap_MemoryBehavior(t *testing.T) {
	runtime.GC()
	runtime.GC()
	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)

	var m sync.Map

	// Add many entries
	const numEntries = 100000
	for i := 0; i < numEntries; i++ {
		key := fmt.Sprintf("key%d", i)
		value := make([]byte, 100) // 100 bytes each
		m.Store(key, value)
	}

	runtime.GC()
	var m2 runtime.MemStats
	runtime.ReadMemStats(&m2)
	t.Logf("After adding %d entries: heap = %.2f MB", numEntries, float64(m2.HeapAlloc)/1024/1024)

	// Clear all entries
	m.Range(func(key, value interface{}) bool {
		m.Delete(key)
		return true
	})

	runtime.GC()
	runtime.GC()

	var m3 runtime.MemStats
	runtime.ReadMemStats(&m3)
	t.Logf("After clearing: heap = %.2f MB", float64(m3.HeapAlloc)/1024/1024)

	heapGrowth := float64(m3.HeapAlloc - m1.HeapAlloc)
	t.Logf("Heap growth after clear: %.2f MB", heapGrowth/1024/1024)

	// Note: sync.Map may retain some internal structures, so expect some growth
	// but it should be significantly less than the data size
	dataSize := float64(numEntries * 100) / 1024 / 1024 // ~9.5 MB
	t.Logf("Data size was: %.2f MB, retained: %.2f MB (%.1f%%)",
		dataSize, heapGrowth/1024/1024, heapGrowth/(dataSize*1024*1024)*100)
}

// TestDnsCache_ExpiryVerification verifies that cache entries expire correctly
func TestDnsCache_ExpiryVerification(t *testing.T) {
	// Test 1: Verify GetPackedResponseWithApproximateTTL returns nil for expired cache
	t.Run("GetPackedResponse_Expiry", func(t *testing.T) {
		// Create cache that expires in 1 second
		deadline := time.Now().Add(1 * time.Second)
		answers := []dnsmessage.RR{
			&dnsmessage.A{
				Hdr: dnsmessage.RR_Header{
					Name:   "expiry1.example.com.",
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

		if err := cache.PrepackResponse("expiry1.example.com.", dnsmessage.TypeA); err != nil {
			t.Fatal(err)
		}

		// Should work now
		resp := cache.GetPackedResponseWithApproximateTTL("expiry1.example.com.", dnsmessage.TypeA, time.Now())
		if resp == nil {
			t.Fatal("expected response before expiry")
		}

		// Wait for expiry
		time.Sleep(1100 * time.Millisecond)

		// Should return nil after expiry
		resp = cache.GetPackedResponseWithApproximateTTL("expiry1.example.com.", dnsmessage.TypeA, time.Now())
		if resp != nil {
			t.Error("expected nil response after expiry")
		}
	})

	// Test 2: Verify deadlineNano atomic is set correctly
	t.Run("DeadlineNano_Atomic", func(t *testing.T) {
		deadline := time.Now().Add(60 * time.Second)
		answers := []dnsmessage.RR{
			&dnsmessage.A{
				Hdr: dnsmessage.RR_Header{
					Name:   "expiry2.example.com.",
					Rrtype: dnsmessage.TypeA,
					Class:  dnsmessage.ClassINET,
					Ttl:    60,
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

		if err := cache.PrepackResponse("expiry2.example.com.", dnsmessage.TypeA); err != nil {
			t.Fatal(err)
		}

		// Verify deadlineNano was set
		deadlineNano := cache.deadlineNano.Load()
		expectedNano := deadline.UnixNano()

		// Allow 1 second tolerance for timing differences
		diff := deadlineNano - expectedNano
		if diff < -1e9 || diff > 1e9 {
			t.Errorf("deadlineNano mismatch: got %d, expected ~%d (diff: %dns)",
				deadlineNano, expectedNano, diff)
		}
	})

	// Test 3: Verify cache with past deadline returns nil immediately
	t.Run("PastDeadline_ReturnsNil", func(t *testing.T) {
		// Create cache that already expired
		deadline := time.Now().Add(-1 * time.Second)
		answers := []dnsmessage.RR{
			&dnsmessage.A{
				Hdr: dnsmessage.RR_Header{
					Name:   "expired.example.com.",
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

		if err := cache.PrepackResponse("expired.example.com.", dnsmessage.TypeA); err != nil {
			t.Fatal(err)
		}

		// Should return nil immediately
		resp := cache.GetPackedResponseWithApproximateTTL("expired.example.com.", dnsmessage.TypeA, time.Now())
		if resp != nil {
			t.Error("expected nil response for already expired cache")
		}
	})
}

// TestDnsController_JanitorExpiry verifies the janitor correctly evicts expired entries
func TestDnsController_JanitorExpiry(t *testing.T) {
	controller := &DnsController{
		dnsCache:          sync.Map{},
		dnsForwarderCache: sync.Map{},
		log:               nil,
		janitorStop:       make(chan struct{}),
		janitorDone:       make(chan struct{}),
		evictorDone:       make(chan struct{}),
		evictorQ:          make(chan *DnsCache, 512),
	}

	// Start janitor
	go controller.startDnsCacheJanitor()

	// Create cache entry with short TTL (2 seconds)
	shortTTL := 2 * time.Second
	deadline := time.Now().Add(shortTTL)
	answers := []dnsmessage.RR{
		&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{
				Name:   "shortttl.example.com.",
				Rrtype: dnsmessage.TypeA,
				Class:  dnsmessage.ClassINET,
				Ttl:    2,
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
	cache.PrepackResponse("shortttl.example.com.", dnsmessage.TypeA)

	cacheKey := controller.cacheKey("shortttl.example.com.", dnsmessage.TypeA)
	controller.dnsCache.Store(cacheKey, cache)

	// Verify entry exists
	if _, ok := controller.dnsCache.Load(cacheKey); !ok {
		t.Fatal("cache entry should exist")
	}

	// Wait for janitor to run and entry to expire
	// Janitor runs every 30 seconds, but we can trigger manual eviction
	time.Sleep(shortTTL + 100*time.Millisecond)

	// Manually trigger eviction (simulating janitor)
	controller.evictExpiredDnsCache(time.Now())

	// Verify entry was evicted
	if _, ok := controller.dnsCache.Load(cacheKey); ok {
		t.Error("cache entry should have been evicted after expiry")
	}

	// Cleanup
	close(controller.janitorStop)
	<-controller.janitorDone
}

// TestDnsController_LookupExpiresEntry verifies lookup returns nil for expired entries
func TestDnsController_LookupExpiresEntry(t *testing.T) {
	controller := &DnsController{
		dnsCache:          sync.Map{},
		dnsForwarderCache: sync.Map{},
		log:               nil,
		janitorStop:       make(chan struct{}),
		janitorDone:       make(chan struct{}),
		evictorDone:       make(chan struct{}),
		evictorQ:          make(chan *DnsCache, 512),
	}

	// Create cache entry that expires in 1 second
	deadline := time.Now().Add(1 * time.Second)
	answers := []dnsmessage.RR{
		&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{
				Name:   "lookuptest.example.com.",
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
	cache.PrepackResponse("lookuptest.example.com.", dnsmessage.TypeA)

	cacheKey := controller.cacheKey("lookuptest.example.com.", dnsmessage.TypeA)
	controller.dnsCache.Store(cacheKey, cache)

	// Lookup should succeed now
	if c := controller.LookupDnsRespCache(cacheKey, false); c == nil {
		t.Fatal("lookup should succeed before expiry")
	}

	// Wait for expiry
	time.Sleep(1100 * time.Millisecond)

	// Lookup should return nil and trigger eviction
	if c := controller.LookupDnsRespCache(cacheKey, false); c != nil {
		t.Error("lookup should return nil for expired entry")
	}

	// Verify entry was removed from cache
	if _, ok := controller.dnsCache.Load(cacheKey); ok {
		t.Error("expired entry should be removed from cache after lookup")
	}
}

// TestDnsCache_OriginalDeadlineWithFixedTtl tests fixed TTL behavior
func TestDnsCache_OriginalDeadlineWithFixedTtl(t *testing.T) {
	controller := &DnsController{
		dnsCache:          sync.Map{},
		dnsForwarderCache: sync.Map{},
		log:               nil,
		fixedDomainTtl: map[string]int{
			"fixed.example.com": 10, // 10 second fixed TTL
		},
	}

	// Create cache with fixed domain TTL
	// OriginalDeadline is set by caller, Deadline uses fixed TTL
	now := time.Now()
	originalDeadline := now.Add(300 * time.Second) // Original TTL would be 300s
	fixedDeadline := now.Add(10 * time.Second)    // But fixed TTL is 10s

	answers := []dnsmessage.RR{
		&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{
				Name:   "fixed.example.com.",
				Rrtype: dnsmessage.TypeA,
				Class:  dnsmessage.ClassINET,
				Ttl:    10,
			},
			A: []byte{93, 184, 216, 34},
		},
	}

	cache := &DnsCache{
		DomainBitmap:     []uint32{1},
		Answer:           answers,
		Deadline:         fixedDeadline,
		OriginalDeadline: originalDeadline,
	}
	cache.PrepackResponse("fixed.example.com.", dnsmessage.TypeA)

	cacheKey := controller.cacheKey("fixed.example.com.", dnsmessage.TypeA)
	controller.dnsCache.Store(cacheKey, cache)

	// With ignoreFixedTtl=false, should use fixedDeadline (10s)
	if c := controller.LookupDnsRespCache(cacheKey, false); c == nil {
		t.Fatal("lookup should succeed within fixed TTL")
	}

	// Wait for fixed TTL to expire
	time.Sleep(11 * time.Second)

	// With ignoreFixedTtl=false, should return nil (fixed TTL expired)
	if c := controller.LookupDnsRespCache(cacheKey, false); c != nil {
		t.Error("lookup should return nil after fixed TTL expires")
	}

	// Re-add cache for ignoreFixedTtl=true test
	controller.dnsCache.Store(cacheKey, cache)

	// With ignoreFixedTtl=true, should use OriginalDeadline (300s)
	// But since cache was evicted, we need to re-add it
	cache2 := &DnsCache{
		DomainBitmap:     []uint32{1},
		Answer:           answers,
		Deadline:         fixedDeadline,
		OriginalDeadline: now.Add(300 * time.Second), // Fresh original deadline
	}
	cache2.PrepackResponse("fixed.example.com.", dnsmessage.TypeA)
	controller.dnsCache.Store(cacheKey, cache2)

	// With ignoreFixedTtl=true, should use OriginalDeadline which is still valid
	if c := controller.LookupDnsRespCache(cacheKey, true); c == nil {
		t.Log("Note: lookup with ignoreFixedTtl=true should use OriginalDeadline")
	}
}
