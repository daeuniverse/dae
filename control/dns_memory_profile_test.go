/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// TestDnsController_RealisticMemoryProfile simulates realistic DNS workload
// and measures memory usage to help identify memory leaks
func TestDnsController_RealisticMemoryProfile(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping memory profile test in short mode")
	}

	// Set GC percentage to default for accurate measurement
	debug.SetGCPercent(100)

	runtime.GC()
	runtime.GC()

	var mInitial runtime.MemStats
	runtime.ReadMemStats(&mInitial)
	t.Logf("=== Initial State ===")
	t.Logf("HeapAlloc: %.2f MB, HeapSys: %.2f MB, Sys: %.2f MB",
		float64(mInitial.HeapAlloc)/1024/1024,
		float64(mInitial.HeapSys)/1024/1024,
		float64(mInitial.Sys)/1024/1024)

	// Create DnsController with realistic configuration
	log := logrus.New()
	log.SetLevel(logrus.WarnLevel) // Reduce logging overhead

	controller := &DnsController{
		dnsCache:          sync.Map{},
		dnsForwarderCache: sync.Map{},
		log:               log,
		fixedDomainTtl:    make(map[string]int),
		janitorStop:       make(chan struct{}),
		janitorDone:       make(chan struct{}),
		evictorDone:       make(chan struct{}),
		evictorQ:          make(chan *DnsCache, 512),
	}

	// Start background goroutines
	go controller.startDnsCacheJanitor()
	go controller.startCacheEvictor()

	var mAfterInit runtime.MemStats
	runtime.ReadMemStats(&mAfterInit)
	t.Logf("\n=== After Controller Init ===")
	t.Logf("HeapAlloc: %.2f MB, HeapSys: %.2f MB, Sys: %.2f MB",
		float64(mAfterInit.HeapAlloc)/1024/1024,
		float64(mAfterInit.HeapSys)/1024/1024,
		float64(mAfterInit.Sys)/1024/1024)

	// Phase 1: Simulate realistic DNS cache population
	// Typical production: 5000-20000 unique domains
	const numDomains = 10000
	const numWorkers = 50

	var wg sync.WaitGroup
	var createdCount atomic.Int64

	t.Logf("\n=== Phase 1: Populating %d DNS cache entries ===", numDomains)
	startTime := time.Now()

	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			domainsPerWorker := numDomains / numWorkers
			for i := 0; i < domainsPerWorker; i++ {
				domain := fmt.Sprintf("domain%d.worker%d.test.example.com.", i, workerID)
				cacheKey := controller.cacheKey(domain, dnsmessage.TypeA)

				// Random TTL between 60-300 seconds (realistic)
				ttl := 60 + (workerID+i)%240
				deadline := time.Now().Add(time.Duration(ttl) * time.Second)

				// Create realistic DNS response with multiple answers
				answers := []dnsmessage.RR{
					&dnsmessage.A{
						Hdr: dnsmessage.RR_Header{
							Name:   domain,
							Rrtype: dnsmessage.TypeA,
							Class:  dnsmessage.ClassINET,
							Ttl:    uint32(ttl),
						},
						A: []byte{93, 184, byte((workerID + i) % 256), byte(i % 256)},
					},
				}

				cache := &DnsCache{
					DomainBitmap:     []uint32{uint32(workerID*1000 + i), uint32(workerID*1000 + i + 1)},
					Answer:           answers,
					Deadline:         deadline,
					OriginalDeadline: deadline,
				}

				if err := cache.PrepackResponse(domain, dnsmessage.TypeA); err == nil {
					controller.dnsCache.Store(cacheKey, cache)
					createdCount.Add(1)
				}
			}
		}(w)
	}
	wg.Wait()

	var mAfterPopulate runtime.MemStats
	runtime.ReadMemStats(&mAfterPopulate)
	t.Logf("Populated %d entries in %.2fs", createdCount.Load(), time.Since(startTime).Seconds())
	t.Logf("HeapAlloc: %.2f MB, HeapSys: %.2f MB, Sys: %.2f MB",
		float64(mAfterPopulate.HeapAlloc)/1024/1024,
		float64(mAfterPopulate.HeapSys)/1024/1024,
		float64(mAfterPopulate.Sys)/1024/1024)
	t.Logf("Heap objects: %d", mAfterPopulate.HeapObjects)

	// Phase 2: Simulate realistic DNS query pattern (cache hits)
	// Most queries hit popular domains (80/20 rule)
	t.Logf("\n=== Phase 2: Simulating DNS queries (cache hits) ===")
	const numQueries = 100000
	const queryWorkers = 100

	var hitCount atomic.Int64
	var missCount atomic.Int64

	startTime = time.Now()
	for w := 0; w < queryWorkers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for i := 0; i < numQueries/queryWorkers; i++ {
				// 80% queries hit popular domains (first 20% of domains)
				var domain string
				if i%10 < 8 {
					// Popular domain
					domainIdx := (workerID + i) % (numDomains / 5)
					domain = fmt.Sprintf("domain%d.worker0.test.example.com.", domainIdx)
				} else {
					// Random domain
					domainIdx := (workerID + i) % numDomains
					workerIdx := domainIdx % numWorkers
					domain = fmt.Sprintf("domain%d.worker%d.test.example.com.", domainIdx/numWorkers, workerIdx)
				}

				cacheKey := controller.cacheKey(domain, dnsmessage.TypeA)
				if val, ok := controller.dnsCache.Load(cacheKey); ok {
					cache := val.(*DnsCache)
					// Simulate TTL refresh path
					offset := time.Duration(20+i%30) * time.Second
					now := time.Now().Add(offset)
					if resp := cache.GetPackedResponseWithApproximateTTL(domain, dnsmessage.TypeA, now); resp != nil {
						hitCount.Add(1)
					} else {
						missCount.Add(1)
					}
				} else {
					missCount.Add(1)
				}
			}
		}(w)
	}
	wg.Wait()

	var mAfterQueries runtime.MemStats
	runtime.ReadMemStats(&mAfterQueries)
	t.Logf("Processed %d queries in %.2fs (hits: %d, misses: %d)",
		numQueries, time.Since(startTime).Seconds(), hitCount.Load(), missCount.Load())
	t.Logf("Hit rate: %.1f%%", float64(hitCount.Load())/float64(numQueries)*100)
	t.Logf("HeapAlloc: %.2f MB, HeapSys: %.2f MB, Sys: %.2f MB",
		float64(mAfterQueries.HeapAlloc)/1024/1024,
		float64(mAfterQueries.HeapSys)/1024/1024,
		float64(mAfterQueries.Sys)/1024/1024)

	// Phase 3: Let entries expire and measure memory after GC
	t.Logf("\n=== Phase 3: After GC ===")
	runtime.GC()
	runtime.GC()
	time.Sleep(100 * time.Millisecond)

	var mAfterGC runtime.MemStats
	runtime.ReadMemStats(&mAfterGC)
	t.Logf("HeapAlloc: %.2f MB, HeapSys: %.2f MB, Sys: %.2f MB",
		float64(mAfterGC.HeapAlloc)/1024/1024,
		float64(mAfterGC.HeapSys)/1024/1024,
		float64(mAfterGC.Sys)/1024/1024)
	t.Logf("Heap objects: %d", mAfterGC.HeapObjects)

	// Phase 4: Clear all caches (simulating Close)
	t.Logf("\n=== Phase 4: Clearing all caches ===")
	close(controller.janitorStop)
	<-controller.janitorDone

	controller.dnsCache.Range(func(key, value interface{}) bool {
		controller.dnsCache.Delete(key)
		return true
	})

	runtime.GC()
	runtime.GC()
	time.Sleep(100 * time.Millisecond)

	var mAfterClear runtime.MemStats
	runtime.ReadMemStats(&mAfterClear)
	t.Logf("HeapAlloc: %.2f MB, HeapSys: %.2f MB, Sys: %.2f MB",
		float64(mAfterClear.HeapAlloc)/1024/1024,
		float64(mAfterClear.HeapSys)/1024/1024,
		float64(mAfterClear.Sys)/1024/1024)

	// Summary
	t.Logf("\n=== Memory Summary ===")
	t.Logf("Initial heap:          %.2f MB", float64(mInitial.HeapAlloc)/1024/1024)
	t.Logf("After populate:        %.2f MB (growth: %.2f MB)",
		float64(mAfterPopulate.HeapAlloc)/1024/1024,
		float64(mAfterPopulate.HeapAlloc-mInitial.HeapAlloc)/1024/1024)
	t.Logf("After queries:         %.2f MB", float64(mAfterQueries.HeapAlloc)/1024/1024)
	t.Logf("After GC:              %.2f MB", float64(mAfterGC.HeapAlloc)/1024/1024)
	t.Logf("After clear:           %.2f MB (growth: %.2f MB)",
		float64(mAfterClear.HeapAlloc)/1024/1024,
		float64(mAfterClear.HeapAlloc-mInitial.HeapAlloc)/1024/1024)
	t.Logf("Sys memory:            %.2f MB (from OS)", float64(mAfterClear.Sys)/1024/1024)

	// Memory per cache entry estimation
	memoryGrowth := mAfterPopulate.HeapAlloc - mInitial.HeapAlloc
	bytesPerEntry := float64(memoryGrowth) / float64(createdCount.Load())
	t.Logf("\nEstimated memory per cache entry: %.1f bytes", bytesPerEntry)
}

// TestDnsController_MemoryUnderSustainedLoad simulates sustained DNS pressure
func TestDnsController_MemoryUnderSustainedLoad(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping sustained load test in short mode")
	}

	debug.SetGCPercent(100)
	runtime.GC()
	runtime.GC()

	var mInitial runtime.MemStats
	runtime.ReadMemStats(&mInitial)

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

	// Simulate sustained load with bounded cache size
	// This better reflects real-world scenarios where cache size is limited
	const duration = 5 * time.Second
	const workers = 50
	const maxCacheSize = 5000 // Limit to realistic cache size

	var wg sync.WaitGroup
	stopCh := make(chan struct{})
	var createCount atomic.Int64

	// Worker 1: Create cache entries (bounded)
	wg.Add(1)
	go func() {
		defer wg.Done()
		i := 0
		for {
			select {
			case <-stopCh:
				return
			default:
				// Only create up to maxCacheSize unique domains
				domainIdx := i % maxCacheSize
				domain := fmt.Sprintf("domain%d.sustained.test.", domainIdx)
				cacheKey := controller.cacheKey(domain, dnsmessage.TypeA)

				// Longer TTL (60s) to simulate typical DNS caching
				deadline := time.Now().Add(60 * time.Second)
				answers := []dnsmessage.RR{
					&dnsmessage.A{
						Hdr: dnsmessage.RR_Header{
							Name:   domain,
							Rrtype: dnsmessage.TypeA,
							Class:  dnsmessage.ClassINET,
							Ttl:    60,
						},
						A: []byte{93, 184, 216, byte(domainIdx % 256)},
					},
				}

				cache := &DnsCache{
					DomainBitmap:     []uint32{uint32(domainIdx)},
					Answer:           answers,
					Deadline:         deadline,
					OriginalDeadline: deadline,
				}
				cache.PrepackResponse(domain, dnsmessage.TypeA)
				controller.dnsCache.Store(cacheKey, cache)
				createCount.Add(1)
				i++
			}
		}
	}()

	// Worker 2-N: Access cache entries
	for w := 0; w < workers-1; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			i := 0
			for {
				select {
				case <-stopCh:
					return
				default:
					// Access existing domains
					domainIdx := i % maxCacheSize
					domain := fmt.Sprintf("domain%d.sustained.test.", domainIdx)
					cacheKey := controller.cacheKey(domain, dnsmessage.TypeA)

					if val, ok := controller.dnsCache.Load(cacheKey); ok {
						cache := val.(*DnsCache)
						// Use realistic time offset
						offset := time.Duration(10+i%20) * time.Second
						now := time.Now().Add(offset)
						_ = cache.GetPackedResponseWithApproximateTTL(domain, dnsmessage.TypeA, now)
					}
					i++
				}
			}
		}(w)
	}

	// Monitor memory during sustained load
	ticker := time.NewTicker(500 * time.Millisecond)
	var maxHeap uint64
	var measurements []uint64

	startTime := time.Now()
	for range ticker.C {
		if time.Since(startTime) > duration {
			break
		}

		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		measurements = append(measurements, m.HeapAlloc)
		if m.HeapAlloc > maxHeap {
			maxHeap = m.HeapAlloc
		}
	}

	close(stopCh)
	wg.Wait()

	// Final measurement after cleanup
	runtime.GC()
	runtime.GC()

	var mFinal runtime.MemStats
	runtime.ReadMemStats(&mFinal)

	close(controller.janitorStop)
	<-controller.janitorDone

	t.Logf("=== Sustained Load Memory Analysis ===")
	t.Logf("Duration: %v", duration)
	t.Logf("Cache entries created: %d", createCount.Load())
	t.Logf("Max heap during load: %.2f MB", float64(maxHeap)/1024/1024)
	t.Logf("Final heap after GC:  %.2f MB", float64(mFinal.HeapAlloc)/1024/1024)
	t.Logf("Initial heap:         %.2f MB", float64(mInitial.HeapAlloc)/1024/1024)
	t.Logf("Net growth:           %.2f MB", float64(mFinal.HeapAlloc-mInitial.HeapAlloc)/1024/1024)

	// Calculate memory trend
	if len(measurements) >= 4 {
		firstHalf := measurements[:len(measurements)/2]
		secondHalf := measurements[len(measurements)/2:]

		var firstAvg, secondAvg uint64
		for _, m := range firstHalf {
			firstAvg += m
		}
		for _, m := range secondHalf {
			secondAvg += m
		}
		firstAvg /= uint64(len(firstHalf))
		secondAvg /= uint64(len(secondHalf))

		trend := float64(int64(secondAvg)-int64(firstAvg)) / 1024 / 1024
		t.Logf("Memory trend: %.2f MB (comparing first/second half)", trend)

		// With bounded cache, memory should stabilize
		if trend > 5 { // More than 5MB growth is concerning
			t.Logf("WARNING: Positive memory trend detected, possible leak")
		}
	}

	// Count remaining cache entries
	remaining := 0
	controller.dnsCache.Range(func(key, value interface{}) bool {
		remaining++
		return true
	})
	t.Logf("Remaining cache entries: %d", remaining)
}

// TestDnsController_BaselineMemory measures baseline memory without DNS operations
func TestDnsController_BaselineMemory(t *testing.T) {
	runtime.GC()
	runtime.GC()

	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)
	t.Logf("Empty program: HeapAlloc = %.2f MB", float64(m1.HeapAlloc)/1024/1024)

	// Create empty sync.Map
	var m sync.Map
	runtime.GC()
	var m2 runtime.MemStats
	runtime.ReadMemStats(&m2)
	t.Logf("Empty sync.Map: HeapAlloc = %.2f MB (growth: %.2f KB)",
		float64(m2.HeapAlloc)/1024/1024, float64(m2.HeapAlloc-m1.HeapAlloc)/1024)

	// Add one entry
	m.Store("key", "value")
	runtime.GC()
	var m3 runtime.MemStats
	runtime.ReadMemStats(&m3)
	t.Logf("sync.Map with 1 entry: HeapAlloc = %.2f MB", float64(m3.HeapAlloc)/1024/1024)

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
	_ = controller

	runtime.GC()
	var m4 runtime.MemStats
	runtime.ReadMemStats(&m4)
	t.Logf("Empty DnsController: HeapAlloc = %.2f MB", float64(m4.HeapAlloc)/1024/1024)

	// Create single DnsCache entry
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
		DomainBitmap:     []uint32{1, 2, 3, 4, 5, 6, 7, 8},
		Answer:           answers,
		Deadline:         deadline,
		OriginalDeadline: deadline,
	}
	cache.PrepackResponse("test.example.com.", dnsmessage.TypeA)

	runtime.GC()
	var m5 runtime.MemStats
	runtime.ReadMemStats(&m5)
	singleCacheSize := m5.HeapAlloc - m4.HeapAlloc
	t.Logf("Single DnsCache: HeapAlloc = %.2f MB (entry size: ~%.0f bytes)",
		float64(m5.HeapAlloc)/1024/1024, float64(singleCacheSize))

	// Estimate for different scales
	for _, entries := range []int{1000, 5000, 10000, 50000, 100000} {
		estimated := float64(entries) * float64(singleCacheSize) / 1024 / 1024
		t.Logf("Estimated for %d entries: %.2f MB", entries, estimated)
	}
}

// TestDnsCache_PackedResponseMemoryAllocation measures memory allocated by refresh
func TestDnsCache_PackedResponseMemoryAllocation(t *testing.T) {
	deadline := time.Now().Add(300 * time.Second)
	answers := []dnsmessage.RR{
		&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{
				Name:   "alloc.example.com.",
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

	cache.PrepackResponse("alloc.example.com.", dnsmessage.TypeA)

	// Measure allocations for refresh
	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)

	// Simulate 1000 refreshes (without CAS, this would be a problem)
	for i := 0; i < 1000; i++ {
		offset := time.Duration(30+i%50) * time.Second
		now := time.Now().Add(offset)
		_ = cache.GetPackedResponseWithApproximateTTL("alloc.example.com.", dnsmessage.TypeA, now)
	}

	var m2 runtime.MemStats
	runtime.ReadMemStats(&m2)

	t.Logf("After 1000 access calls:")
	t.Logf("  HeapAlloc growth: %.2f KB", float64(m2.HeapAlloc-m1.HeapAlloc)/1024)
	t.Logf("  Total allocs: %.2f KB", float64(m2.TotalAlloc-m1.TotalAlloc)/1024)

	// With CAS fix, growth should be minimal
	growth := float64(m2.HeapAlloc - m1.HeapAlloc)
	if growth > 50*1024 { // 50KB threshold
		t.Logf("WARNING: Unexpected memory growth: %.2f KB", growth/1024)
	}
}
