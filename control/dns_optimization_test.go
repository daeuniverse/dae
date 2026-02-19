/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// TestSingleflight_CacheHitNotBlocked verifies that cache hits
// are not blocked by slow singleflight requests.
func TestSingleflight_CacheHitNotBlocked(t *testing.T) {
	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)

	var bpfUpdateCount atomic.Int32
	var bpfUpdateBlockTime time.Duration = 100 * time.Millisecond

	controller, err := NewDnsController(nil, &DnsControllerOption{
		Log:              log,
		ConcurrencyLimit: 100,
		CacheAccessCallback: func(cache *DnsCache) error {
			// Simulate slow BPF update
			time.Sleep(bpfUpdateBlockTime)
			bpfUpdateCount.Add(1)
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
		t.Fatalf("Failed to create controller: %v", err)
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

	// Trigger route binding refresh (this should be async)
	start := time.Now()
	result := controller.LookupDnsRespCache(cacheKey, false)
	elapsed := time.Since(start)

	// Cache hit should return immediately (not blocked by async BPF update)
	if result == nil {
		t.Error("Expected cache hit, got nil")
	}

	// The lookup should complete much faster than the BPF update time
	// Async update means lookup returns immediately
	if elapsed > 50*time.Millisecond {
		t.Errorf("Cache hit took too long: %v (expected < 50ms, BPF update takes %v)", elapsed, bpfUpdateBlockTime)
	}

	t.Logf("Cache hit latency: %v (async BPF update takes %v)", elapsed, bpfUpdateBlockTime)
}

// TestAsyncBpfUpdate_NonBlocking verifies that BPF updates don't block DNS queries.
func TestAsyncBpfUpdate_NonBlocking(t *testing.T) {
	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)

	var updateCount atomic.Int32
	var slowUpdateTime time.Duration = 200 * time.Millisecond

	controller, err := NewDnsController(nil, &DnsControllerOption{
		Log:              log,
		ConcurrencyLimit: 100,
		CacheAccessCallback: func(cache *DnsCache) error {
			time.Sleep(slowUpdateTime)
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
		t.Fatalf("Failed to create controller: %v", err)
	}
	defer controller.Close()

	// Create multiple cache entries and trigger updates
	numCaches := 10
	var wg sync.WaitGroup

	start := time.Now()
	for i := 0; i < numCaches; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			cacheKey := "domain" + string(rune('0'+idx)) + ".com.A"
			cache := &DnsCache{
				Answer: []dnsmessage.RR{
					&dnsmessage.A{
						Hdr: dnsmessage.RR_Header{
							Name:   cacheKey,
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

			// Lookup should trigger async update
			controller.LookupDnsRespCache(cacheKey, false)
		}(i)
	}
	wg.Wait()
	elapsed := time.Since(start)

	// All lookups should complete much faster than sequential BPF updates
	// With async updates, total time should be < slowUpdateTime, not numCaches * slowUpdateTime
	if elapsed > slowUpdateTime {
		t.Errorf("Lookups took too long: %v (expected < %v with async updates)", elapsed, slowUpdateTime)
	}

	t.Logf("%d lookups completed in %v (async, each BPF update takes %v)", numCaches, elapsed, slowUpdateTime)
}

// TestConcurrencyLimit_DefaultValue verifies the default concurrency limit is 16384.
func TestConcurrencyLimit_DefaultValue(t *testing.T) {
	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)

	// Test default (ConcurrencyLimit = 0)
	controller, err := NewDnsController(nil, &DnsControllerOption{
		Log:              log,
		ConcurrencyLimit: 0, // Should use default 16384
	})
	if err != nil {
		t.Fatalf("Failed to create controller: %v", err)
	}
	defer controller.Close()

	// Verify the channel capacity is 16384
	capacity := cap(controller.concurrencyLimiter)
	expectedCapacity := 16384
	if capacity != expectedCapacity {
		t.Errorf("Expected concurrency limit %d, got %d", expectedCapacity, capacity)
	}
}

// TestConcurrencyLimit_CustomValue verifies custom concurrency limit works.
func TestConcurrencyLimit_CustomValue(t *testing.T) {
	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)

	customLimit := 4096
	controller, err := NewDnsController(nil, &DnsControllerOption{
		Log:              log,
		ConcurrencyLimit: customLimit,
	})
	if err != nil {
		t.Fatalf("Failed to create controller: %v", err)
	}
	defer controller.Close()

	capacity := cap(controller.concurrencyLimiter)
	if capacity != customLimit {
		t.Errorf("Expected concurrency limit %d, got %d", customLimit, capacity)
	}
}

// TestConcurrencyLimit_Reject verifies that queries are rejected when limit exceeded.
func TestConcurrencyLimit_Reject(t *testing.T) {
	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)

	// Small limit for testing
	smallLimit := 2
	controller, err := NewDnsController(nil, &DnsControllerOption{
		Log:              log,
		ConcurrencyLimit: smallLimit,
	})
	if err != nil {
		t.Fatalf("Failed to create controller: %v", err)
	}
	defer controller.Close()

	// Fill up the semaphore
	for i := 0; i < smallLimit; i++ {
		controller.concurrencyLimiter <- struct{}{}
	}

	// Create a DNS message
	msg := new(dnsmessage.Msg)
	msg.SetQuestion("example.com.", dnsmessage.TypeA)

	// Try to handle - should be rejected
	err = controller.Handle_(context.Background(), msg, nil)
	if err != ErrDNSQueryConcurrencyLimitExceeded {
		t.Errorf("Expected ErrDNSQueryConcurrencyLimitExceeded, got: %v", err)
	}

	// Release one slot
	<-controller.concurrencyLimiter

	// Now it should work (though it will fail due to no routing)
	err = controller.Handle_(context.Background(), msg, nil)
	if err == ErrDNSQueryConcurrencyLimitExceeded {
		t.Error("Should not be rejected after releasing slot")
	}
}

// TestAsyncBpfUpdate_QueueFull verifies behavior when async queue is full.
func TestAsyncBpfUpdate_QueueFull(t *testing.T) {
	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)

	var processedCount atomic.Int32
	var blockProcessed atomic.Bool
	blockProcessed.Store(true)

	// Create controller with a slow callback that blocks
	controller, err := NewDnsController(nil, &DnsControllerOption{
		Log:              log,
		ConcurrencyLimit: 100,
		CacheAccessCallback: func(cache *DnsCache) error {
			// Block until we allow processing
			for blockProcessed.Load() {
				time.Sleep(10 * time.Millisecond)
			}
			processedCount.Add(1)
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
		t.Fatalf("Failed to create controller: %v", err)
	}
	defer controller.Close()

	// Create many caches to fill the queue (queue size is 256)
	// When queue is full, updates should be dropped without blocking
	numCaches := 300 // More than queue size
	start := time.Now()

	for i := 0; i < numCaches; i++ {
		cacheKey := "domain" + string(rune('0'+i%10)) + ".com.A"
		cache := &DnsCache{
			Answer: []dnsmessage.RR{
				&dnsmessage.A{
					Hdr: dnsmessage.RR_Header{
						Name:   cacheKey,
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

		// This should not block even when queue is full
		result := controller.LookupDnsRespCache(cacheKey, false)
		if result == nil {
			t.Errorf("Cache hit should return immediately: %s", cacheKey)
		}
	}
	elapsed := time.Since(start)

	// All lookups should complete quickly despite full queue
	if elapsed > 100*time.Millisecond {
		t.Errorf("Lookups took too long with full queue: %v", elapsed)
	}

	t.Logf("%d lookups completed in %v (queue size 256, callback blocked)", numCaches, elapsed)

	// Unblock the processor and let it finish
	blockProcessed.Store(false)
}

// TestDifferentialBpfUpdate_DataUnchanged verifies that BPF updates are skipped
// when data hasn't changed.
func TestDifferentialBpfUpdate_DataUnchanged(t *testing.T) {
	// Create a cache with some data
	cache := &DnsCache{
		DomainBitmap: []uint32{1, 2, 3},
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

	now := time.Now()

	// First check - should need update (never updated)
	if !cache.NeedsBpfUpdate(now) {
		t.Error("Expected first update to be needed")
	}

	// Mark as updated
	cache.MarkBpfUpdated(now)

	// Second check immediately - should NOT need update (min interval not passed)
	if cache.NeedsBpfUpdate(now) {
		t.Error("Expected update to be skipped (min interval)")
	}

	// Wait for min interval to pass
	time.Sleep(MinBpfUpdateInterval + 10*time.Millisecond)
	now = time.Now()

	// Third check after min interval - should NOT need update (data unchanged)
	if cache.NeedsBpfUpdate(now) {
		t.Error("Expected update to be skipped (data unchanged)")
	}
}

// TestDifferentialBpfUpdate_DataChanged verifies that BPF updates are triggered
// when data changes.
func TestDifferentialBpfUpdate_DataChanged(t *testing.T) {
	// Create a cache with some data
	cache := &DnsCache{
		DomainBitmap: []uint32{1, 2, 3},
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

	now := time.Now()

	// First update
	cache.MarkBpfUpdated(now)

	// Wait for min interval
	time.Sleep(MinBpfUpdateInterval + 10*time.Millisecond)
	now = time.Now()

	// Should NOT need update yet
	if cache.NeedsBpfUpdate(now) {
		t.Error("Expected update to be skipped (data unchanged)")
	}

	// Change the data (simulate DNS response update)
	cache.Answer = []dnsmessage.RR{
		&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{
				Name:   "example.com.",
				Rrtype: dnsmessage.TypeA,
				Class:  dnsmessage.ClassINET,
				Ttl:    300,
			},
			A: []byte{5, 6, 7, 8}, // Different IP
		},
	}

	// Now should need update (data changed)
	if !cache.NeedsBpfUpdate(now) {
		t.Error("Expected update to be needed (data changed)")
	}
}

// TestDifferentialBpfUpdate_MaxInterval verifies that updates are forced
// after the maximum interval even if data hasn't changed.
func TestDifferentialBpfUpdate_MaxInterval(t *testing.T) {
	cache := &DnsCache{
		DomainBitmap: []uint32{1, 2, 3},
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

	// Mark as updated in the past (simulate max interval passed)
	pastTime := time.Now().Add(-MaxBpfUpdateInterval - time.Second)
	cache.MarkBpfUpdated(pastTime)

	now := time.Now()

	// Should need update (max interval passed)
	if !cache.NeedsBpfUpdate(now) {
		t.Error("Expected update to be forced (max interval passed)")
	}
}

// TestBpfDataHash tests the hash computation for BPF data.
func TestBpfDataHash(t *testing.T) {
	cache1 := &DnsCache{
		DomainBitmap: []uint32{1, 2, 3},
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
	}

	cache2 := &DnsCache{
		DomainBitmap: []uint32{1, 2, 3},
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
	}

	cache3 := &DnsCache{
		DomainBitmap: []uint32{1, 2, 3},
		Answer: []dnsmessage.RR{
			&dnsmessage.A{
				Hdr: dnsmessage.RR_Header{
					Name:   "example.com.",
					Rrtype: dnsmessage.TypeA,
					Class:  dnsmessage.ClassINET,
					Ttl:    300,
				},
				A: []byte{5, 6, 7, 8}, // Different IP
			},
		},
	}

	hash1 := cache1.ComputeBpfDataHash()
	hash2 := cache2.ComputeBpfDataHash()
	hash3 := cache3.ComputeBpfDataHash()

	// Same data should produce same hash
	if hash1 != hash2 {
		t.Errorf("Expected same hash for same data: %d vs %d", hash1, hash2)
	}

	// Different data should produce different hash
	if hash1 == hash3 {
		t.Errorf("Expected different hash for different data: %d vs %d", hash1, hash3)
	}

	t.Logf("Hash1: %d, Hash2: %d, Hash3: %d", hash1, hash2, hash3)
}

// TestDifferentialBpfUpdate_ConcurrentSafety verifies CAS protection against race conditions.
// Multiple goroutines should not all trigger updates - only one should succeed.
func TestDifferentialBpfUpdate_ConcurrentSafety(t *testing.T) {
	cache := &DnsCache{
		DomainBitmap: []uint32{1, 2, 3},
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

	numGoroutines := 100
	var successCount atomic.Int32
	var wg sync.WaitGroup

	// All goroutines try to check at the same time
	startWg := sync.WaitGroup{}
	startWg.Add(1)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			startWg.Wait() // Wait for all goroutines to be ready
			
			now := time.Now()
			if cache.NeedsBpfUpdate(now) {
				successCount.Add(1)
			}
		}()
	}

	// Start all goroutines at once
	startWg.Done()
	wg.Wait()

	// Only ONE goroutine should succeed due to CAS
	winners := successCount.Load()
	if winners != 1 {
		t.Errorf("Expected exactly 1 goroutine to succeed, got %d (race condition detected!)", winners)
	} else {
		t.Logf("CAS protection working: only 1 of %d goroutines succeeded", numGoroutines)
	}
}

// TestDifferentialBpfUpdate_ConcurrentDataChange verifies correct behavior
// when data changes during concurrent access.
func TestDifferentialBpfUpdate_ConcurrentDataChange(t *testing.T) {
	cache := &DnsCache{
		DomainBitmap: []uint32{1, 2, 3},
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

	// Mark as updated
	cache.MarkBpfUpdated(time.Now())

	// Wait for min interval
	time.Sleep(MinBpfUpdateInterval + 10*time.Millisecond)

	// First check with unchanged data - should NOT need update
	if cache.NeedsBpfUpdate(time.Now()) {
		t.Error("Expected no update needed for unchanged data")
	}

	// Simulate concurrent data change (this could happen in real scenario)
	// In practice, Answer is not modified after creation, but this tests robustness
	cache.Answer = []dnsmessage.RR{
		&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{
				Name:   "example.com.",
				Rrtype: dnsmessage.TypeA,
				Class:  dnsmessage.ClassINET,
				Ttl:    300,
			},
			A: []byte{5, 6, 7, 8},
		},
	}

	// Now should need update (data changed)
	if !cache.NeedsBpfUpdate(time.Now()) {
		t.Error("Expected update needed for changed data")
	}
}

// TestDifferentialBpfUpdate_BackwardCompatibility verifies that the new
// differential update mechanism doesn't break existing behavior.
func TestDifferentialBpfUpdate_BackwardCompatibility(t *testing.T) {
	cache := &DnsCache{
		DomainBitmap: []uint32{1, 2, 3},
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

	// Test 1: First access should trigger update (old behavior)
	if !cache.NeedsBpfUpdate(time.Now()) {
		t.Error("First access should need update")
	}

	// Test 2: Mark updated and verify hash is stored
	cache.MarkBpfUpdated(time.Now())
	hash := cache.lastBpfDataHash.Load()
	if hash == 0 {
		t.Error("Hash should be non-zero after MarkBpfUpdated")
	}

	// Test 3: Wait for min interval, data unchanged - should NOT update
	time.Sleep(MinBpfUpdateInterval + 10*time.Millisecond)
	if cache.NeedsBpfUpdate(time.Now()) {
		t.Error("Unchanged data should not need update")
	}

	// Test 4: Verify MarkRouteBindingRefreshed still works (backward compat)
	cache.MarkRouteBindingRefreshed(time.Now())
	// This should not affect the hash
	newHash := cache.lastBpfDataHash.Load()
	if newHash != hash {
		t.Error("MarkRouteBindingRefreshed should not affect hash")
	}

	t.Log("Backward compatibility verified")
}
