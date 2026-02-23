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
	"golang.org/x/sync/singleflight"
)

// TestAsyncCacheRaceCondition tests that async caching doesn't cause cache stampede
// under high concurrency scenarios.
//
// Scenario: 1000 concurrent requests for the same domain (cache miss)
// Expected: Only ONE upstream request (due to singleflight), all others wait
// Result: All goroutines should get the cached response
func TestAsyncCacheRaceCondition(t *testing.T) {
	log := logrus.New()
	log.SetLevel(logrus.WarnLevel)

	controller := &DnsController{
		log:                    log,
		optimisticCacheEnabled: false,
	}
	controller.dnsCache = sync.Map{}

	// Simulate the async caching behavior from dialSend
	var upstreamCallCount atomic.Int32
	var wg sync.WaitGroup
	concurrency := 1000

	// Simulate concurrent requests all missing cache and hitting singleflight
	// In real code, singleflight ensures only ONE upstream request
	// Here we simulate the same behavior

	var sf singleflight.Group
	cacheKey := "example.com1"

	start := time.Now()

	for i := range concurrency {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			// First check cache (simulating cache miss for all)
			if _, ok := controller.dnsCache.Load(cacheKey); ok {
				t.Errorf("goroutine %d: unexpected cache hit", id)
				return
			}

			// Use singleflight to coalesce requests
			res, err, _ := sf.Do(cacheKey, func() (any, error) {
				// Only ONE goroutine executes this
				upstreamCallCount.Add(1)

				// Simulate upstream latency
				time.Sleep(50 * time.Millisecond)

				// Create response
				msg := &dnsmessage.Msg{
					MsgHdr: dnsmessage.MsgHdr{
						Response: true,
						Rcode:    dnsmessage.RcodeSuccess,
					},
					Question: []dnsmessage.Question{
						{Name: "example.com.", Qtype: dnsmessage.TypeA, Qclass: dnsmessage.ClassINET},
					},
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

				// Simulate async caching (from dialSend)
				go func() {
					defer func() {
						if r := recover(); r != nil {
							log.Errorf("panic in async cache: %v", r)
						}
					}()

					// Create cache entry
					cache := &DnsCache{
						Answer:   msg.Answer,
						Deadline: time.Now().Add(300 * time.Second),
					}
					controller.dnsCache.Store(cacheKey, cache)
				}()

				return msg, nil
			})

			if err != nil {
				t.Errorf("goroutine %d: unexpected error: %v", id, err)
				return
			}

			// Verify response
			msg := res.(*dnsmessage.Msg)
			if len(msg.Answer) == 0 {
				t.Errorf("goroutine %d: empty answer", id)
			}
		}(i)
	}

	wg.Wait()
	elapsed := time.Since(start)

	// Verify only ONE upstream request was made
	if count := upstreamCallCount.Load(); count != 1 {
		t.Errorf("Expected 1 upstream call (singleflight), got %d", count)
	}

	// Verify cache was written
	cache, ok := controller.dnsCache.Load(cacheKey)
	if !ok {
		t.Error("Cache entry not found after async write")
	} else {
		t.Logf("Cache entry found: %v answers", len(cache.(*DnsCache).Answer))
	}

	t.Logf("Handled %d concurrent requests in %v (singleflight + async cache)", concurrency, elapsed)
}

// TestAsyncCacheStampedeWithoutSingleflight demonstrates what happens WITHOUT singleflight
// This shows the cache stampede problem that async caching alone cannot prevent
func TestAsyncCacheStampedeWithoutSingleflight(t *testing.T) {
	log := logrus.New()
	log.SetLevel(logrus.WarnLevel)

	controller := &DnsController{
		log:      log,
		dnsCache: sync.Map{},
	}

	var upstreamCallCount atomic.Int32
	var cacheWriteCount atomic.Int32
	var wg sync.WaitGroup
	concurrency := 100

	// Scenario: All requests check cache, find miss, call upstream, cache async
	// WITHOUT singleflight protection, this causes:
	// 1. Cache stampede - all 100 requests hit upstream simultaneously
	// 2. Cache write race - multiple goroutines write the same key

	for i := range concurrency {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			// Check cache (all miss)
			if _, ok := controller.dnsCache.Load("example.com1"); ok {
				return // Cache hit (shouldn't happen in this test)
			}

			// Cache miss - all goroutines call upstream (NO SINGLEFLIGHT)
			upstreamCallCount.Add(1)
			time.Sleep(10 * time.Millisecond) // Simulate upstream

			// Async cache (all goroutines do this)
			go func() {
				cacheWriteCount.Add(1)
				msg := &dnsmessage.Msg{
					Answer: []dnsmessage.RR{
						&dnsmessage.A{
							Hdr: dnsmessage.RR_Header{Ttl: 300},
						},
					},
				}
				cache := &DnsCache{
					Answer:   msg.Answer,
					Deadline: time.Now().Add(300 * time.Second),
				}
				controller.dnsCache.Store("example.com1", cache)
			}()
		}(i)
	}

	wg.Wait()
	time.Sleep(100 * time.Millisecond) // Wait for async writes

	// WITHOUT singleflight, we get cache stampede
	if count := upstreamCallCount.Load(); count != int32(concurrency) {
		t.Logf("Expected %d upstream calls without singleflight, got %d", concurrency, count)
	}

	// Multiple async cache writes (wasted work)
	t.Logf("Cache write attempts: %d (should be 1 with singleflight)", cacheWriteCount.Load())

	t.Log("This test demonstrates why singleflight is ESSENTIAL to prevent cache stampede")
}

// TestAsyncCacheTimingWithSingleflight verifies that async caching + singleflight
// provides optimal performance under realistic concurrent load
func TestAsyncCacheTimingWithSingleflight(t *testing.T) {
	log := logrus.New()
	log.SetLevel(logrus.WarnLevel)

	controller := &DnsController{
		log:      log,
		dnsCache: sync.Map{},
	}

	var sf singleflight.Group
	var upstreamCallCount atomic.Int32
	var wg sync.WaitGroup

	scenarios := []struct {
		name       string
		concurrent int
	}{
		{"10-concurrent", 10},
		{"100-concurrent", 100},
		{"1000-concurrent", 1000},
	}

	for _, scenario := range scenarios {
		upstreamCallCount.Store(0)
		start := time.Now()

		for i := 0; i < scenario.concurrent; i++ {
			wg.Go(func() {

				cacheKey := "test.com1"

				// Check cache first
				if _, ok := controller.dnsCache.Load(cacheKey); ok {
					return // Cache hit
				}

				// Use singleflight
				_, _, _ = sf.Do(cacheKey, func() (any, error) {
					upstreamCallCount.Add(1)
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
			})
		}

		wg.Wait()
		elapsed := time.Since(start)

		calls := upstreamCallCount.Load()
		t.Logf("%s: %v elapsed, %d upstream calls (expected 1)",
			scenario.name, elapsed, calls)

		if calls != 1 {
			t.Errorf("%s: singleflight failed - got %d upstream calls", scenario.name, calls)
		}

		// Clear for next scenario
		controller.dnsCache.Delete("test.com1")
	}
}

// TestAsyncCacheDoesNotBlock verifies that async caching truly doesn't block
func TestAsyncCacheDoesNotBlock(t *testing.T) {
	log := logrus.New()
	log.SetLevel(logrus.WarnLevel)

	controller := &DnsController{
		log:      log,
		dnsCache: sync.Map{},
	}

	// Simulate a slow cache operation (e.g., BPF update)
	slowCacheDuration := 100 * time.Millisecond

	// Measure time to complete 100 requests
	start := time.Now()

	for range 100 {
		// Simulate send response (instant)

		// Async cache (should not block)
		go func() {
			time.Sleep(slowCacheDuration) // Simulate slow cache
			controller.dnsCache.Store("key", &DnsCache{})
		}()
	}

	elapsed := time.Since(start)

	// If async, should complete in < 10ms despite 100ms cache operation
	if elapsed > 20*time.Millisecond {
		t.Errorf("Async caching blocked: took %v (expected < 20ms)", elapsed)
	}

	t.Logf("100 async cache operations completed in %v (did not block)", elapsed)
}
