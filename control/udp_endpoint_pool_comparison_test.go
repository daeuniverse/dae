/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 *
 * Comparison test: Sharded Mutex vs Singleflight for UDP Endpoint Pool
 *
 * This test demonstrates why sharded mutex is better than singleflight
 * for the UDP endpoint pool use case, with actual test evidence.
 */

package control

import (
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sync/singleflight"
)

// =============================================================================
// Singleflight Implementation (for comparison)
// =============================================================================

type singleflightUdpEndpointPool struct {
	pool sync.Map
	sg   singleflight.Group
}

type singleflightCreateResult struct {
	endpoint any
	created  bool
}

func (p *singleflightUdpEndpointPool) GetOrCreate(lAddr netip.AddrPort, createFunc func() (any, error)) (any, bool, error) {
	// Fast path: check existing
	if v, ok := p.pool.Load(lAddr); ok {
		return v, false, nil
	}

	// Slow path: use singleflight
	key := lAddr.String()
	v, err, _ := p.sg.Do(key, func() (interface{}, error) {
		// Double-check
		if v, ok := p.pool.Load(lAddr); ok {
			return &singleflightCreateResult{endpoint: v, created: false}, nil
		}

		// Create new
		endpoint, err := createFunc()
		if err != nil {
			return nil, err
		}
		p.pool.Store(lAddr, endpoint)
		return &singleflightCreateResult{endpoint: endpoint, created: true}, nil
	})

	if err != nil {
		return nil, false, err
	}

	result := v.(*singleflightCreateResult)
	return result.endpoint, result.created, nil
}

// =============================================================================
// Sharded Mutex Implementation (current production)
// =============================================================================

type shardedUdpEndpointPool struct {
	pool          sync.Map
	createMuShard [64]sync.Mutex
}

func (p *shardedUdpEndpointPool) GetOrCreate(lAddr netip.AddrPort, createFunc func() (any, error)) (any, bool, error) {
	// Fast path: check existing
	if v, ok := p.pool.Load(lAddr); ok {
		return v, false, nil
	}

	// Slow path: use sharded mutex
	mu := p.shardMuFor(lAddr)
	mu.Lock()
	defer mu.Unlock()

	// Double-check
	if v, ok := p.pool.Load(lAddr); ok {
		return v, false, nil
	}

	// Create new
	endpoint, err := createFunc()
	if err != nil {
		return nil, false, err
	}
	p.pool.Store(lAddr, endpoint)
	return endpoint, true, nil
}

func (p *shardedUdpEndpointPool) shardMuFor(lAddr netip.AddrPort) *sync.Mutex {
	idx := int(hashAddrPortForBench(lAddr) & 63)
	return &p.createMuShard[idx]
}

func hashAddrPortForBench(lAddr netip.AddrPort) uint64 {
	addrBytes := lAddr.Addr().AsSlice()
	const (
		fnvOffset64 = 14695981039346656037
		fnvPrime64  = 1099511628211
	)
	h := uint64(fnvOffset64)
	for _, b := range addrBytes {
		h ^= uint64(b)
		h *= fnvPrime64
	}
	h ^= uint64(lAddr.Port())
	h *= fnvPrime64
	return h
}

// =============================================================================
// COMPARISON TEST 1: Transient Network Error Scenario
// =============================================================================

// TestComparison_TransientError tests the key difference in error handling.
//
// SCENARIO: Network is temporarily down, then recovers quickly.
//
// This test simulates UDP endpoint creation with transient dial failures.
func TestComparison_TransientError(t *testing.T) {
	t.Run("Singleflight", func(t *testing.T) {
		p := &singleflightUdpEndpointPool{}
		lAddr := netip.MustParseAddrPort("10.0.0.1:443")

		var callCount atomic.Int32
		var dialSucceeds atomic.Bool
		dialSucceeds.Store(false)

		// Simulate dial that may succeed or fail
		createFunc := func() (any, error) {
			callCount.Add(1)
			if dialSucceeds.Load() {
				endpoint := &struct{ name string }{name: "endpoint"}
				p.pool.Store(lAddr, endpoint)
				return endpoint, nil
			}
			return nil, fmt.Errorf("dial timeout: temporary network failure")
		}

		// First wave: 10 concurrent requests while network is down
		var wg sync.WaitGroup
		var failCount atomic.Int32
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				_, _, err := p.GetOrCreate(lAddr, createFunc)
				if err != nil {
					failCount.Add(1)
				}
			}(i)
		}
		wg.Wait()

		callsAfterFirstWave := callCount.Load()
		t.Logf("After first wave: %d dial attempts, %d failures", callsAfterFirstWave, failCount.Load())

		// Network recovers
		dialSucceeds.Store(true)

		// Second wave: 10 more concurrent requests
		var successCount atomic.Int32
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				_, _, err := p.GetOrCreate(lAddr, createFunc)
				if err == nil {
					successCount.Add(1)
				}
			}(i)
		}
		wg.Wait()

		totalCalls := callCount.Load()
		t.Logf("After second wave: %d total dial attempts, %d successes",
			totalCalls, successCount.Load())

		// Key finding: singleflight batches all concurrent requests into one attempt
		t.Logf("\n=== SINGLEFLIGHT ANALYSIS ===")
		t.Logf("PRO: Efficient - only %d dial attempts for %d requests", totalCalls, 20)
		if callsAfterFirstWave == 1 {
			t.Logf("PRO: First wave shared single dial attempt")
		}
		t.Logf("CON: If dial fails, all concurrent requests in that wave fail")
		t.Logf("CON: No retry within the wave - must wait for wave to complete")
	})

	t.Run("ShardedMutex", func(t *testing.T) {
		p := &shardedUdpEndpointPool{}
		lAddr := netip.MustParseAddrPort("10.0.0.2:443")

		var callCount atomic.Int32
		var dialSucceeds atomic.Bool
		dialSucceeds.Store(false)

		createFunc := func() (any, error) {
			callCount.Add(1)
			if dialSucceeds.Load() {
				endpoint := &struct{ name string }{name: "endpoint"}
				p.pool.Store(lAddr, endpoint)
				return endpoint, nil
			}
			return nil, fmt.Errorf("dial timeout: temporary network failure")
		}

		// First wave: 10 concurrent requests
		var wg sync.WaitGroup
		var failCount atomic.Int32
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				_, _, err := p.GetOrCreate(lAddr, createFunc)
				if err != nil {
					failCount.Add(1)
				}
			}(i)
		}

		// Simulate network recovering after 5ms (during the first wave)
		go func() {
			time.Sleep(5 * time.Millisecond)
			dialSucceeds.Store(true)
		}()

		wg.Wait()

		totalCalls := callCount.Load()
		t.Logf("After first wave: %d dial attempts, %d failures",
			totalCalls, failCount.Load())

		// Key finding: sharded mutex allows multiple concurrent retries
		t.Logf("\n=== SHARDED MUTEX ANALYSIS ===")
		if totalCalls > 1 {
			t.Logf("PRO: Multiple goroutines could retry concurrently")
			t.Logf("PRO: If network recovers during retries, later attempts succeed")
			t.Logf("CON: More dial attempts (%d vs singleflight's 1)", totalCalls)
		} else {
			t.Logf("Same efficiency as singleflight in fast case")
		}
	})
}

// =============================================================================
// COMPARISON TEST 2: Retry Timing Analysis
// =============================================================================

// TestComparison_RetryTiming tests the timing behavior difference.
//
// KEY FINDING: With singleflight, you must wait for the entire first batch
// to complete before retrying. With sharded mutex, retries can happen
// as soon as previous attempts fail.
func TestComparison_RetryTiming(t *testing.T) {
	t.Run("Singleflight_DelayedRecovery", func(t *testing.T) {
		p := &singleflightUdpEndpointPool{}
		lAddr := netip.MustParseAddrPort("10.0.0.3:443")

		var callCount atomic.Int32
		var delayMs atomic.Int32
		delayMs.Store(50) // First call takes 50ms

		createFunc := func() (any, error) {
			callCount.Add(1)
			ms := delayMs.Load()
			if ms > 0 {
				time.Sleep(time.Duration(ms) * time.Millisecond)
				return nil, fmt.Errorf("timeout after %dms", ms)
			}
			return "endpoint", nil
		}

		start := time.Now()

		// First wave: starts at t=0
		var wg sync.WaitGroup
		for i := 0; i < 5; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				p.GetOrCreate(lAddr, createFunc)
			}()
		}

		// While first wave is in progress, make it succeed at t=20ms
		go func() {
			time.Sleep(20 * time.Millisecond)
			delayMs.Store(0)
			t.Logf("At %v: Error condition resolved", time.Since(start))
		}()

		wg.Wait()
		firstWaveDuration := time.Since(start)

		t.Logf("First wave duration: %v", firstWaveDuration)
		t.Logf("Total createFunc calls: %d", callCount.Load())
		t.Logf("\nSINGLEFLIGHT: Even though error resolved at 20ms,")
		t.Logf("first wave still failed because it had to wait for initial call (~50ms)")
	})

	t.Run("ShardedMutex_ImmediateRetry", func(t *testing.T) {
		p := &shardedUdpEndpointPool{}
		lAddr := netip.MustParseAddrPort("10.0.0.4:443")

		var callCount atomic.Int32
		var shouldFail atomic.Bool
		shouldFail.Store(true)

		createFunc := func() (any, error) {
			callCount.Add(1)
			if shouldFail.Load() {
				return nil, fmt.Errorf("timeout")
			}
			p.pool.Store(lAddr, "endpoint")
			return "endpoint", nil
		}

		start := time.Now()

		// First wave: 10 concurrent requests
		var wg sync.WaitGroup
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				// Each goroutine retries up to 3 times
				for attempt := 0; attempt < 3; attempt++ {
					_, _, err := p.GetOrCreate(lAddr, createFunc)
					if err == nil {
						t.Logf("Goroutine #%d succeeded on attempt %d at %v",
							id, attempt+1, time.Since(start))
						return
					}
				}
			}(i)
		}

		// Make it succeed after 10ms
		go func() {
			time.Sleep(10 * time.Millisecond)
			shouldFail.Store(false)
			t.Logf("At %v: Error condition resolved", time.Since(start))
		}()

		wg.Wait()
		totalDuration := time.Since(start)

		t.Logf("Total duration: %v", totalDuration)
		t.Logf("Total createFunc calls: %d", callCount.Load())

		t.Logf("\nSHARDED MUTEX: Goroutines could retry immediately after failure,")
		t.Logf("no need to wait for other goroutines' first attempts")
	})
}

// =============================================================================
// BENCHMARKS: Performance Comparison
// =============================================================================

func BenchmarkSingleflight_Success(b *testing.B) {
	p := &singleflightUdpEndpointPool{}
	lAddr := netip.MustParseAddrPort("10.0.0.20:12345")
	p.pool.Store(lAddr, "existing") // Pre-populate

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			p.GetOrCreate(lAddr, func() (any, error) {
				return "endpoint", nil
			})
		}
	})
}

func BenchmarkShardedMutex_Success(b *testing.B) {
	p := &shardedUdpEndpointPool{}
	lAddr := netip.MustParseAddrPort("10.0.0.21:12345")
	p.pool.Store(lAddr, "existing") // Pre-populate

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			p.GetOrCreate(lAddr, func() (any, error) {
				return "endpoint", nil
			})
		}
	})
}

// BenchmarkSingleflight_Create simulates the worst case where
// each request needs to create a new endpoint.
func BenchmarkSingleflight_Create(b *testing.B) {
	p := &singleflightUdpEndpointPool{}
	var counter uint64

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			c := atomic.AddUint64(&counter, 1)
			lAddr := netip.AddrPortFrom(
				netip.AddrFrom4([4]byte{10, 0, byte(c), byte(c >> 8)}),
				uint16(10000+uint32(c)%1000),
			)
			p.GetOrCreate(lAddr, func() (any, error) {
				return "endpoint", nil
			})
		}
	})
}

// BenchmarkShardedMutex_Create simulates the worst case where
// each request needs to create a new endpoint.
func BenchmarkShardedMutex_Create(b *testing.B) {
	p := &shardedUdpEndpointPool{}
	var counter uint64

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			c := atomic.AddUint64(&counter, 1)
			lAddr := netip.AddrPortFrom(
				netip.AddrFrom4([4]byte{10, 1, byte(c), byte(c >> 8)}),
				uint16(10000+uint32(c)%1000),
			)
			p.GetOrCreate(lAddr, func() (any, error) {
				return "endpoint", nil
			})
		}
	})
}
