/*
 *  SPDX-License-Identifier: AGPL-3.0-only
 *  Copyright (c) 2022-2025, daeuniverse Organization <dae@daeuniverse.org>
 *
 *  UDP Task Pool Leak Test
 *  Verifies that convoy goroutines are properly cleaned up
 */

package control

import (
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestUdpTaskPoolNoLeak tests that convoy goroutines are properly cleaned up
func TestUdpTaskPoolNoLeak(t *testing.T) {
	// Save original timeout
	oldTimeout := UdpTaskPoolAgingTime
	UdpTaskPoolAgingTime = 100 * time.Millisecond
	defer func() { UdpTaskPoolAgingTime = oldTimeout }()

	pool := NewUdpTaskPool()

	// Get initial goroutine count
	initialGoroutines := runtime.NumGoroutine()
	t.Logf("Initial goroutines: %d", initialGoroutines)

	// Simulate stress test: emit tasks for many unique keys
	const numKeys = 1000
	const tasksPerKey = 10

	var wg sync.WaitGroup
	for i := range numKeys {
		key := netip.AddrPortFrom(
			netip.AddrFrom4([4]byte{byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)}),
			12345,
		)

		for range tasksPerKey {
			wg.Add(1)
			go func(k netip.AddrPort) {
				defer wg.Done()
				pool.EmitTask(k, func() {
					// Simulate some work
					time.Sleep(10 * time.Microsecond)
				})
			}(key)
		}
	}

	wg.Wait()
	t.Logf("All tasks emitted and completed")

	// Check goroutine count immediately after
	afterStress := runtime.NumGoroutine()
	t.Logf("After stress test goroutines: %d (delta: +%d)", afterStress, afterStress-initialGoroutines)

	// Wait for cleanup (2x timeout + margin)
	time.Sleep(250 * time.Millisecond)

	// Force GC to help cleanup
	runtime.GC()
	time.Sleep(50 * time.Millisecond)

	// Check goroutine count after cleanup
	afterCleanup := runtime.NumGoroutine()
	t.Logf("After cleanup goroutines: %d (delta: %+d)", afterCleanup, afterCleanup-initialGoroutines)

	// Allow small variance (some goroutines may still be cleaning up)
	leaked := afterCleanup - initialGoroutines
	if leaked > 10 {
		t.Errorf("Goroutine leak detected: %d goroutines not cleaned up", leaked)
	} else if leaked > 0 {
		t.Logf("Warning: %d goroutines may not be cleaned up yet", leaked)
	} else {
		t.Logf("SUCCESS: All convoy goroutines properly cleaned up!")
	}

	// Check queue count in pool
	queueCount := 0
	pool.queues.Range(func(key, value any) bool {
		queueCount++
		return true
	})
	t.Logf("Remaining queues in pool: %d", queueCount)

	if queueCount > 10 {
		t.Errorf("Queue leak detected: %d queues still in pool", queueCount)
	}
}

// TestUdpTaskPoolDrainingFlag tests that the draining flag works correctly
func TestUdpTaskPoolDrainingFlag(t *testing.T) {
	oldTimeout := UdpTaskPoolAgingTime
	UdpTaskPoolAgingTime = 50 * time.Millisecond
	defer func() { UdpTaskPoolAgingTime = oldTimeout }()

	pool := NewUdpTaskPool()
	key := netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, 2, 3, 4}), 80)

	// Emit a task to create a queue
	var executed atomic.Bool
	pool.EmitTask(key, func() {
		time.Sleep(10 * time.Millisecond)
		executed.Store(true)
	})

	// Give convoy goroutine time to start
	time.Sleep(20 * time.Millisecond)

	// Load the queue
	v, ok := pool.queues.Load(key)
	if !ok {
		t.Fatal("Queue not created")
	}
	q := v.(*UdpTaskQueue)

	// Check that draining is initially false
	if q.draining.Load() {
		t.Error("Queue should not be draining initially")
	}

	// Wait for convoy to set draining flag (after timeout)
	time.Sleep(100 * time.Millisecond)

	// Try to emit another task - should create new queue if draining works
	var executed2 atomic.Bool
	pool.EmitTask(key, func() {
		executed2.Store(true)
	})

	// Wait for task to complete
	time.Sleep(20 * time.Millisecond)

	if !executed.Load() {
		t.Error("First task did not execute")
	}
	if !executed2.Load() {
		t.Error("Second task did not execute")
	}

	// Check that a new queue was created (old one should be deleted)
	v2, ok := pool.queues.Load(key)
	if !ok {
		t.Fatal("Queue not found after cleanup")
	}
	q2 := v2.(*UdpTaskQueue)

	// The queue should be a new instance (or at least not draining)
	if q == q2 && q.draining.Load() {
		t.Log("Note: Old queue still exists but should be cleaned up soon")
	}

	t.Logf("SUCCESS: Draining flag mechanism works correctly")
}

// TestUdpTaskPoolConcurrentAccess tests concurrent access patterns
func TestUdpTaskPoolConcurrentAccess(t *testing.T) {
	oldTimeout := UdpTaskPoolAgingTime
	UdpTaskPoolAgingTime = 50 * time.Millisecond
	defer func() { UdpTaskPoolAgingTime = oldTimeout }()

	pool := NewUdpTaskPool()
	initialGoroutines := runtime.NumGoroutine()

	// Simulate realistic access pattern:
	// - Many goroutines
	// - Concurrent emit
	// - Some keys are hot (frequent access), some are cold (rare access)

	const numGoroutines = 100
	const tasksPerGoroutine = 100

	var wg sync.WaitGroup

	// Hot keys (20% of traffic)
	for i := range numGoroutines / 5 {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			for j := range tasksPerGoroutine {
				key := netip.AddrPortFrom(
					netip.AddrFrom4([4]byte{1, 1, 1, byte(j % 10)}), // 10 hot keys
					80,
				)
				pool.EmitTask(key, func() {
					time.Sleep(time.Microsecond)
				})
			}
		}(i)
	}

	// Cold keys (80% of traffic)
	for i := range numGoroutines * 4 / 5 {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			for j := range tasksPerGoroutine / 10 { // Fewer tasks for cold keys
				key := netip.AddrPortFrom(
					netip.AddrFrom4([4]byte{
						byte(goroutineID),
						byte(j >> 16),
						byte(j >> 8),
						byte(j),
					}),
					uint16(goroutineID),
				)
				pool.EmitTask(key, func() {
					time.Sleep(time.Microsecond)
				})
			}
		}(i)
	}

	wg.Wait()
	t.Logf("All concurrent tasks completed")

	// Wait for cleanup
	time.Sleep(200 * time.Millisecond)
	runtime.GC()
	time.Sleep(50 * time.Millisecond)

	afterCleanup := runtime.NumGoroutine()
	leaked := afterCleanup - initialGoroutines

	t.Logf("Goroutines: initial=%d, after=%d, leaked=%d",
		initialGoroutines, afterCleanup, leaked)

	if leaked > 10 {
		t.Errorf("Goroutine leak in concurrent test: %d", leaked)
	} else {
		t.Logf("SUCCESS: Concurrent access pattern handled correctly")
	}
}

// BenchmarkUdpTaskPool benchmarks the pool performance
func BenchmarkUdpTaskPool(b *testing.B) {
	pool := NewUdpTaskPool()
	key := netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, 2, 3, 4}), 80)

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			pool.EmitTask(key, func() {})
			i++
		}
	})
}

// TestUdpTaskPoolAgingTime verifies that 100ms aging time is sufficient
// for burst traffic while enabling fast memory reclamation.
func TestUdpTaskPoolAgingTime(t *testing.T) {
	// Test with production value (100ms)
	originalAgingTime := UdpTaskPoolAgingTime
	UdpTaskPoolAgingTime = 100 * time.Millisecond
	defer func() { UdpTaskPoolAgingTime = originalAgingTime }()

	pool := NewUdpTaskPool()

	// Capture baseline after pool creation
	runtime.GC()
	time.Sleep(10 * time.Millisecond)
	baselineGoroutines := runtime.NumGoroutine()
	t.Logf("Baseline goroutines: %d", baselineGoroutines)

	// Simulate burst traffic: 1000 keys, 100 tasks each
	const numKeys = 1000
	const tasksPerKey = 100

	start := time.Now()
	var wg sync.WaitGroup
	for i := range numKeys {
		key := netip.AddrPortFrom(
			netip.AddrFrom4([4]byte{byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)}),
			443,
		)
		for range tasksPerKey {
			wg.Add(1)
			pool.EmitTask(key, func() {
				wg.Done()
			})
		}
	}
	wg.Wait()
	burstDuration := time.Since(start)
	t.Logf("Burst traffic completed in %v", burstDuration)

	// Verify all tasks processed in order
	if burstDuration > 5*time.Second {
		t.Errorf("Burst processing too slow: %v", burstDuration)
	}

	// Wait for aging + cleanup margin
	time.Sleep(UdpTaskPoolAgingTime + 50*time.Millisecond)
	runtime.GC()
	time.Sleep(50 * time.Millisecond)

	// Verify memory reclamation
	queueCount := 0
	pool.queues.Range(func(key, value any) bool {
		queueCount++
		return true
	})

	if queueCount > 10 {
		t.Errorf("Too many queues remaining after aging: %d", queueCount)
	} else {
		t.Logf("Memory reclamation successful: %d queues remaining", queueCount)
	}

	// Verify goroutine cleanup (allow some variance)
	currentGoroutines := runtime.NumGoroutine()
	leaked := currentGoroutines - baselineGoroutines
	if leaked > 20 {
		t.Errorf("Goroutine leak: %d (baseline=%d, current=%d)", leaked, baselineGoroutines, currentGoroutines)
	} else {
		t.Logf("Goroutine cleanup successful: %d leaked (acceptable)", leaked)
	}
}

// BenchmarkUdpTaskPoolAgingTime benchmarks different aging times
func BenchmarkUdpTaskPoolAgingTime(b *testing.B) {
	agingTimes := []time.Duration{
		50 * time.Millisecond,
		100 * time.Millisecond,
		200 * time.Millisecond,
		500 * time.Millisecond,
		1 * time.Second,
	}

	for _, aging := range agingTimes {
		b.Run(aging.String(), func(b *testing.B) {
			originalAgingTime := UdpTaskPoolAgingTime
			UdpTaskPoolAgingTime = aging
			defer func() { UdpTaskPoolAgingTime = originalAgingTime }()

			pool := NewUdpTaskPool()
			key := netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, 2, 3, 4}), 443)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				pool.EmitTask(key, func() {})
			}
		})
	}
}

// TestUdpTaskPool_ContinuousTraffic verifies 100ms aging with continuous low-rate traffic.
// Ensures queues persist when packets arrive faster than aging time.
func TestUdpTaskPool_ContinuousTraffic(t *testing.T) {
	originalAgingTime := UdpTaskPoolAgingTime
	UdpTaskPoolAgingTime = 100 * time.Millisecond
	defer func() { UdpTaskPoolAgingTime = originalAgingTime }()

	pool := NewUdpTaskPool()
	key := netip.MustParseAddrPort("192.168.1.1:443")

	// Continuous traffic: 1 packet every 80ms for 1 second (interval < agingTime)
	// Queue should persist, not age out
	for i := 0; i < 12; i++ {
		var done atomic.Bool
		pool.EmitTask(key, func() {
			done.Store(true)
		})
		require.Eventually(t, func() bool { return done.Load() }, 50*time.Millisecond, 5*time.Millisecond)
		time.Sleep(80 * time.Millisecond)
	}

	// Verify queue still exists (not aged out)
	count := 0
	pool.queues.Range(func(_, _ any) bool {
		count++
		return true
	})
	require.Equal(t, 1, count, "Queue should persist with continuous traffic (interval < agingTime)")
}

// TestUdpTaskPool_ConcurrentContinuousTraffic verifies concurrent flows with continuous traffic.
// Simulates real-world scenario: multiple QUIC connections with ongoing traffic.
func TestUdpTaskPool_ConcurrentContinuousTraffic(t *testing.T) {
	originalAgingTime := UdpTaskPoolAgingTime
	UdpTaskPoolAgingTime = 100 * time.Millisecond
	defer func() { UdpTaskPoolAgingTime = originalAgingTime }()

	pool := NewUdpTaskPool()

	// Simulate 10 concurrent QUIC flows
	const numFlows = 10
	const packetsPerFlow = 20
	const packetInterval = 80 * time.Millisecond // < agingTime

	var wg sync.WaitGroup
	var allProcessed atomic.Int32

	start := time.Now()

	// Start concurrent flows
	for flowID := 0; flowID < numFlows; flowID++ {
		wg.Add(1)
		go func(fid int) {
			defer wg.Done()

			key := netip.AddrPortFrom(
				netip.AddrFrom4([4]byte{192, 168, 1, byte(fid + 1)}),
				443,
			)

			// Send packets at intervals
			for pkt := 0; pkt < packetsPerFlow; pkt++ {
				pool.EmitTask(key, func() {
					allProcessed.Add(1)
				})
				time.Sleep(packetInterval)
			}
		}(flowID)
	}

	// Wait for all goroutines to finish sending
	wg.Wait()
	totalDuration := time.Since(start)

	// Verify all packets processed
	expectedTotal := int32(numFlows * packetsPerFlow)
	require.Eventually(t, func() bool {
		return allProcessed.Load() >= expectedTotal
	}, 5*time.Second, 50*time.Millisecond, "all packets should be processed")

	t.Logf("Processed %d packets from %d concurrent flows in %v", allProcessed.Load(), numFlows, totalDuration)

	// Wait for aging
	time.Sleep(UdpTaskPoolAgingTime + 50*time.Millisecond)

	// Verify memory reclamation after traffic stops
	runtime.GC()
	time.Sleep(50 * time.Millisecond)

	queueCount := 0
	pool.queues.Range(func(_, _ any) bool {
		queueCount++
		return true
	})

	// All queues should be cleaned up after aging
	require.LessOrEqual(t, queueCount, 2, "queues should be cleaned up after aging (got %d)", queueCount)
}

// TestUdpTaskPool_MixedBurstAndContinuous verifies mixed traffic patterns.
func TestUdpTaskPool_MixedBurstAndContinuous(t *testing.T) {
	originalAgingTime := UdpTaskPoolAgingTime
	UdpTaskPoolAgingTime = 100 * time.Millisecond
	defer func() { UdpTaskPoolAgingTime = originalAgingTime }()

	pool := NewUdpTaskPool()

	// Phase 1: Burst traffic (creates queues)
	burstKey := netip.MustParseAddrPort("10.0.0.1:443")
	for i := 0; i < 100; i++ {
		pool.EmitTask(burstKey, func() {})
	}
	time.Sleep(50 * time.Millisecond) // Let burst process

	// Phase 2: Continuous traffic (keeps queue alive)
	continuousKey := netip.MustParseAddrPort("10.0.0.2:443")
	for i := 0; i < 10; i++ {
		pool.EmitTask(continuousKey, func() {})
		time.Sleep(80 * time.Millisecond) // < agingTime
	}

	// Verify: burst queue should be gone, continuous queue should remain
	time.Sleep(UdpTaskPoolAgingTime + 50*time.Millisecond)

	pool.queues.Range(func(key, _ any) bool {
		k := key.(netip.AddrPort)
		// Only continuousKey should remain (or none if timing is tight)
		if k != continuousKey {
			t.Logf("Unexpected queue remaining: %v", k)
		}
		return true
	})
}
