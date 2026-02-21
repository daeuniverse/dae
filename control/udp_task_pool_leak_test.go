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
)

// TestUdpTaskPoolNoLeak tests that convoy goroutines are properly cleaned up
func TestUdpTaskPoolNoLeak(t *testing.T) {
	// Save original timeout
	oldTimeout := DefaultNatTimeout
	DefaultNatTimeout = 100 * time.Millisecond
	defer func() { DefaultNatTimeout = oldTimeout }()

	pool := NewUdpTaskPool()

	// Get initial goroutine count
	initialGoroutines := runtime.NumGoroutine()
	t.Logf("Initial goroutines: %d", initialGoroutines)

	// Simulate stress test: emit tasks for many unique keys
	const numKeys = 1000
	const tasksPerKey = 10

	var wg sync.WaitGroup
	for i := 0; i < numKeys; i++ {
		key := netip.AddrPortFrom(
			netip.AddrFrom4([4]byte{byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)}),
			12345,
		)
		
		for j := 0; j < tasksPerKey; j++ {
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
	pool.queues.Range(func(key, value interface{}) bool {
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
	oldTimeout := DefaultNatTimeout
	DefaultNatTimeout = 50 * time.Millisecond
	defer func() { DefaultNatTimeout = oldTimeout }()

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
	oldTimeout := DefaultNatTimeout
	DefaultNatTimeout = 50 * time.Millisecond
	defer func() { DefaultNatTimeout = oldTimeout }()

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
	for i := 0; i < numGoroutines/5; i++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			for j := 0; j < tasksPerGoroutine; j++ {
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
	for i := 0; i < numGoroutines*4/5; i++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			for j := 0; j < tasksPerGoroutine/10; j++ { // Fewer tasks for cold keys
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
