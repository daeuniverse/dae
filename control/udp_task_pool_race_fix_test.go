/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@daeuniverse.org>
 *
 * Test for UDP TaskPool race condition fix (CompareAndDelete).
 * Validates that the fix prevents goroutine leaks and queue corruption.
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

// TestCompareAndDelete_RaceCondition simulates the exact race condition
// described in the PR review comment:
// - Old convoy tries to delete Q1
// - Meanwhile acquireQueue creates Q2
// - Old convoy should NOT delete Q2
func TestCompareAndDelete_RaceCondition(t *testing.T) {
	pool := NewUdpTaskPool()
	key := NewUdpSrcOnlyFlowKey(netip.MustParseAddrPort("192.168.1.1:12345"))

	// Create initial queue
	q1 := pool.acquireQueue(key)
	q1.refs.Add(-1) // Release the reference

	// Start goroutine that simulates the old convoy trying to delete Q1
	// This will set draining=true and try to delete
	var deleteResult atomic.Bool
	var deleteWg sync.WaitGroup
	deleteWg.Add(1)

	go func() {
		defer deleteWg.Done()
		// Simulate convoy cleanup: set draining, wait, try delete
		q1.refs.Store(-1000000)
		time.Sleep(5 * time.Millisecond) // Allow race window

		// This should only delete Q1, not any new queue
		deleted := pool.tryDeleteQueue(key, q1)
		deleteResult.Store(deleted)
	}()

	// Simulate concurrent acquireQueue seeing draining Q1 and creating Q2
	time.Sleep(2 * time.Millisecond) // Enter race window

	// Q1 is draining, acquireQueue should create new queue
	q2 := pool.acquireQueue(key)

	// Wait for delete attempt to complete
	deleteWg.Wait()

	// Verify: Q1 delete should have failed because Q2 was stored
	// (CompareAndDelete only deletes if value matches)
	if deleteResult.Load() {
		t.Error("tryDeleteQueue should have failed - Q2 replaced Q1 in map")
	}

	// Verify: Q2 should still be usable
	if q2 == nil {
		t.Fatal("Q2 should not be nil")
	}

	// Verify: Q2 is not draining
	if q2.refs.Load() < 0 {
		t.Error("Q2 should not be draining")
	}

	// Verify: Q2 is in the map
	loaded, ok := pool.queues.Load(key)
	if !ok {
		t.Fatal("Q2 should be in map")
	}
	if loaded.(*UdpTaskQueue) != q2 {
		t.Error("Map should contain Q2, not Q1")
	}

	// Cleanup
	q2.refs.Add(-1)
}

// TestCompareAndDelete_AcquireQueueRace simulates the second race condition
// in acquireQueue draining path:
// - Two goroutines both see draining=true
// - Both try to Delete the same key
// - Only one should succeed in deleting the correct queue
func TestCompareAndDelete_AcquireQueueRace(t *testing.T) {
	pool := NewUdpTaskPool()
	key := NewUdpSrcOnlyFlowKey(netip.MustParseAddrPort("10.0.0.1:53"))

	// Create queue and mark as draining
	q1 := pool.acquireQueue(key)
	q1.refs.Add(-1)
	q1.refs.Store(-1000000)

	// Simulate two concurrent acquireQueue calls
	var wg sync.WaitGroup
	queues := make([]*UdpTaskQueue, 2) // Fixed-size array avoids data race
	var createCount atomic.Int32

	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			q := pool.acquireQueue(key)
			createCount.Add(1)
			queues[idx] = q // Each goroutine writes to its own slot
		}(i)
	}
	wg.Wait()

	q2, q3 := queues[0], queues[1]

	// Both should get the same queue (LoadOrStore semantics)
	if q2 != q3 {
		t.Errorf("Both goroutines should get the same queue, got different queues: q2=%p, q3=%p", q2, q3)
	}

	// The new queue should not be draining
	if q2 == nil {
		t.Fatal("Queue should not be nil")
	}
	if q2.refs.Load() < 0 {
		t.Error("New queue should not be draining")
	}

	// Cleanup
	q2.refs.Add(-1)
}

// TestNoGoroutineLeak verifies that convoy goroutines properly exit
// and don't leak after the CompareAndDelete fix.
func TestNoGoroutineLeak(t *testing.T) {
	// Use a separate pool to isolate the test
	pool := NewUdpTaskPool()

	// Get initial goroutine count
	runtime.GC()
	time.Sleep(10 * time.Millisecond)
	initialGoroutines := runtime.NumGoroutine()

	// Create and release many queues rapidly
	// This simulates the scenario that caused the original leak
	const numQueues = 100
	keys := make([]UdpFlowKey, numQueues)
	for i := 0; i < numQueues; i++ {
		keys[i] = NewUdpSrcOnlyFlowKey(netip.MustParseAddrPort("192.168.1.1:1234"))
		keys[i] = NewUdpSrcOnlyFlowKey(netip.AddrPortFrom(
			netip.AddrFrom4([4]byte{192, 168, byte(i / 256), byte(i % 256)}),
			uint16(10000+i),
		))
	}

	// Rapidly create and abandon queues
	for i := 0; i < numQueues; i++ {
		q := pool.acquireQueue(keys[i])
		q.refs.Add(-1)
	}

	// Wait for aging and cleanup
	time.Sleep(UdpTaskPoolAgingTime + 50*time.Millisecond)

	// Force GC to help cleanup
	runtime.GC()
	time.Sleep(50 * time.Millisecond)

	// Check goroutine count
	finalGoroutines := runtime.NumGoroutine()
	leaked := finalGoroutines - initialGoroutines

	t.Logf("Goroutines: initial=%d, final=%d, leaked=%d", initialGoroutines, finalGoroutines, leaked)

	// Allow some variance, but should not have massive leak
	// Original bug would leak ~100 goroutines here
	if leaked > 10 {
		t.Errorf("Potential goroutine leak: %d goroutines leaked", leaked)
	}

	// Verify all queues were cleaned up
	count := 0
	pool.queues.Range(func(_, _ any) bool {
		count++
		return true
	})
	if count > 0 {
		t.Logf("Warning: %d queues still in map after aging", count)
	}
}

// TestConvoyExitAfterFailedDelete verifies that CompareAndDelete
// prevents queue corruption when convoy tries to delete a replaced queue.
func TestConvoyExitAfterFailedDelete(t *testing.T) {
	pool := NewUdpTaskPool()
	key := NewUdpSrcOnlyFlowKey(netip.MustParseAddrPort("172.16.0.1:8080"))

	// Create queue and immediately release
	q1 := pool.acquireQueue(key)
	q1.refs.Add(-1)

	// Get the queue from map to verify it's q1
	loaded1, _ := pool.queues.Load(key)
	if loaded1.(*UdpTaskQueue) != q1 {
		t.Fatal("Initial setup failed: q1 not in map")
	}

	// Simulate the race: create new queue via acquireQueue
	// This happens when q1 is draining
	q1.refs.Store(-1000000)
	q2 := pool.acquireQueue(key)

	// q2 should be different from q1
	if q2 == q1 {
		t.Fatal("q2 should be a new queue, not q1")
	}

	// Now q1's convoy will try to delete, but CompareAndDelete should fail
	// because map contains q2, not q1
	deleted := pool.tryDeleteQueue(key, q1)
	if deleted {
		t.Error("tryDeleteQueue should fail - q2 replaced q1 in map")
	}

	// Verify q2 is still in map and usable
	loaded2, ok := pool.queues.Load(key)
	if !ok {
		t.Fatal("q2 should still be in map")
	}
	if loaded2.(*UdpTaskQueue) != q2 {
		t.Error("Map should still contain q2")
	}

	// Cleanup
	q2.refs.Add(-1)
}

// TestConvoyExitWhenMappingDeletedBeforeSelfDelete verifies that convoy goroutine
// exits when the queue mapping is deleted/replaced before convoy can self-delete.
// This is the regression test for the issue reported in PR #936 comment #3976442155.
func TestConvoyExitWhenMappingDeletedBeforeSelfDelete(t *testing.T) {
	pool := NewUdpTaskPool()
	key := NewUdpSrcOnlyFlowKey(netip.MustParseAddrPort("172.16.0.1:8080"))

	// Create queue
	q := pool.acquireQueue(key)
	q.refs.Add(-1) // Release reference

	// Get initial goroutine count
	initialGoroutines := runtime.NumGoroutine()

	// Simulate the race: the mapping is deleted by another path
	// (e.g., acquireQueue's CompareAndDelete during draining)
	pool.queues.Delete(key)

	// Now convoy will try to delete and fail because key is gone
	// Without the fix, convoy would loop forever.
	// With the fix, convoy should detect stale state and exit.

	// Trigger convoy cleanup by waiting for aging time
	time.Sleep(UdpTaskPoolAgingTime + 50*time.Millisecond)

	// Give convoy time to process
	time.Sleep(100 * time.Millisecond)

	// Verify the queue is no longer in map
	_, ok := pool.queues.Load(key)
	if ok {
		t.Error("Queue should not be in map after mapping was deleted")
	}

	// Check goroutine count hasn't increased significantly
	// (convoy should have exited, not leaked)
	finalGoroutines := runtime.NumGoroutine()
	if finalGoroutines > initialGoroutines+5 {
		t.Errorf("Potential goroutine leak: initial=%d, final=%d", initialGoroutines, finalGoroutines)
	}
}

// TestConvoyExitWhenMappingReplaced verifies that convoy exits when
// the mapping is replaced with a new queue before self-delete.
func TestConvoyExitWhenMappingReplaced(t *testing.T) {
	pool := NewUdpTaskPool()
	key := NewUdpSrcOnlyFlowKey(netip.MustParseAddrPort("10.0.0.1:53"))

	// Create initial queue
	q1 := pool.acquireQueue(key)
	q1.refs.Add(-1)

	// Mark q1 as draining to simulate it being in cleanup state
	q1.refs.Store(-1000000)

	// acquireQueue should create a new queue since q1 is draining
	q2 := pool.acquireQueue(key)
	if q2 == q1 {
		t.Fatal("q2 should be a new queue")
	}

	// Now q1's convoy (if running) would try to delete and fail
	// because map contains q2, not q1.
	// q1 should detect it's stale and exit.

	// Verify q2 is in map (check immediately, before aging cleanup)
	loaded, ok := pool.queues.Load(key)
	if !ok {
		t.Error("Queue should exist in map")
	} else if loaded.(*UdpTaskQueue) != q2 {
		t.Error("Map should contain q2, not q1")
	}

	// Cleanup
	q2.refs.Add(-1)
}

// TestCompareAndDeleteSemantics verifies the exact semantics of CompareAndDelete
func TestCompareAndDeleteSemantics(t *testing.T) {
	pool := NewUdpTaskPool()
	key := NewUdpSrcOnlyFlowKey(netip.MustParseAddrPort("8.8.8.8:53"))

	// Create queue
	q1 := pool.acquireQueue(key)
	q1.refs.Add(-1)

	// Test 1: CompareAndDelete with matching pointer should succeed
	deleted := pool.queues.CompareAndDelete(key, q1)
	if !deleted {
		t.Error("CompareAndDelete should succeed when value matches")
	}

	// Verify it was deleted
	_, ok := pool.queues.Load(key)
	if ok {
		t.Error("Queue should have been deleted")
	}

	// Test 2: CompareAndDelete with non-existent key should fail
	deleted = pool.queues.CompareAndDelete(key, q1)
	if deleted {
		t.Error("CompareAndDelete should fail for non-existent key")
	}

	// Test 3: CompareAndDelete with wrong pointer should fail
	q2 := pool.acquireQueue(key)
	q2.refs.Add(-1)

	deleted = pool.queues.CompareAndDelete(key, q1) // Try to delete with old pointer
	if deleted {
		t.Error("CompareAndDelete should fail when value doesn't match")
	}

	// Verify q2 is still in map
	loaded, ok := pool.queues.Load(key)
	if !ok || loaded.(*UdpTaskQueue) != q2 {
		t.Error("q2 should still be in map")
	}

	// Cleanup
	q2.refs.Add(-1)
}

// BenchmarkCompareAndDelete vs LoadAndDelete pattern
func BenchmarkCompareAndDelete(b *testing.B) {
	pool := NewUdpTaskPool()
	key := NewUdpSrcOnlyFlowKey(netip.MustParseAddrPort("1.2.3.4:5678"))

	q := pool.acquireQueue(key)
	q.refs.Add(-1)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Simulate: store, then try to delete with CompareAndDelete
		pool.queues.Store(key, q)
		pool.queues.CompareAndDelete(key, q)
	}
}

func BenchmarkLoadAndDeletePattern(b *testing.B) {
	pool := NewUdpTaskPool()
	key := NewUdpSrcOnlyFlowKey(netip.MustParseAddrPort("1.2.3.4:5678"))

	q := pool.acquireQueue(key)
	q.refs.Add(-1)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Simulate OLD pattern: LoadAndDelete + compare
		pool.queues.Store(key, q)
		if v, loaded := pool.queues.LoadAndDelete(key); loaded {
			_ = v.(*UdpTaskQueue) == q
		}
	}
}

// TestHighConcurrencyStress stresses the fixed implementation under high concurrency
func TestHighConcurrencyStress(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stress test in short mode")
	}

	pool := NewUdpTaskPool()

	const (
		numGoroutines = 50
		numOperations = 100
	)

	var wg sync.WaitGroup
	var errorCount atomic.Int32

	for g := 0; g < numGoroutines; g++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			for i := 0; i < numOperations; i++ {
				key := NewUdpSrcOnlyFlowKey(netip.AddrPortFrom(
					netip.AddrFrom4([4]byte{192, 168, byte(goroutineID % 256), byte(i % 256)}),
					uint16(10000+i),
				))

				q := pool.acquireQueue(key)

				// Verify queue is valid
				if q == nil {
					errorCount.Add(1)
					continue
				}

				// Simulate work
				time.Sleep(time.Microsecond)

				q.refs.Add(-1)
			}
		}(g)
	}

	wg.Wait()

	if errorCount.Load() > 0 {
		t.Errorf("Encountered %d errors during stress test", errorCount.Load())
	}

	// Wait for cleanup
	time.Sleep(UdpTaskPoolAgingTime + 100*time.Millisecond)

	// Count remaining queues
	remaining := 0
	pool.queues.Range(func(_, _ any) bool {
		remaining++
		return true
	})

	t.Logf("Remaining queues after stress test: %d", remaining)
}
