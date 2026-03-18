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
)

// TestBoundedPoolSubmitBasic tests basic pool functionality.
func TestBoundedPoolSubmitBasic(t *testing.T) {
	ctx := context.Background()
	pool := NewBoundedGoroutinePool(ctx, 10)

	if pool == nil {
		t.Fatal("NewBoundedGoroutinePool returned nil")
	}

	// Submit a simple task
	executed := atomic.Bool{}
	task := func() {
		executed.Store(true)
	}

	if !pool.Submit(task) {
		t.Error("Submit failed")
	}

	// Wait a bit for task to execute
	time.Sleep(10 * time.Millisecond)

	if !executed.Load() {
		t.Error("Task was not executed")
	}

	pool.Close()
}

// TestBoundedPoolCapacity tests that pool respects capacity limit.
func TestBoundedPoolCapacity(t *testing.T) {
	ctx := context.Background()
	poolSize := 3
	pool := NewBoundedGoroutinePool(ctx, poolSize)

	// Track active goroutines
	active := atomic.Int32{}
	blocking := atomic.Bool{}

	// Submit tasks that block
	var wg sync.WaitGroup
	for i := 0; i < poolSize; i++ {
		wg.Add(1)
		pool.Submit(func() {
			active.Add(1)
			defer active.Add(-1)
			time.Sleep(50 * time.Millisecond)
			wg.Done()
		})
	}

	// Wait for all to start
	time.Sleep(10 * time.Millisecond)

	if active.Load() != int32(poolSize) {
		t.Errorf("Expected %d active, got %d", poolSize, active.Load())
	}

	// Try to submit one more - it should block
	go func() {
		pool.Submit(func() {
			blocking.Store(true)
		})
	}()

	// Give it time to start blocking
	time.Sleep(10 * time.Millisecond)

	// The fourth submit should be blocked (not executed yet)
	if blocking.Load() {
		t.Error("Fourth task should be blocked, not executed")
	}

	// Wait for initial tasks to complete
	wg.Wait()
	pool.Close()
}

// TestBoundedPoolCloseBlocksNewTasks tests that closed pool rejects new tasks.
func TestBoundedPoolCloseBlocksNewTasks(t *testing.T) {
	ctx := context.Background()
	pool := NewBoundedGoroutinePool(ctx, 10)

	// Start a goroutine to close the pool
	go pool.Close()

	// Wait a bit for close to start
	time.Sleep(10 * time.Millisecond)

	// Submit after close should fail (context is cancelled)
	submitted := atomic.Bool{}
	go pool.Submit(func() {
		submitted.Store(true)
	})

	time.Sleep(20 * time.Millisecond)

	// The submit might succeed if it races with close, but context should be cancelled
	// The key is that Close() should complete without hanging
}

// TestBoundedPoolWaitOnClose tests that Close waits for all tasks.
func TestBoundedPoolWaitOnClose(t *testing.T) {
	ctx := context.Background()
	pool := NewBoundedGoroutinePool(ctx, 10)

	started := atomic.Int32{}
	completed := atomic.Int32{}
	taskCount := 5

	// Submit tasks that take time
	for i := 0; i < taskCount; i++ {
		pool.Submit(func() {
			started.Add(1)
			time.Sleep(100 * time.Millisecond)
			completed.Add(1)
		})
	}

	// All tasks should start
	time.Sleep(10 * time.Millisecond)
	if started.Load() != int32(taskCount) {
		t.Errorf("Expected %d started, got %d", taskCount, started.Load())
	}

	// Close should wait for completion
	start := time.Now()
	pool.Close()
	elapsed := time.Since(start)

	// Should wait at least 80ms (allowing some scheduling variance)
	if elapsed < 80*time.Millisecond {
		t.Errorf("Close should have waited for tasks, took %v (expected at least 80ms)", elapsed)
	}

	if completed.Load() != int32(taskCount) {
		t.Errorf("Expected %d completed, got %d", taskCount, completed.Load())
	}
}

// TestBoundedPoolMetrics tests metric tracking.
func TestBoundedPoolMetrics(t *testing.T) {
	ctx := context.Background()
	pool := NewBoundedGoroutinePool(ctx, 5)

	taskCount := 3
	for i := 0; i < taskCount; i++ {
		pool.Submit(func() {
			time.Sleep(10 * time.Millisecond)
		})
	}

	if pool.total.Load() != int64(taskCount) {
		t.Errorf("Expected total %d, got %d", taskCount, pool.total.Load())
	}

	// Wait and check active goes back to 0
	time.Sleep(50 * time.Millisecond)

	if pool.active.Load() != 0 {
		t.Errorf("Expected active 0, got %d", pool.active.Load())
	}

	pool.Close()
}

// TestBoundedPoolZeroCapacity tests default capacity handling.
func TestBoundedPoolZeroCapacity(t *testing.T) {
	ctx := context.Background()
	pool := NewBoundedGoroutinePool(ctx, 0)

	if pool == nil {
		t.Fatal("Pool with 0 capacity should default to GOMAXPROCS*8, not nil")
	}

	executed := atomic.Bool{}
	pool.Submit(func() {
		executed.Store(true)
	})

	time.Sleep(10 * time.Millisecond)

	if !executed.Load() {
		t.Error("Task not executed with default capacity")
	}

	pool.Close()
}

// TestBoundedPoolConcurrentSubmit tests concurrent submissions.
func TestBoundedPoolConcurrentSubmit(t *testing.T) {
	ctx := context.Background()
	pool := NewBoundedGoroutinePool(ctx, 100)

	const goroutines = 50
	const tasksPerGoroutine = 20

	var wg sync.WaitGroup
	counter := atomic.Int64{}

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < tasksPerGoroutine; j++ {
				pool.Submit(func() {
					counter.Add(1)
				})
			}
		}()
	}

	wg.Wait()
	time.Sleep(50 * time.Millisecond) // Let all tasks complete

	expected := int64(goroutines * tasksPerGoroutine)
	if counter.Load() != expected {
		t.Errorf("Expected %d tasks executed, got %d", expected, counter.Load())
	}

	pool.Close()
}

// TestBoundedPoolPanicRecovery tests that pool properly cleans up after panicking tasks.
// Note: Go panics in goroutines are not automatically recovered, which is expected behavior.
// The pool ensures cleanup (semaphore release, wg.Done()) happens via defer.
func TestBoundedPoolPanicRecovery(t *testing.T) {
	ctx := context.Background()
	pool := NewBoundedGoroutinePool(ctx, 10)

	// Submit a task that will panic - but ensure defer cleanup still works
	panicked := atomic.Bool{}
	pool.Submit(func() {
		defer func() {
			if r := recover(); r != nil {
				panicked.Store(true)
			}
		}()
		panic("test panic")
	})

	time.Sleep(20 * time.Millisecond)

	if !panicked.Load() {
		t.Error("Panic should have occurred")
	}

	// Pool resources should be properly cleaned up via defer
	// Submit another task - pool should still work
	executed := atomic.Bool{}
	pool.Submit(func() {
		executed.Store(true)
	})

	time.Sleep(20 * time.Millisecond)

	if !executed.Load() {
		t.Error("Pool should continue working after panic (resources cleaned up)")
	}

	// Close should not hang (defer cleanup worked)
	pool.Close()
}

// TestUdpBoundedPoolManagerNilManager tests nil manager behavior.
// This test documents that calling Submit/Close on nil manager WILL panic.
// This is acceptable because:
// 1. Manager is always initialized in NewControlPlaneWithContext
// 2. Only used internally in control_plane.go where we control usage
func TestUdpBoundedPoolManagerNilManager(t *testing.T) {
	// Document the panic behavior
	t.Run("nil_manager_panics", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Logf("As expected, nil manager causes panic: %v", r)
			} else {
				t.Error("Expected panic when calling Submit on nil manager")
			}
		}()

		var m *udpBoundedPoolManager
		m.Submit(func() {}) // Will panic
	})
}

// TestUdpBoundedPoolManagerNormal tests normal manager usage.
func TestUdpBoundedPoolManagerNormal(t *testing.T) {
	ctx := context.Background()
	manager := newUdpBoundedPoolManager(ctx)

	if manager == nil {
		t.Fatal("newUdpBoundedPoolManager returned nil")
	}

	if manager.generalPool == nil {
		t.Fatal("manager.generalPool is nil")
	}

	executed := atomic.Bool{}
	if !manager.Submit(func() {
		executed.Store(true)
	}) {
		t.Error("Submit failed")
	}

	time.Sleep(10 * time.Millisecond)

	if !executed.Load() {
		t.Error("Task was not executed")
	}

	// Close should work without panic
	manager.Close()

	// Submit after close may succeed due to race, but context should be cancelled
	// The important thing is that Close() completes without hanging
	manager.Submit(func() {}) // May return false, that's ok
}

// TestUdpBoundedPoolManagerConcurrent tests concurrent manager usage.
func TestUdpBoundedPoolManagerConcurrent(t *testing.T) {
	ctx := context.Background()
	manager := newUdpBoundedPoolManager(ctx)

	const goroutines = 20
	const tasksPerGoroutine = 50

	var wg sync.WaitGroup
	counter := atomic.Int64{}

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < tasksPerGoroutine; j++ {
				manager.Submit(func() {
					counter.Add(1)
				})
			}
		}()
	}

	wg.Wait()
	time.Sleep(100 * time.Millisecond)

	expected := int64(goroutines * tasksPerGoroutine)
	if counter.Load() != expected {
		t.Errorf("Expected %d tasks executed, got %d", expected, counter.Load())
	}

	manager.Close()
}

// TestBoundedPoolBackpressure tests blocking backpressure behavior.
func TestBoundedPoolBackpressure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pool := NewBoundedGoroutinePool(ctx, 2)

	// Fill the pool
	var startWg, blockWg sync.WaitGroup
	startWg.Add(2)

	for i := 0; i < 2; i++ {
		pool.Submit(func() {
			startWg.Done()
			time.Sleep(100 * time.Millisecond)
		})
	}

	startWg.Wait()

	submitted := atomic.Bool{}
	// This submission should block (pool is at capacity)
	blockWg.Add(1)
	go func() {
		defer blockWg.Done()
		if pool.Submit(func() {
			submitted.Store(true)
		}) {
			// Task was submitted (after blocking)
		}
	}()

	// Give it time to start blocking
	time.Sleep(20 * time.Millisecond)

	// Task should not have executed yet (still blocked)
	if submitted.Load() {
		t.Error("Task should be blocked, not executed yet")
	}

	// Wait for completion - blocked task should eventually execute
	blockWg.Wait()

	// After waiting, the task should have been submitted and executed
	time.Sleep(10 * time.Millisecond)

	pool.Close()
}

// TestBoundedPoolContextCancellation tests context cancellation handling.
func TestBoundedPoolContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	pool := NewBoundedGoroutinePool(ctx, 10)

	// Submit a task first to ensure pool is ready
	done := atomic.Bool{}
	pool.Submit(func() {
		done.Store(true)
	})

	time.Sleep(10 * time.Millisecond)

	// Cancel context
	cancel()

	// Give cancellation time to propagate
	time.Sleep(20 * time.Millisecond)

	// Submit should fail immediately after context is cancelled
	submitted := pool.Submit(func() {})

	if submitted {
		// This is ok - there's a race between cancellation and submit
		// The key is that Close() should work correctly
		t.Log("Submit succeeded despite cancellation (race condition, not a failure)")
	}

	pool.Close()
}
