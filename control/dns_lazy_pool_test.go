/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
)

// TestLazyConnPool_BasicInit tests normal initialization and close path.
func TestLazyConnPool_BasicInit(t *testing.T) {
	var pool lazyConnPool
	initCount := atomic.Int32{}

	getPool := func() *connPool {
		return pool.getOrInit(func() *connPool {
			initCount.Add(1)
			return newConnPool(2, func(ctx context.Context) (netproxy.Conn, error) {
				return nil, nil
			})
		})
	}

	// First get should initialize
	p1 := getPool()
	if p1 == nil {
		t.Fatal("expected non-nil pool")
	}
	if initCount.Load() != 1 {
		t.Errorf("expected 1 init, got %d", initCount.Load())
	}

	// Second get should return same pool
	p2 := getPool()
	if p1 != p2 {
		t.Error("expected same pool instance")
	}
	if initCount.Load() != 1 {
		t.Errorf("expected still 1 init, got %d", initCount.Load())
	}

	// Close should work
	if err := pool.closePool(); err != nil {
		t.Errorf("close failed: %v", err)
	}
}

// TestLazyConnPool_InitOnlyOnce tests that sync.Once ensures single initialization.
func TestLazyConnPool_InitOnlyOnce(t *testing.T) {
	var pool lazyConnPool
	initCount := atomic.Int32{}

	// Concurrent gets
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pool.getOrInit(func() *connPool {
				time.Sleep(time.Microsecond) // Increase race window
				initCount.Add(1)
				return newConnPool(2, func(ctx context.Context) (netproxy.Conn, error) {
					return nil, nil
				})
			})
		}()
	}
	wg.Wait()

	if initCount.Load() != 1 {
		t.Errorf("expected exactly 1 init, got %d", initCount.Load())
	}
}

// TestLazyConnPool_CloseTwice tests idempotent close.
func TestLazyConnPool_CloseTwice(t *testing.T) {
	var pool lazyConnPool

	pool.getOrInit(func() *connPool {
		return newConnPool(2, func(ctx context.Context) (netproxy.Conn, error) {
			return nil, nil
		})
	})

	if err := pool.closePool(); err != nil {
		t.Errorf("first close failed: %v", err)
	}
	if err := pool.closePool(); err != nil {
		t.Errorf("second close failed: %v", err)
	}
}

// TestLazyConnPool_CloseThenGet tests behavior after close.
// This documents the current sync.Once behavior: getOrInit after close returns nil.
func TestLazyConnPool_CloseThenGet(t *testing.T) {
	var pool lazyConnPool
	initCount := atomic.Int32{}

	// Normal path: init, use, close
	p1 := pool.getOrInit(func() *connPool {
		initCount.Add(1)
		return newConnPool(2, func(ctx context.Context) (netproxy.Conn, error) {
			return nil, nil
		})
	})
	if p1 == nil {
		t.Fatal("expected non-nil pool on first get")
	}

	if err := pool.closePool(); err != nil {
		t.Errorf("close failed: %v", err)
	}

	// sync.Once behavior: getOrInit after close returns nil
	// This is acceptable because forwarders are never reused after close
	p2 := pool.getOrInit(func() *connPool {
		initCount.Add(1) // This will NOT be called
		return newConnPool(2, func(ctx context.Context) (netproxy.Conn, error) {
			return nil, nil
		})
	})

	if p2 != nil {
		t.Errorf("expected nil pool after close, got non-nil")
	}
	if initCount.Load() != 1 {
		t.Errorf("expected no re-init, got %d inits", initCount.Load())
	}

	t.Log("NOTE: close-then-get returns nil (sync.Once semantics)")
	t.Log("This is acceptable because forwarders are discarded after close in actual usage")
}

// TestLazyConnPool_ConcurrentCloseAndGet tests concurrent close and get operations.
func TestLazyConnPool_ConcurrentCloseAndGet(t *testing.T) {
	var pool lazyConnPool
	initCount := atomic.Int32{}
	var closeCount atomic.Int32
	var getCount atomic.Int64

	var wg sync.WaitGroup
	iterations := 100

	// Start getters
	for i := 0; i < iterations; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p := pool.getOrInit(func() *connPool {
				initCount.Add(1)
				return newConnPool(2, func(ctx context.Context) (netproxy.Conn, error) {
					return nil, nil
				})
			})
			getCount.Add(1)
			if p != nil {
				// Just check non-nil, don't use the pool after close
				// (connPool has existing issues with concurrent close+use)
			}
		}()
	}

	// Start closers (after a small delay)
	go func() {
		time.Sleep(10 * time.Microsecond)
		for i := 0; i < 5; i++ {
			time.Sleep(time.Microsecond)
			pool.closePool()
			closeCount.Add(1)
		}
	}()

	wg.Wait()

	t.Logf("Inits: %d, Closes: %d, Gets: %d", initCount.Load(), closeCount.Load(), getCount.Load())
	if initCount.Load() != 1 {
		t.Errorf("expected exactly 1 init, got %d", initCount.Load())
	}
}

// TestLazyConnPool_RealWorldPattern simulates actual usage pattern.
func TestLazyConnPool_RealWorldPattern(t *testing.T) {
	// Simulate DnsController cache behavior
	type forwarder struct {
		pool lazyConnPool
	}

	forwarders := make(map[string]*forwarder)
	var mu sync.Mutex

	getForwarder := func(key string) *forwarder {
		mu.Lock()
		defer mu.Unlock()
		if f, ok := forwarders[key]; ok {
			return f
		}
		f := &forwarder{}
		forwarders[key] = f
		return f
	}

	useForwarder := func(key string) {
		f := getForwarder(key)
		p := f.pool.getOrInit(func() *connPool {
			return newConnPool(2, func(ctx context.Context) (netproxy.Conn, error) {
				return nil, nil
			})
		})
		if p != nil {
			// Simulate using the pool
		}
	}

	evictForwarder := func(key string) {
		mu.Lock()
		defer mu.Unlock()
		if f, ok := forwarders[key]; ok {
			f.pool.closePool()
			delete(forwarders, key) // Key: forwarder is DISCARDED after close
		}
	}

	// Simulate usage pattern
	for i := 0; i < 10; i++ {
		useForwarder("key1")
	}
	evictForwarder("key1")

	// After eviction, new request creates NEW forwarder
	useForwarder("key1") // This creates a new forwarder with new lazyConnPool

	if len(forwarders) != 1 {
		t.Errorf("expected 1 forwarder, got %d", len(forwarders))
	}

	// Verify the new forwarder works
	f := forwarders["key1"]
	if f == nil {
		t.Fatal("forwarder should exist")
	}
	// New lazyConnPool should work normally
	p := f.pool.getOrInit(func() *connPool {
		return newConnPool(2, func(ctx context.Context) (netproxy.Conn, error) {
			return nil, nil
		})
	})
	if p == nil {
		t.Error("new forwarder pool should be initialized")
	}
}

// TestLazyConnPool_DoTLSPattern simulates DoTLS usage specifically.
func TestLazyConnPool_DoTLSPattern(t *testing.T) {
	// Simulate the actual DoTLS pattern
	type DoTLSMock struct {
		lazyConnPool
		closed atomic.Bool
	}

	forwarder := &DoTLSMock{}

	// Pattern 1: ForwardDNS creates pool
	for i := 0; i < 10; i++ {
		pool := forwarder.getOrInit(func() *connPool {
			return newConnPool(2, func(ctx context.Context) (netproxy.Conn, error) {
				return nil, nil
			})
		})
		if pool == nil {
			t.Error("pool should be created on first use")
		}
	}

	// Pattern 2: Close is called when forwarder is evicted
	if err := forwarder.closePool(); err != nil {
		t.Errorf("close failed: %v", err)
	}
	forwarder.closed.Store(true)

	// Pattern 3: After eviction, forwarder is DISCARDED
	// A new DoTLS object would be created for next request
	// The old forwarder.closePool() nils the pool, sync.Once prevents re-init

	if !forwarder.closed.Load() {
		t.Error("forwarder should be marked closed")
	}

	// This documents the behavior: attempting to use closed forwarder returns nil
	pool := forwarder.getOrInit(func() *connPool {
		t.Error("init should not be called after close")
		return newConnPool(2, func(ctx context.Context) (netproxy.Conn, error) {
			return nil, nil
		})
	})
	if pool != nil {
		t.Errorf("using closed forwarder should return nil, got %v", pool)
	}
}

// BenchmarkLazyConnPool_Get compares performance.
func BenchmarkLazyConnPool_Get(b *testing.B) {
	var pool lazyConnPool
	pool.getOrInit(func() *connPool {
		return newConnPool(2, func(ctx context.Context) (netproxy.Conn, error) {
			return nil, nil
		})
	})

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			p := pool.getOrInit(func() *connPool {
				return newConnPool(2, func(ctx context.Context) (netproxy.Conn, error) {
					return nil, nil
				})
			})
			if p != nil {
				// use pool
			}
		}
	})
}

// TestLazyConnPool_NilGet tests getOrInit when pool is nil (after close).
func TestLazyConnPool_NilGet(t *testing.T) {
	var pool lazyConnPool

	// Close without ever initializing
	if err := pool.closePool(); err != nil {
		t.Errorf("close of nil pool should succeed, got: %v", err)
	}

	// Get after close: should return nil (closed flag prevents new init)
	p := pool.getOrInit(func() *connPool {
		t.Error("init function should not run after close")
		return newConnPool(2, func(ctx context.Context) (netproxy.Conn, error) {
			return nil, nil
		})
	})

	// With atomic.Value + closed flag, close prevents new initialization
	if p != nil {
		t.Error("getOrInit should return nil after close")
	}

	t.Log("NOTE: Once closed, lazyConnPool cannot be reinitialized.")
	t.Log("This is acceptable because forwarders are discarded after close.")
}
