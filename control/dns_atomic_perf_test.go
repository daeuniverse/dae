/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@daeuniverse.org>
 */

package control

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// BenchmarkCacheAccessWithLastAccessUpdate benchmarks cache access with lastAccessNano update
func BenchmarkCacheAccessWithLastAccessUpdate(b *testing.B) {
	cache := &DnsCache{
		DomainBitmap: []uint32{1},
		Deadline:     time.Now().Add(time.Hour),
	}
	
	now := time.Now()
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		// Simulate cache access pattern
		cache.lastAccessNano.Store(now.UnixNano())
		_ = cache.lastAccessNano.Load()
	}
}

// BenchmarkCacheAccessWithoutLastAccess benchmarks cache access without lastAccessNano update
func BenchmarkCacheAccessWithoutLastAccess(b *testing.B) {
	cache := &DnsCache{
		DomainBitmap: []uint32{1},
		Deadline:     time.Now().Add(time.Hour),
	}
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		// Simulate cache access without update
		_ = cache.lastAccessNano.Load()
	}
}

// BenchmarkAtomicOperations compares different atomic operation patterns
func BenchmarkAtomicInt64Store(b *testing.B) {
	var val atomic.Int64
	now := time.Now().UnixNano()
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		val.Store(now)
	}
}

func BenchmarkAtomicInt64Load(b *testing.B) {
	var val atomic.Int64
	val.Store(time.Now().UnixNano())
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		_ = val.Load()
	}
}

func BenchmarkAtomicInt64Swap(b *testing.B) {
	var val atomic.Int64
	val.Store(time.Now().UnixNano())
	now := time.Now().UnixNano()
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		_ = val.Swap(now)
	}
}

// BenchmarkMutexVsAtomic compares mutex vs atomic for frequent updates
type CacheWithMutex struct {
	mu          sync.RWMutex
	lastAccess  int64
}

type CacheWithAtomic struct {
	lastAccess atomic.Int64
}

func BenchmarkLastAccess_Mutex(b *testing.B) {
	cache := &CacheWithMutex{}
	now := time.Now().UnixNano()
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		cache.mu.Lock()
		cache.lastAccess = now
		cache.mu.Unlock()
	}
}

func BenchmarkLastAccess_MutexRWMutex(b *testing.B) {
	cache := &CacheWithMutex{}
	cache.lastAccess = time.Now().UnixNano()
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		cache.mu.RLock()
		_ = cache.lastAccess
		cache.mu.RUnlock()
	}
}

func BenchmarkLastAccess_Atomic(b *testing.B) {
	cache := &CacheWithAtomic{}
	now := time.Now().UnixNano()
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		cache.lastAccess.Store(now)
	}
}

func BenchmarkLastAccess_AtomicRead(b *testing.B) {
	cache := &CacheWithAtomic{}
	cache.lastAccess.Store(time.Now().UnixNano())
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		_ = cache.lastAccess.Load()
	}
}

// BenchmarkConcurrentAccess simulates concurrent cache access
func BenchmarkConcurrentAccess_Atomic(b *testing.B) {
	cache := &DnsCache{
		DomainBitmap: []uint32{1},
		Deadline:     time.Now().Add(time.Hour),
	}
	
	now := time.Now()
	
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			cache.lastAccessNano.Store(now.UnixNano())
		}
	})
}

func BenchmarkConcurrentAccess_AtomicRead(b *testing.B) {
	cache := &DnsCache{
		DomainBitmap: []uint32{1},
		Deadline:     time.Now().Add(time.Hour),
	}
	cache.lastAccessNano.Store(time.Now().UnixNano())
	
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = cache.lastAccessNano.Load()
		}
	})
}
