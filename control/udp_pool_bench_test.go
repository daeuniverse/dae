/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net/netip"
	"sync"
	"testing"
	"time"
)

// mockAnyfromPoolOld simulates the OLD GetOrCreate logic.
type mockAnyfromPoolOld struct {
	shards [64]struct {
		mu   sync.RWMutex
		pool map[netip.AddrPort]*mockAnyfrom
	}
}

type mockAnyfrom struct {
	expiresAtNano int64
	ttl           time.Duration
}

func (m *mockAnyfrom) RefreshTtl() {
	if m.ttl > 0 {
		m.expiresAtNano = time.Now().Add(m.ttl).UnixNano()
	}
}

func newMockAnyfromPoolOld() *mockAnyfromPoolOld {
	p := &mockAnyfromPoolOld{}
	for i := range p.shards {
		p.shards[i].pool = make(map[netip.AddrPort]*mockAnyfrom)
	}
	return p
}

func (p *mockAnyfromPoolOld) shardFor(lAddr netip.AddrPort) *struct {
	mu   sync.RWMutex
	pool map[netip.AddrPort]*mockAnyfrom
} {
	idx := int(hashAddrPort(lAddr) & 63)
	return &p.shards[idx]
}

func (p *mockAnyfromPoolOld) GetOrCreate(lAddr netip.AddrPort, ttl time.Duration) (*mockAnyfrom, bool, error) {
	shard := p.shardFor(lAddr)
	shard.mu.RLock()
	af, ok := shard.pool[lAddr]
	if !ok {
		shard.mu.RUnlock()
		shard.mu.Lock()
		defer shard.mu.Unlock()
		if af, ok = shard.pool[lAddr]; ok {
			af.RefreshTtl()
			return af, false, nil
		}
		// Simulate socket creation (minimal overhead for benchmark)
		af = &mockAnyfrom{ttl: ttl}
		if ttl > 0 {
			af.RefreshTtl()
			shard.pool[lAddr] = af
		}
		return af, true, nil
	}
	af.RefreshTtl()
	shard.mu.RUnlock()
	return af, false, nil
}

// mockAnyfromPoolNew simulates the NEW GetOrCreate logic (socket created outside lock).
type mockAnyfromPoolNew struct {
	shards [64]struct {
		mu   sync.RWMutex
		pool map[netip.AddrPort]*mockAnyfrom
	}
}

func newMockAnyfromPoolNew() *mockAnyfromPoolNew {
	p := &mockAnyfromPoolNew{}
	for i := range p.shards {
		p.shards[i].pool = make(map[netip.AddrPort]*mockAnyfrom)
	}
	return p
}

func (p *mockAnyfromPoolNew) shardFor(lAddr netip.AddrPort) *struct {
	mu   sync.RWMutex
	pool map[netip.AddrPort]*mockAnyfrom
} {
	idx := int(hashAddrPort(lAddr) & 63)
	return &p.shards[idx]
}

func (p *mockAnyfromPoolNew) createSocket(lAddr netip.AddrPort, ttl time.Duration) (*mockAnyfrom, error) {
	// Simulate socket creation (minimal overhead for benchmark)
	return &mockAnyfrom{ttl: ttl}, nil
}

func (p *mockAnyfromPoolNew) GetOrCreate(lAddr netip.AddrPort, ttl time.Duration) (*mockAnyfrom, bool, error) {
	shard := p.shardFor(lAddr)
	shard.mu.RLock()
	af, ok := shard.pool[lAddr]
	if ok {
		af.RefreshTtl()
		shard.mu.RUnlock()
		return af, false, nil
	}
	shard.mu.RUnlock()

	// Not found in cache. Create socket outside the lock.
	newAf, _ := p.createSocket(lAddr, ttl)

	// Acquire write lock to check if another goroutine already created it.
	shard.mu.Lock()
	defer shard.mu.Unlock()

	if af, ok = shard.pool[lAddr]; ok {
		// Another goroutine created it while we were creating the socket.
		// Close our duplicate and return the existing one.
		// (In real code: newAf.Close())
		af.RefreshTtl()
		return af, false, nil
	}

	// Store the newly created socket.
	shard.pool[lAddr] = newAf
	return newAf, true, nil
}

// BenchmarkPoolGetOrCreate_Old_Hit benchmarks OLD pool with cache hit.
func BenchmarkPoolGetOrCreate_Old_Hit(b *testing.B) {
	p := newMockAnyfromPoolOld()
	addr := mustParseAddrPort("192.168.1.1:12345")
	// Pre-populate
	p.GetOrCreate(addr, 5*time.Second)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			p.GetOrCreate(addr, 5*time.Second)
		}
	})
}

// BenchmarkPoolGetOrCreate_New_Hit benchmarks NEW pool with cache hit.
func BenchmarkPoolGetOrCreate_New_Hit(b *testing.B) {
	p := newMockAnyfromPoolNew()
	addr := mustParseAddrPort("192.168.1.1:12345")
	// Pre-populate
	p.GetOrCreate(addr, 5*time.Second)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			p.GetOrCreate(addr, 5*time.Second)
		}
	})
}

// BenchmarkPoolGetOrCreate_Old_Miss benchmarks OLD pool with cache miss (single key).
func BenchmarkPoolGetOrCreate_Old_Miss(b *testing.B) {
	p := newMockAnyfromPoolOld()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		addr := mustParseAddrPort("192.168.1.1:12345")
		p.GetOrCreate(addr, 5*time.Second)
		p.shards[0].pool = make(map[netip.AddrPort]*mockAnyfrom)
	}
}

// BenchmarkPoolGetOrCreate_New_Miss benchmarks NEW pool with cache miss (single key).
func BenchmarkPoolGetOrCreate_New_Miss(b *testing.B) {
	p := newMockAnyfromPoolNew()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		addr := mustParseAddrPort("192.168.1.1:12345")
		p.GetOrCreate(addr, 5*time.Second)
		p.shards[0].pool = make(map[netip.AddrPort]*mockAnyfrom)
	}
}

// BenchmarkPoolGetOrCreate_Old_ConcurrentMiss benchmarks OLD pool with concurrent cache misses.
func BenchmarkPoolGetOrCreate_Old_ConcurrentMiss(b *testing.B) {
	p := newMockAnyfromPoolOld()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			addr := mustParseAddrPort("192.168.1.1:12345")
			p.GetOrCreate(addr, 5*time.Second)
			i++
			if i > 1000 {
				// Reset pool to simulate new connections
				p.shards[0].pool = make(map[netip.AddrPort]*mockAnyfrom)
				i = 0
			}
		}
	})
}

// BenchmarkPoolGetOrCreate_New_ConcurrentMiss benchmarks NEW pool with concurrent cache misses.
func BenchmarkPoolGetOrCreate_New_ConcurrentMiss(b *testing.B) {
	p := newMockAnyfromPoolNew()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			addr := mustParseAddrPort("192.168.1.1:12345")
			p.GetOrCreate(addr, 5*time.Second)
			i++
			if i > 1000 {
				// Reset pool to simulate new connections
				p.shards[0].pool = make(map[netip.AddrPort]*mockAnyfrom)
				i = 0
			}
		}
	})
}
