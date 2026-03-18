/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// BenchmarkRefreshTtl_Old benchmarks the OLD simple RefreshTtl.
func BenchmarkRefreshTtl_Old(b *testing.B) {
	var expiresAtNano atomic.Int64
	ttl := 5 * time.Second

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		refreshTtlOld(&expiresAtNano, ttl)
	}
}

// BenchmarkRefreshTtl_New benchmarks the NEW throttled RefreshTtl.
func BenchmarkRefreshTtl_New(b *testing.B) {
	var lastRefreshNano atomic.Int64
	var expiresAtNano atomic.Int64
	ttl := 5 * time.Second

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		refreshTtlNew(&lastRefreshNano, &expiresAtNano, ttl)
	}
}

// refreshTtlOld is the OLD version: simple atomic store.
func refreshTtlOld(expiresAtNano *atomic.Int64, ttl time.Duration) {
	if ttl > 0 {
		expiresAtNano.Store(time.Now().Add(ttl).UnixNano())
	}
}

// refreshTtlNew is the NEW version with throttling.
func refreshTtlNew(lastRefreshNano, expiresAtNano *atomic.Int64, ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	now := time.Now().UnixNano()
	last := lastRefreshNano.Load()
	minInterval := ttlRefreshMinInterval
	if ttlNano := int64(ttl); ttlNano > 10*ttlRefreshMinInterval {
		minInterval = ttlNano / 50
	}
	if now-last < minInterval {
		return
	}
	if lastRefreshNano.CompareAndSwap(last, now) {
		expiresAtNano.Store(now + int64(ttl))
	}
}

// BenchmarkRefreshTtl_New_Hit benchmarks the NEW version when throttle is hit (skip refresh).
func BenchmarkRefreshTtl_New_Hit(b *testing.B) {
	var lastRefreshNano atomic.Int64
	var expiresAtNano atomic.Int64
	ttl := 5 * time.Second
	// Pre-set lastRefreshNano to recent time to trigger throttle skip
	lastRefreshNano.Store(time.Now().UnixNano())

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		refreshTtlNew(&lastRefreshNano, &expiresAtNano, ttl)
	}
}

// BenchmarkAnyfromWriteTo_Old simulates OLD WriteTo pattern with defer.
func BenchmarkAnyfromWriteTo_Old(b *testing.B) {
	conn := &net.UDPConn{} // Dummy
	expiresAtNano := atomic.Int64{}
	ttl := 5 * time.Second

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		func() {
			defer refreshTtlOld(&expiresAtNano, ttl)
			// Simulate write operation
			_ = conn
		}()
	}
}

// BenchmarkAnyfromWriteTo_New simulates NEW WriteTo pattern with manual call.
func BenchmarkAnyfromWriteTo_New(b *testing.B) {
	conn := &net.UDPConn{} // Dummy
	lastRefreshNano := atomic.Int64{}
	expiresAtNano := atomic.Int64{}
	ttl := 5 * time.Second

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Simulate write operation
		_ = conn
		refreshTtlNew(&lastRefreshNano, &expiresAtNano, ttl)
	}
}

// BenchmarkAnyfromWriteTo_New_Throttled simulates NEW WriteTo with throttled refresh.
func BenchmarkAnyfromWriteTo_New_Throttled(b *testing.B) {
	conn := &net.UDPConn{} // Dummy
	lastRefreshNano := atomic.Int64{}
	expiresAtNano := atomic.Int64{}
	ttl := 5 * time.Second
	// Pre-set to recent time
	lastRefreshNano.Store(time.Now().UnixNano())

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Simulate write operation
		_ = conn
		refreshTtlNew(&lastRefreshNano, &expiresAtNano, ttl)
	}
}
