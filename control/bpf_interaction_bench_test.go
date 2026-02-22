/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@daeuniverse.org>
 *
 * Benchmark for Go-eBPF interaction performance
 */

package control

import (
	"sync/atomic"
	"testing"
	"time"

	dnsmessage "github.com/miekg/dns"
)

// BenchmarkComputeBpfDataHash measures the hash computation performance
// This is called when NeedsBpfUpdate determines an update might be needed
func BenchmarkComputeBpfDataHash(b *testing.B) {
	cache := &DnsCache{
		DomainBitmap: []uint32{0x12345678, 0x87654321, 0xDEADBEEF, 0xCAFEBABE},
		Answer: []dnsmessage.RR{
			&dnsmessage.A{
				Hdr: dnsmessage.RR_Header{Name: "example.com.", Rrtype: dnsmessage.TypeA, Class: dnsmessage.ClassINET, Ttl: 300},
				A:   []byte{93, 184, 216, 34},
			},
			&dnsmessage.A{
				Hdr: dnsmessage.RR_Header{Name: "example.com.", Rrtype: dnsmessage.TypeA, Class: dnsmessage.ClassINET, Ttl: 300},
				A:   []byte{93, 184, 216, 35},
			},
			&dnsmessage.AAAA{
				Hdr: dnsmessage.RR_Header{Name: "example.com.", Rrtype: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET, Ttl: 300},
				AAAA: []byte{0x26, 0x07, 0xf8, 0xb0, 0x40, 0x00, 0x08, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x0e},
			},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cache.ComputeBpfDataHash()
	}
}

// BenchmarkComputeBpfDataHash_LargeAnswer measures hash with many IPs
func BenchmarkComputeBpfDataHash_LargeAnswer(b *testing.B) {
	// Simulate a CDN response with many IPs
	var answers []dnsmessage.RR
	for i := 0; i < 20; i++ {
		answers = append(answers, &dnsmessage.A{
			Hdr: dnsmessage.RR_Header{Name: "cdn.example.com.", Rrtype: dnsmessage.TypeA, Class: dnsmessage.ClassINET, Ttl: 300},
			A:   []byte{byte(93 + i), 184, 216, byte(34 + i)},
		})
	}
	// Add 10 AAAA records
	for i := 0; i < 10; i++ {
		answers = append(answers, &dnsmessage.AAAA{
			Hdr:  dnsmessage.RR_Header{Name: "cdn.example.com.", Rrtype: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET, Ttl: 300},
			AAAA: []byte{0x26, 0x07, 0xf8, 0xb0, 0x40, 0x00, 0x08, byte(i), 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, byte(i)},
		})
	}

	cache := &DnsCache{
		DomainBitmap: make([]uint32, 32), // Typical size
		Answer:       answers,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cache.ComputeBpfDataHash()
	}
}

// BenchmarkNeedsBpfUpdate_HitMinInterval measures the fast path (within min interval)
func BenchmarkNeedsBpfUpdate_HitMinInterval(b *testing.B) {
	cache := &DnsCache{
		DomainBitmap: []uint32{0x12345678},
		Answer: []dnsmessage.RR{
			&dnsmessage.A{
				Hdr: dnsmessage.RR_Header{Name: "example.com.", Rrtype: dnsmessage.TypeA, Class: dnsmessage.ClassINET, Ttl: 300},
				A:   []byte{93, 184, 216, 34},
			},
		},
	}
	now := time.Now()
	cache.MarkBpfUpdated(now) // Just updated, should hit min interval

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cache.NeedsBpfUpdate(now.Add(100 * time.Millisecond))
	}
}

// BenchmarkNeedsBpfUpdate_DataChanged measures when data has changed
func BenchmarkNeedsBpfUpdate_DataChanged(b *testing.B) {
	cache := &DnsCache{
		DomainBitmap: []uint32{0x12345678},
		Answer: []dnsmessage.RR{
			&dnsmessage.A{
				Hdr: dnsmessage.RR_Header{Name: "example.com.", Rrtype: dnsmessage.TypeA, Class: dnsmessage.ClassINET, Ttl: 300},
				A:   []byte{93, 184, 216, 34},
			},
		},
	}
	now := time.Now()
	cache.MarkBpfUpdated(now.Add(-2 * time.Second)) // 2 seconds ago
	cache.lastBpfDataHash.Store(0x1234567890ABCDEF) // Different hash

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cache.NeedsBpfUpdate(now)
	}
}

// BenchmarkNeedsBpfUpdate_Parallel measures parallel access (concurrent cache hits)
func BenchmarkNeedsBpfUpdate_Parallel(b *testing.B) {
	cache := &DnsCache{
		DomainBitmap: []uint32{0x12345678},
		Answer: []dnsmessage.RR{
			&dnsmessage.A{
				Hdr: dnsmessage.RR_Header{Name: "example.com.", Rrtype: dnsmessage.TypeA, Class: dnsmessage.ClassINET, Ttl: 300},
				A:   []byte{93, 184, 216, 34},
			},
		},
	}
	now := time.Now()
	cache.MarkBpfUpdated(now)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = cache.NeedsBpfUpdate(now)
		}
	})
}

// BenchmarkAtomicOperations compares atomic operation costs
func BenchmarkAtomicOperations(b *testing.B) {
	var val atomic.Int64
	now := time.Now().UnixNano()

	b.Run("Load", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = val.Load()
		}
	})

	b.Run("Store", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			val.Store(now)
		}
	})

	b.Run("CompareAndSwap_Success", func(b *testing.B) {
		val.Store(now)
		for i := 0; i < b.N; i++ {
			_ = val.CompareAndSwap(now, now+1)
		}
	})

	b.Run("CompareAndSwap_Fail", func(b *testing.B) {
		val.Store(now)
		for i := 0; i < b.N; i++ {
			_ = val.CompareAndSwap(now-1, now+1) // Will fail
		}
	})
}
