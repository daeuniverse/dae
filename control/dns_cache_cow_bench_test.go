/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@daeuniverse.org>
 */

package control

import (
	"sync/atomic"
	"testing"
	"time"

	dnsmessage "github.com/miekg/dns"
)

// BenchmarkDnsCache_COW_Read demonstrates the performance benefit of Copy-on-Write
// with atomic.Pointer for lock-free reads.
//
// Expected result: ~1-2ns per read (atomic pointer load)
// vs old implementation with deep copy + Pack: ~100-1000ns
func BenchmarkDnsCache_COW_Read(b *testing.B) {
	answers := []dnsmessage.RR{
		&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{
				Name:   "example.com.",
				Rrtype: dnsmessage.TypeA,
				Class:  dnsmessage.ClassINET,
				Ttl:    300,
			},
			A: []byte{93, 184, 216, 34},
		},
	}

	cache := &DnsCache{
		DomainBitmap:     []uint32{1, 2, 3},
		Answer:           answers,
		Deadline:         time.Now().Add(5 * time.Minute),
		OriginalDeadline: time.Now().Add(5 * time.Minute),
	}

	// Pre-pack the response
	if err := cache.PrepackResponse("example.com.", dnsmessage.TypeA); err != nil {
		b.Fatalf("failed to prepack response: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// Lock-free read: atomic pointer load
		// This is the optimized hot path
		if ptr := cache.GetPackedResponse(); ptr != nil {
			_ = ptr
		}
	}
}

// BenchmarkDnsCache_COW_Read_Parallel demonstrates lock-free reads under contention
func BenchmarkDnsCache_COW_Read_Parallel(b *testing.B) {
	answers := []dnsmessage.RR{
		&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{
				Name:   "example.com.",
				Rrtype: dnsmessage.TypeA,
				Class:  dnsmessage.ClassINET,
				Ttl:    300,
			},
			A: []byte{93, 184, 216, 34},
		},
	}

	cache := &DnsCache{
		DomainBitmap:     []uint32{1, 2, 3},
		Answer:           answers,
		Deadline:         time.Now().Add(5 * time.Minute),
		OriginalDeadline: time.Now().Add(5 * time.Minute),
	}

	if err := cache.PrepackResponse("example.com.", dnsmessage.TypeA); err != nil {
		b.Fatalf("failed to prepack response: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			// Lock-free read - no mutex contention
			if ptr := cache.GetPackedResponse(); ptr != nil {
				_ = ptr
			}
		}
	})
}

// BenchmarkDnsCache_COW_Update benchmarks the slow path (TTL refresh)
// This happens rarely (only when TTL differs by >15 seconds)
func BenchmarkDnsCache_COW_Update(b *testing.B) {
	answers := []dnsmessage.RR{
		&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{
				Name:   "example.com.",
				Rrtype: dnsmessage.TypeA,
				Class:  dnsmessage.ClassINET,
				Ttl:    300,
			},
			A: []byte{93, 184, 216, 34},
		},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		cache := &DnsCache{
			DomainBitmap:     []uint32{1, 2, 3},
			Answer:           answers,
			Deadline:         time.Now().Add(5 * time.Minute),
			OriginalDeadline: time.Now().Add(5 * time.Minute),
		}

		// Simulate TTL refresh (slow path)
		_ = cache.PrepackResponse("example.com.", dnsmessage.TypeA)
	}
}

// BenchmarkDnsCache_COW_Mixed simulates realistic workload:
// 99% reads, 1% updates (TTL refresh)
func BenchmarkDnsCache_COW_Mixed(b *testing.B) {
	answers := []dnsmessage.RR{
		&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{
				Name:   "example.com.",
				Rrtype: dnsmessage.TypeA,
				Class:  dnsmessage.ClassINET,
				Ttl:    300,
			},
			A: []byte{93, 184, 216, 34},
		},
	}

	cache := &DnsCache{
		DomainBitmap:     []uint32{1, 2, 3},
		Answer:           answers,
		Deadline:         time.Now().Add(5 * time.Minute),
		OriginalDeadline: time.Now().Add(5 * time.Minute),
	}

	if err := cache.PrepackResponse("example.com.", dnsmessage.TypeA); err != nil {
		b.Fatalf("failed to prepack response: %v", err)
	}

	var updateCount atomic.Int64

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			// 99% reads
			if i%100 != 0 {
				if ptr := cache.GetPackedResponse(); ptr != nil {
					_ = ptr
				}
			} else {
				// 1% updates (TTL refresh)
				// This is rare in production - only when TTL differs by >15s
				now := time.Now().Add(20 * time.Second)
				_ = cache.GetPackedResponseWithApproximateTTL("example.com.", dnsmessage.TypeA, now)
				updateCount.Add(1)
			}
			i++
		}
	})

	b.ReportMetric(float64(updateCount.Load())/float64(b.N), "updates/op")
}

// BenchmarkDnsCache_COW_GetPackedResponse benchmarks the complete hot path
// This is what actual DNS queries will use
func BenchmarkDnsCache_COW_GetPackedResponse(b *testing.B) {
	answers := []dnsmessage.RR{
		&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{
				Name:   "example.com.",
				Rrtype: dnsmessage.TypeA,
				Class:  dnsmessage.ClassINET,
				Ttl:    300,
			},
			A: []byte{93, 184, 216, 34},
		},
	}

	cache := &DnsCache{
		DomainBitmap:     []uint32{1, 2, 3},
		Answer:           answers,
		Deadline:         time.Now().Add(5 * time.Minute),
		OriginalDeadline: time.Now().Add(5 * time.Minute),
	}

	if err := cache.PrepackResponse("example.com.", dnsmessage.TypeA); err != nil {
		b.Fatalf("failed to prepack response: %v", err)
	}

	now := time.Now()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// Fast path: TTL within threshold
		_ = cache.GetPackedResponseWithApproximateTTL("example.com.", dnsmessage.TypeA, now)
	}
}

// BenchmarkDnsCache_COW_GetPackedResponse_Parallel benchmarks parallel cache hits
func BenchmarkDnsCache_COW_GetPackedResponse_Parallel(b *testing.B) {
	answers := []dnsmessage.RR{
		&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{
				Name:   "example.com.",
				Rrtype: dnsmessage.TypeA,
				Class:  dnsmessage.ClassINET,
				Ttl:    300,
			},
			A: []byte{93, 184, 216, 34},
		},
	}

	cache := &DnsCache{
		DomainBitmap:     []uint32{1, 2, 3},
		Answer:           answers,
		Deadline:         time.Now().Add(5 * time.Minute),
		OriginalDeadline: time.Now().Add(5 * time.Minute),
	}

	if err := cache.PrepackResponse("example.com.", dnsmessage.TypeA); err != nil {
		b.Fatalf("failed to prepack response: %v", err)
	}

	now := time.Now()

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			// Fast path: TTL within threshold
			_ = cache.GetPackedResponseWithApproximateTTL("example.com.", dnsmessage.TypeA, now)
		}
	})
}
