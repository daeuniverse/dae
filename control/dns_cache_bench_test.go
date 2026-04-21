/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net"
	"testing"
	"time"

	dnsmessage "github.com/miekg/dns"
)

func newBenchmarkDnsCache(t testing.TB) *DnsCache {
	t.Helper()
	answers := []dnsmessage.RR{
		&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{Name: "benchmark.example.com.", Rrtype: dnsmessage.TypeA, Class: dnsmessage.ClassINET, Ttl: 300},
			A:   net.IPv4(93, 184, 216, 34),
		},
		&dnsmessage.AAAA{
			Hdr: dnsmessage.RR_Header{Name: "benchmark.example.com.", Rrtype: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET, Ttl: 300},
			AAAA: []byte{
				0x26, 0x07, 0xf8, 0xb0, 0x40, 0x0, 0x8, 0x0,
				0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x20, 0x22,
			},
		},
	}
	cache := &DnsCache{
		DomainBitmap:     []uint32{1, 2, 3},
		Answer:           answers,
		Deadline:         time.Now().Add(5 * time.Minute),
		OriginalDeadline: time.Now().Add(5 * time.Minute),
	}
	if err := cache.PrepackResponse("benchmark.example.com.", dnsmessage.TypeA); err != nil {
		t.Fatalf("PrepackResponse: %v", err)
	}
	return cache
}

func BenchmarkDnsCache_GetPackedResponse(b *testing.B) {
	cache := newBenchmarkDnsCache(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		packed := cache.GetPackedResponse()
		if len(packed) == 0 {
			b.Fatal("empty packed response")
		}
	}
}

func BenchmarkDnsCache_GetPackedResponseWithApproximateTTL(b *testing.B) {
	cache := newBenchmarkDnsCache(b)
	now := time.Now()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		packed := cache.GetPackedResponseWithApproximateTTL("benchmark.example.com.", dnsmessage.TypeA, now)
		if len(packed) == 0 {
			b.Fatal("empty packed response")
		}
	}
}

func BenchmarkDnsCache_GetPackedResponseWithApproximateTTL_Stale(b *testing.B) {
	cache := newBenchmarkDnsCache(b)
	now := time.Now().Add(4*time.Minute + 45*time.Second)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		packed := cache.GetPackedResponseWithApproximateTTL("benchmark.example.com.", dnsmessage.TypeA, now)
		if len(packed) == 0 {
			b.Fatal("empty packed response")
		}
	}
}

func BenchmarkDnsCache_FillInto(b *testing.B) {
	cache := newBenchmarkDnsCache(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := new(dnsmessage.Msg)
		req.SetQuestion("benchmark.example.com.", dnsmessage.TypeA)
		cache.FillInto(req)
	}
}

func BenchmarkDnsCache_FillIntoWithPacked(b *testing.B) {
	cache := newBenchmarkDnsCache(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := new(dnsmessage.Msg)
		req.SetQuestion("benchmark.example.com.", dnsmessage.TypeA)
		cache.FillIntoWithPacked(req)
	}
}

func BenchmarkDnsCache_FillIntoWithTTL(b *testing.B) {
	cache := newBenchmarkDnsCache(b)
	now := time.Now()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := new(dnsmessage.Msg)
		req.SetQuestion("benchmark.example.com.", dnsmessage.TypeA)
		result := cache.FillIntoWithTTL(req, now)
		if result == nil {
			b.Fatal("nil result")
		}
	}
}

func BenchmarkDnsCache_ComputeBpfDataHash(b *testing.B) {
	cache := newBenchmarkDnsCache(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.ComputeBpfDataHash()
	}
}

func BenchmarkDnsCache_Clone(b *testing.B) {
	cache := newBenchmarkDnsCache(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cloned := cache.Clone()
		if cloned == nil {
			b.Fatal("nil clone")
		}
	}
}

func BenchmarkDnsCache_CloneForReload(b *testing.B) {
	cache := newBenchmarkDnsCache(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cloned := cache.CloneForReload()
		if cloned == nil {
			b.Fatal("nil clone")
		}
	}
}

func BenchmarkDnsCache_NeedsBpfUpdate(b *testing.B) {
	cache := newBenchmarkDnsCache(b)
	now := time.Now()
	cache.MarkBpfUpdated(now)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.NeedsBpfUpdate(now.Add(time.Duration(i) * time.Second))
	}
}

func BenchmarkDnsCache_ParallelGetPackedResponse(b *testing.B) {
	cache := newBenchmarkDnsCache(b)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			packed := cache.GetPackedResponse()
			if len(packed) == 0 {
				b.Fatal("empty packed response")
			}
		}
	})
}

func BenchmarkDnsCache_ParallelGetPackedResponseWithTTL(b *testing.B) {
	cache := newBenchmarkDnsCache(b)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			now := time.Unix(1_700_000_000, int64(i)*1e6)
			packed := cache.GetPackedResponseWithApproximateTTL("benchmark.example.com.", dnsmessage.TypeA, now)
			if len(packed) == 0 {
				b.Fatal("empty packed response")
			}
			i++
		}
	})
}
