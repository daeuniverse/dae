/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@daeuniverse.org>
 *
 * Throughput Benchmark Suite
 *
 * This file measures throughput under various load patterns:
 * 1. DNS query throughput (QPS)
 * 2. Routing decision throughput (RPS)
 * 3. Connection handling throughput
 * 4. Mixed workload throughput
 */

package control

import (
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	dnsmessage "github.com/miekg/dns"
)

// =============================================================================
// Section 1: DNS Query Throughput (QPS)
// =============================================================================

// BenchmarkDnsQPS_CacheHit measures DNS queries per second with cache hits
func BenchmarkDnsQPS_CacheHit(b *testing.B) {
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

	var cache sync.Map
	for i := 0; i < 10000; i++ {
		dnsCache := &DnsCache{
			DomainBitmap:     []uint32{1, 2, 3},
			Answer:           answers,
			Deadline:         time.Now().Add(5 * time.Minute),
			OriginalDeadline: time.Now().Add(5 * time.Minute),
		}
		_ = dnsCache.PrepackResponse(fmt.Sprintf("domain%d.com.", i), dnsmessage.TypeA)
		cache.Store(fmt.Sprintf("domain%d.com.:1", i), dnsCache)
	}

	var ops atomic.Int64

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			key := fmt.Sprintf("domain%d.com.:1", i%10000)
			if val, ok := cache.Load(key); ok {
				c := val.(*DnsCache)
				_ = c.PackedResponse
				ops.Add(1)
			}
			i++
		}
	})
}

// BenchmarkDnsQPS_VariousCacheSizes measures QPS with different cache sizes
func BenchmarkDnsQPS_VariousCacheSizes(b *testing.B) {
	cacheSizes := []int{100, 1000, 10000, 100000}

	for _, size := range cacheSizes {
		b.Run(fmt.Sprintf("CacheSize_%d", size), func(b *testing.B) {
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

			var cache sync.Map
			for i := 0; i < size; i++ {
				dnsCache := &DnsCache{
					DomainBitmap:     []uint32{1, 2, 3},
					Answer:           answers,
					Deadline:         time.Now().Add(5 * time.Minute),
					OriginalDeadline: time.Now().Add(5 * time.Minute),
				}
				_ = dnsCache.PrepackResponse(fmt.Sprintf("domain%d.com.", i), dnsmessage.TypeA)
				cache.Store(fmt.Sprintf("domain%d.com.:1", i), dnsCache)
			}

			b.ReportAllocs()
			b.ResetTimer()

			b.RunParallel(func(pb *testing.PB) {
				i := 0
				for pb.Next() {
					key := fmt.Sprintf("domain%d.com.:1", i%size)
					if val, ok := cache.Load(key); ok {
						c := val.(*DnsCache)
						_ = c.PackedResponse
					}
					i++
				}
			})
		})
	}
}

// =============================================================================
// Section 2: Routing Decision Throughput (RPS)
// =============================================================================

// BenchmarkRoutingRPS_IPOnly measures routing decisions per second (IP only)
func BenchmarkRoutingRPS_IPOnly(b *testing.B) {
	matcher := buildTestRoutingMatcher(b, 100)
	srcAddr := netip.AddrFrom4([4]byte{192, 168, 1, 100})

	var ops atomic.Int64

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			dstAddr := netip.AddrFrom4([4]byte{byte(93 + i%10), 184, 216, byte(34 + i%100)})
			_, _, _, _ = matcher.Match(
				srcAddr.As16(),
				dstAddr.As16(),
				12345+uint16(i%65535),
				443+uint16(i%1000),
				consts.IpVersion_4,
				consts.L4ProtoType_TCP,
				"",
				[16]byte{},
				0,
				[16]byte{},
			)
			ops.Add(1)
			i++
		}
	})
}

// BenchmarkRoutingRPS_Domain measures routing decisions per second (with domain)
func BenchmarkRoutingRPS_Domain(b *testing.B) {
	matcher := buildTestRoutingMatcher(b, 100)
	srcAddr := netip.AddrFrom4([4]byte{192, 168, 1, 100})
	dstAddr := netip.AddrFrom4([4]byte{93, 184, 216, 34})

	var ops atomic.Int64

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			_, _, _, _ = matcher.Match(
				srcAddr.As16(),
				dstAddr.As16(),
				12345+uint16(i%65535),
				443,
				consts.IpVersion_4,
				consts.L4ProtoType_TCP,
				fmt.Sprintf("domain%d.example.com", i%10000),
				[16]byte{},
				0,
				[16]byte{},
			)
			ops.Add(1)
			i++
		}
	})
}

// BenchmarkRoutingRPS_VariousRuleCounts measures RPS with different rule counts
func BenchmarkRoutingRPS_VariousRuleCounts(b *testing.B) {
	ruleCounts := []int{10, 50, 100, 500, 1000}

	for _, count := range ruleCounts {
		b.Run(fmt.Sprintf("Rules_%d", count), func(b *testing.B) {
			matcher := buildTestRoutingMatcher(b, count)
			srcAddr := netip.AddrFrom4([4]byte{192, 168, 1, 100})
			dstAddr := netip.AddrFrom4([4]byte{93, 184, 216, 34})

			b.ReportAllocs()
			b.ResetTimer()

			b.RunParallel(func(pb *testing.PB) {
				i := 0
				for pb.Next() {
					_, _, _, _ = matcher.Match(
						srcAddr.As16(),
						dstAddr.As16(),
						12345+uint16(i%65535),
						443,
						consts.IpVersion_4,
						consts.L4ProtoType_TCP,
						"example.com",
						[16]byte{},
						0,
						[16]byte{},
					)
					i++
				}
			})
		})
	}
}

// =============================================================================
// Section 3: Connection Handling Throughput
// =============================================================================

// BenchmarkConnectionThroughput_UDP measures UDP connection handling
func BenchmarkConnectionThroughput_UDP(b *testing.B) {
	p := NewUdpTaskPool()
	var counter atomic.Uint64
	var processed atomic.Int64

	keys := make([]netip.AddrPort, 1000)
	for i := 0; i < 1000; i++ {
		keys[i] = netip.AddrPortFrom(
			netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 1}),
			uint16(10000+i),
		)
	}

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			i := counter.Add(1) - 1
			k := keys[i%1000]
			p.EmitTask(k, func() {
				processed.Add(1)
			})
		}
	})

	b.StopTimer()

	// Wait for tasks to complete
	deadline := time.Now().Add(5 * time.Second)
	for processed.Load() < int64(b.N) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
}

// BenchmarkConnectionThroughput_UDPEndpointPool measures UDP endpoint pool performance
func BenchmarkConnectionThroughput_UDPEndpointPool(b *testing.B) {
	p := NewUdpEndpointPool()

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			lAddr := netip.AddrPortFrom(
				netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i >> 16), byte(i)}),
				uint16(10000+i%55000),
			)
			_, _, _ = p.GetOrCreate(lAddr, &UdpEndpointOptions{})
			i++
		}
	})
}

// =============================================================================
// Section 4: Mixed Workload Throughput
// =============================================================================

// MixedWorkloadConfig defines the workload mix
type MixedWorkloadConfig struct {
	DNSCacheHitPercent   int // 0-100
	DomainRoutingPercent int // 0-100
	Concurrency          int
}

// BenchmarkMixedWorkload simulates realistic traffic mix
func BenchmarkMixedWorkload(b *testing.B) {
	configs := []MixedWorkloadConfig{
		{DNSCacheHitPercent: 90, DomainRoutingPercent: 70, Concurrency: 1},
		{DNSCacheHitPercent: 90, DomainRoutingPercent: 70, Concurrency: 4},
		{DNSCacheHitPercent: 90, DomainRoutingPercent: 70, Concurrency: 16},
		{DNSCacheHitPercent: 50, DomainRoutingPercent: 30, Concurrency: 1},
		{DNSCacheHitPercent: 50, DomainRoutingPercent: 30, Concurrency: 4},
		{DNSCacheHitPercent: 50, DomainRoutingPercent: 30, Concurrency: 16},
	}

	for _, cfg := range configs {
		name := fmt.Sprintf("DNS%d_Domain%d_Conc%d",
			cfg.DNSCacheHitPercent, cfg.DomainRoutingPercent, cfg.Concurrency)
		b.Run(name, func(b *testing.B) {
			runMixedWorkload(b, cfg)
		})
	}
}

func runMixedWorkload(b *testing.B, cfg MixedWorkloadConfig) {
	// Setup DNS cache
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

	var cache sync.Map
	for i := 0; i < 10000; i++ {
		dnsCache := &DnsCache{
			DomainBitmap:     []uint32{1, 2, 3},
			Answer:           answers,
			Deadline:         time.Now().Add(5 * time.Minute),
			OriginalDeadline: time.Now().Add(5 * time.Minute),
		}
		_ = dnsCache.PrepackResponse(fmt.Sprintf("domain%d.com.", i), dnsmessage.TypeA)
		cache.Store(fmt.Sprintf("domain%d.com.:1", i), dnsCache)
	}

	// Setup routing matcher
	matcher := buildTestRoutingMatcher(b, 100)
	srcAddr := netip.AddrFrom4([4]byte{192, 168, 1, 100})
	dstAddr := netip.AddrFrom4([4]byte{93, 184, 216, 34})

	var dnsOps, routeOps atomic.Int64

	b.ReportAllocs()
	b.ResetTimer()

	b.SetParallelism(cfg.Concurrency)
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			// Simulate DNS lookup (cache hit probability)
			if i%100 < cfg.DNSCacheHitPercent {
				key := fmt.Sprintf("domain%d.com.:1", i%10000)
				if val, ok := cache.Load(key); ok {
					c := val.(*DnsCache)
					_ = c.PackedResponse
					dnsOps.Add(1)
				}
			}

			// Simulate routing decision (domain routing probability)
			domain := ""
			if i%100 < cfg.DomainRoutingPercent {
				domain = fmt.Sprintf("domain%d.com", i%10000)
			}

			_, _, _, _ = matcher.Match(
				srcAddr.As16(),
				dstAddr.As16(),
				12345+uint16(i%65535),
				443,
				consts.IpVersion_4,
				consts.L4ProtoType_TCP,
				domain,
				[16]byte{},
				0,
				[16]byte{},
			)
			routeOps.Add(1)
			i++
		}
	})

	b.ReportMetric(float64(dnsOps.Load())/float64(b.N)*100, "dns_hit%")
	b.ReportMetric(float64(routeOps.Load())/float64(b.N)*100, "route%")
}

// =============================================================================
// Section 5: Stress Tests
// =============================================================================

// BenchmarkStress_HighConcurrency tests under high concurrency
func BenchmarkStress_HighConcurrency(b *testing.B) {
	concurrencies := []int{1, 2, 4, 8, 16, 32, 64, 128}

	for _, conc := range concurrencies {
		b.Run(fmt.Sprintf("Goroutines_%d", conc), func(b *testing.B) {
			matcher := buildTestRoutingMatcher(b, 100)
			srcAddr := netip.AddrFrom4([4]byte{192, 168, 1, 100})
			dstAddr := netip.AddrFrom4([4]byte{93, 184, 216, 34})

			b.ReportAllocs()
			b.ResetTimer()

			b.SetParallelism(conc)
			b.RunParallel(func(pb *testing.PB) {
				i := 0
				for pb.Next() {
					_, _, _, _ = matcher.Match(
						srcAddr.As16(),
						dstAddr.As16(),
						12345+uint16(i%65535),
						443,
						consts.IpVersion_4,
						consts.L4ProtoType_TCP,
						fmt.Sprintf("domain%d.com", i%1000),
						[16]byte{},
						0,
						[16]byte{},
					)
					i++
				}
			})
		})
	}
}

// BenchmarkStress_MemoryPressure tests under memory pressure
func BenchmarkStress_MemoryPressure(b *testing.B) {
	// Create a large cache to simulate memory pressure
	var cache sync.Map
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

	// Pre-populate with many entries
	for i := 0; i < 50000; i++ {
		dnsCache := &DnsCache{
			DomainBitmap:     []uint32{1, 2, 3},
			Answer:           answers,
			Deadline:         time.Now().Add(5 * time.Minute),
			OriginalDeadline: time.Now().Add(5 * time.Minute),
		}
		_ = dnsCache.PrepackResponse(fmt.Sprintf("domain%d.com.", i), dnsmessage.TypeA)
		cache.Store(fmt.Sprintf("domain%d.com.:1", i), dnsCache)
	}

	matcher := buildTestRoutingMatcher(b, 100)
	srcAddr := netip.AddrFrom4([4]byte{192, 168, 1, 100})
	dstAddr := netip.AddrFrom4([4]byte{93, 184, 216, 34})

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			// Random cache access
			key := fmt.Sprintf("domain%d.com.:1", i%50000)
			if val, ok := cache.Load(key); ok {
				c := val.(*DnsCache)
				_ = c.PackedResponse
			}

			// Routing decision
			_, _, _, _ = matcher.Match(
				srcAddr.As16(),
				dstAddr.As16(),
				12345+uint16(i%65535),
				443,
				consts.IpVersion_4,
				consts.L4ProtoType_TCP,
				fmt.Sprintf("domain%d.com", i%50000),
				[16]byte{},
				0,
				[16]byte{},
			)
			i++
		}
	})
}
