/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@daeuniverse.org>
 *
 * Transparency Proxy Performance Benchmark Suite
 *
 * This file benchmarks the critical path of transparent proxying:
 * 1. DNS resolution latency (cache hit/miss, upstream query)
 * 2. Routing rule matching latency
 * 3. End-to-end connection establishment latency
 * 4. Throughput under various loads
 */

package control

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/pkg/trie"
	dnsmessage "github.com/miekg/dns"
)

// =============================================================================
// Section 1: DNS Resolution Latency Benchmarks
// =============================================================================

// BenchmarkDnsCache_LookupLatency measures DNS cache lookup latency
func BenchmarkDnsCache_LookupLatency(b *testing.B) {
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
	_ = cache.PrepackResponse("example.com.", dnsmessage.TypeA)

	var dnsCache sync.Map
	dnsCache.Store("example.com.:1", cache)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if val, ok := dnsCache.Load("example.com.:1"); ok {
			c := val.(*DnsCache)
			_ = c.GetPackedResponse()
		}
	}
}

// BenchmarkDnsCache_LookupLatency_Parallel measures parallel DNS cache lookup
func BenchmarkDnsCache_LookupLatency_Parallel(b *testing.B) {
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
	_ = cache.PrepackResponse("example.com.", dnsmessage.TypeA)

	var dnsCache sync.Map
	for i := 0; i < 1000; i++ {
		key := fmt.Sprintf("domain%d.com.:1", i)
		dnsCache.Store(key, cache)
	}

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			key := fmt.Sprintf("domain%d.com.:1", i%1000)
			if val, ok := dnsCache.Load(key); ok {
				c := val.(*DnsCache)
				_ = c.GetPackedResponse()
			}
			i++
		}
	})
}

// =============================================================================
// Section 1.5: DNS Rule Matching Latency Benchmarks (DNS Request/Response Routing)
// =============================================================================

// BenchmarkDnsRequestMatcher_Match measures DNS request routing rule matching
func BenchmarkDnsRequestMatcher_Match(b *testing.B) {
	matcher := buildTestDnsRequestMatcher(b, 100)

	domains := []string{
		"example.com",
		"api.example.com",
		"cdn.example.com",
		"www.google.com",
		"api.github.com",
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		domain := domains[i%len(domains)]
		_, _ = matcher.Match(domain, dnsmessage.TypeA)
	}
}

// BenchmarkDnsRequestMatcher_Match_Parallel measures parallel DNS request routing
func BenchmarkDnsRequestMatcher_Match_Parallel(b *testing.B) {
	matcher := buildTestDnsRequestMatcher(b, 100)

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			domain := fmt.Sprintf("domain%d.example.com", i%1000)
			_, _ = matcher.Match(domain, dnsmessage.TypeA)
			i++
		}
	})
}

// BenchmarkDnsRequestMatcher_ManyRules measures DNS request routing with many rules
func BenchmarkDnsRequestMatcher_ManyRules(b *testing.B) {
	ruleCounts := []int{10, 50, 100, 500}

	for _, count := range ruleCounts {
		b.Run(fmt.Sprintf("Rules_%d", count), func(b *testing.B) {
			matcher := buildTestDnsRequestMatcher(b, count)

			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_, _ = matcher.Match("example.com", dnsmessage.TypeA)
			}
		})
	}
}

// BenchmarkDnsResponseMatcher_Match measures DNS response routing rule matching
func BenchmarkDnsResponseMatcher_Match(b *testing.B) {
	matcher := buildTestDnsResponseMatcher(b, 100)

	ips := []netip.Addr{
		netip.MustParseAddr("93.184.216.34"),
		netip.MustParseAddr("142.250.185.46"),
		netip.MustParseAddr("140.82.121.4"),
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = matcher.Match(
			"example.com",
			dnsmessage.TypeA,
			ips,
			consts.DnsRequestOutboundIndex(0),
		)
	}
}

// BenchmarkDnsResponseMatcher_Match_Parallel measures parallel DNS response routing
func BenchmarkDnsResponseMatcher_Match_Parallel(b *testing.B) {
	matcher := buildTestDnsResponseMatcher(b, 100)

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			ips := []netip.Addr{
				netip.MustParseAddr(fmt.Sprintf("10.%d.%d.%d", i%256, (i/256)%256, (i/65536)%256)),
			}
			_, _ = matcher.Match(
				fmt.Sprintf("domain%d.example.com", i%1000),
				dnsmessage.TypeA,
				ips,
				consts.DnsRequestOutboundIndex(i%10),
			)
			i++
		}
	})
}

// BenchmarkDnsResponseMatcher_WithIPs measures DNS response routing with multiple IPs
func BenchmarkDnsResponseMatcher_WithIPs(b *testing.B) {
	matcher := buildTestDnsResponseMatcher(b, 100)

	// Simulate responses with varying numbers of IPs
	testCases := []struct {
		name string
		ips  []netip.Addr
	}{
		{"1_IP", []netip.Addr{netip.MustParseAddr("93.184.216.34")}},
		{"4_IPs", []netip.Addr{
			netip.MustParseAddr("93.184.216.34"),
			netip.MustParseAddr("93.184.216.35"),
			netip.MustParseAddr("93.184.216.36"),
			netip.MustParseAddr("93.184.216.37"),
		}},
		{"8_IPs", []netip.Addr{
			netip.MustParseAddr("93.184.216.34"),
			netip.MustParseAddr("93.184.216.35"),
			netip.MustParseAddr("93.184.216.36"),
			netip.MustParseAddr("93.184.216.37"),
			netip.MustParseAddr("93.184.216.38"),
			netip.MustParseAddr("93.184.216.39"),
			netip.MustParseAddr("93.184.216.40"),
			netip.MustParseAddr("93.184.216.41"),
		}},
	}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_, _ = matcher.Match(
					"example.com",
					dnsmessage.TypeA,
					tc.ips,
					consts.DnsRequestOutboundIndex(0),
				)
			}
		})
	}
}

// =============================================================================
// Section 2: Routing Rule Matching Latency Benchmarks
// =============================================================================

// BenchmarkRoutingMatcher_Match_IPOnly measures IP-only routing (fastest path)
func BenchmarkRoutingMatcher_Match_IPOnly(b *testing.B) {
	matcher := buildTestRoutingMatcher(b, 100)

	srcAddr := netip.AddrFrom4([4]byte{192, 168, 1, 100})
	dstAddr := netip.AddrFrom4([4]byte{93, 184, 216, 34})

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _, _, _ = matcher.Match(
			srcAddr.As16(),
			dstAddr.As16(),
			12345,
			443,
			consts.IpVersion_4,
			consts.L4ProtoType_TCP,
			"", // No domain - IP only
			[16]byte{},
			0,
			[16]byte{},
		)
	}
}

// BenchmarkRoutingMatcher_Match_DomainOnly measures domain-only routing
func BenchmarkRoutingMatcher_Match_DomainOnly(b *testing.B) {
	matcher := buildTestRoutingMatcher(b, 100)

	srcAddr := netip.AddrFrom4([4]byte{192, 168, 1, 100})
	dstAddr := netip.AddrFrom4([4]byte{93, 184, 216, 34})

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _, _, _ = matcher.Match(
			srcAddr.As16(),
			dstAddr.As16(),
			12345,
			443,
			consts.IpVersion_4,
			consts.L4ProtoType_TCP,
			"example.com",
			[16]byte{},
			0,
			[16]byte{},
		)
	}
}

// BenchmarkRoutingMatcher_Match_Complex measures complex routing with multiple conditions
func BenchmarkRoutingMatcher_Match_Complex(b *testing.B) {
	matcher := buildTestRoutingMatcher(b, 100)

	srcAddr := netip.AddrFrom4([4]byte{192, 168, 1, 100})
	dstAddr := netip.AddrFrom4([4]byte{93, 184, 216, 34})

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _, _, _ = matcher.Match(
			srcAddr.As16(),
			dstAddr.As16(),
			12345,
			443,
			consts.IpVersion_4,
			consts.L4ProtoType_TCP,
			"api.example.com",
			[16]byte{0x6e, 0x67, 0x69, 0x6e, 0x78, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, // process name
			0,
			[16]byte{},
		)
	}
}

// BenchmarkRoutingMatcher_Match_Parallel measures parallel routing decisions
func BenchmarkRoutingMatcher_Match_Parallel(b *testing.B) {
	matcher := buildTestRoutingMatcher(b, 100)

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		srcAddr := netip.AddrFrom4([4]byte{192, 168, 1, 100})
		for pb.Next() {
			dstAddr := netip.AddrFrom4([4]byte{byte(93 + i%10), byte(184 + i%5), byte(216 + i%3), byte(34 + i%20)})
			_, _, _, _ = matcher.Match(
				srcAddr.As16(),
				dstAddr.As16(),
				12345+uint16(i%1000),
				443+uint16(i%100),
				consts.IpVersion_4,
				consts.L4ProtoType_TCP,
				fmt.Sprintf("domain%d.example.com", i%1000),
				[16]byte{},
				0,
				[16]byte{},
			)
			i++
		}
	})
}

// BenchmarkRoutingMatcher_ManyRules measures routing with many rules (worst case)
func BenchmarkRoutingMatcher_ManyRules(b *testing.B) {
	ruleCounts := []int{10, 50, 100, 500, 1000}

	for _, count := range ruleCounts {
		b.Run(fmt.Sprintf("Rules_%d", count), func(b *testing.B) {
			matcher := buildTestRoutingMatcher(b, count)

			srcAddr := netip.AddrFrom4([4]byte{192, 168, 1, 100})
			dstAddr := netip.AddrFrom4([4]byte{93, 184, 216, 34})

			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_, _, _, _ = matcher.Match(
					srcAddr.As16(),
					dstAddr.As16(),
					12345,
					443,
					consts.IpVersion_4,
					consts.L4ProtoType_TCP,
					"example.com",
					[16]byte{},
					0,
					[16]byte{},
				)
			}
		})
	}
}

// =============================================================================
// Section 3: Domain Matching Latency Benchmarks
// =============================================================================

// BenchmarkDomainMatcher_VariousTypes benchmarks different domain matching types
func BenchmarkDomainMatcher_VariousTypes(b *testing.B) {
	testCases := []struct {
		name   string
		domain string
	}{
		{"ShortDomain", "a.com"},
		{"MediumDomain", "example.com"},
		{"LongDomain", "subdomain.api.service.example.com"},
		{"VeryLongDomain", "a1.b2.c3.d4.e5.f6.g7.h8.i9.j0.k1.l2.m3.n4.o5.example.com"},
	}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			matcher := buildTestDomainMatcher(b, 100)

			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_ = matcher.MatchDomainBitmap(tc.domain)
			}
		})
	}
}

// =============================================================================
// Section 4: Combined Latency (Critical Path)
// =============================================================================

// BenchmarkCriticalPath_DNSThenRoute simulates the critical path: DNS lookup -> routing decision
func BenchmarkCriticalPath_DNSThenRoute(b *testing.B) {
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

	dnsCache := &DnsCache{
		DomainBitmap:     []uint32{1, 2, 3},
		Answer:           answers,
		Deadline:         time.Now().Add(5 * time.Minute),
		OriginalDeadline: time.Now().Add(5 * time.Minute),
	}
	_ = dnsCache.PrepackResponse("example.com.", dnsmessage.TypeA)

	var cache sync.Map
	cache.Store("example.com.:1", dnsCache)

	// Setup routing matcher
	routingMatcher := buildTestRoutingMatcher(b, 100)

	srcAddr := netip.AddrFrom4([4]byte{192, 168, 1, 100})
	dstAddr := netip.AddrFrom4([4]byte{93, 184, 216, 34})

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Step 1: DNS cache lookup
		if val, ok := cache.Load("example.com.:1"); ok {
			c := val.(*DnsCache)
			_ = c.GetPackedResponse()
		}

		// Step 2: Routing decision
		_, _, _, _ = routingMatcher.Match(
			srcAddr.As16(),
			dstAddr.As16(),
			12345,
			443,
			consts.IpVersion_4,
			consts.L4ProtoType_TCP,
			"example.com",
			[16]byte{},
			0,
			[16]byte{},
		)
	}
}

// BenchmarkCriticalPath_FullDnsFlow simulates complete DNS flow: Request Match -> Cache -> Response Match -> Route
func BenchmarkCriticalPath_FullDnsFlow(b *testing.B) {
	// Setup DNS request matcher
	reqMatcher := buildTestDnsRequestMatcher(b, 100)

	// Setup DNS response matcher
	respMatcher := buildTestDnsResponseMatcher(b, 100)

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

	dnsCache := &DnsCache{
		DomainBitmap:     []uint32{1, 2, 3},
		Answer:           answers,
		Deadline:         time.Now().Add(5 * time.Minute),
		OriginalDeadline: time.Now().Add(5 * time.Minute),
	}
	_ = dnsCache.PrepackResponse("example.com.", dnsmessage.TypeA)

	var cache sync.Map
	cache.Store("example.com.:1", dnsCache)

	// Setup routing matcher
	routingMatcher := buildTestRoutingMatcher(b, 100)

	srcAddr := netip.AddrFrom4([4]byte{192, 168, 1, 100})
	dstAddr := netip.AddrFrom4([4]byte{93, 184, 216, 34})
	ips := []netip.Addr{dstAddr}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Step 1: DNS request routing (which upstream to use)
		_, _ = reqMatcher.Match("example.com", dnsmessage.TypeA)

		// Step 2: DNS cache lookup
		if val, ok := cache.Load("example.com.:1"); ok {
			c := val.(*DnsCache)
			_ = c.GetPackedResponse()
		}

		// Step 3: DNS response routing (accept/reject based on response)
		_, _ = respMatcher.Match("example.com", dnsmessage.TypeA, ips, consts.DnsRequestOutboundIndex(0))

		// Step 4: Traffic routing decision
		_, _, _, _ = routingMatcher.Match(
			srcAddr.As16(),
			dstAddr.As16(),
			12345,
			443,
			consts.IpVersion_4,
			consts.L4ProtoType_TCP,
			"example.com",
			[16]byte{},
			0,
			[16]byte{},
		)
	}
}

// BenchmarkCriticalPath_FullDnsFlow_Parallel measures parallel full DNS flow
func BenchmarkCriticalPath_FullDnsFlow_Parallel(b *testing.B) {
	// Setup matchers
	reqMatcher := buildTestDnsRequestMatcher(b, 100)
	respMatcher := buildTestDnsResponseMatcher(b, 100)
	routingMatcher := buildTestRoutingMatcher(b, 100)

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
	for i := 0; i < 100; i++ {
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
		srcAddr := netip.AddrFrom4([4]byte{192, 168, 1, 100})
		for pb.Next() {
			domain := fmt.Sprintf("domain%d.com", i%100)
			cacheKey := fmt.Sprintf("%s.:1", domain)

			// Step 1: DNS request routing
			_, _ = reqMatcher.Match(domain, dnsmessage.TypeA)

			// Step 2: DNS cache lookup
			if val, ok := cache.Load(cacheKey); ok {
				c := val.(*DnsCache)
				_ = c.GetPackedResponse()
			}

			// Step 3: DNS response routing
			dstAddr := netip.AddrFrom4([4]byte{byte(93 + i%10), 184, 216, byte(34 + i%20)})
			ips := []netip.Addr{dstAddr}
			_, _ = respMatcher.Match(domain, dnsmessage.TypeA, ips, consts.DnsRequestOutboundIndex(i%10))

			// Step 4: Traffic routing
			_, _, _, _ = routingMatcher.Match(
				srcAddr.As16(),
				dstAddr.As16(),
				12345+uint16(i%1000),
				443,
				consts.IpVersion_4,
				consts.L4ProtoType_TCP,
				domain,
				[16]byte{},
				0,
				[16]byte{},
			)
			i++
		}
	})
}

// BenchmarkCriticalPath_FullParallel measures parallel critical path performance
func BenchmarkCriticalPath_FullParallel(b *testing.B) {
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

	dnsCache := &DnsCache{
		DomainBitmap:     []uint32{1, 2, 3},
		Answer:           answers,
		Deadline:         time.Now().Add(5 * time.Minute),
		OriginalDeadline: time.Now().Add(5 * time.Minute),
	}
	_ = dnsCache.PrepackResponse("example.com.", dnsmessage.TypeA)

	var cache sync.Map
	for i := 0; i < 100; i++ {
		cache.Store(fmt.Sprintf("domain%d.com.:1", i), dnsCache)
	}

	// Setup routing matcher
	routingMatcher := buildTestRoutingMatcher(b, 100)

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		srcAddr := netip.AddrFrom4([4]byte{192, 168, 1, 100})
		for pb.Next() {
			// DNS lookup
			key := fmt.Sprintf("domain%d.com.:1", i%100)
			if val, ok := cache.Load(key); ok {
				c := val.(*DnsCache)
				_ = c.GetPackedResponse()
			}

			// Routing decision
			dstAddr := netip.AddrFrom4([4]byte{byte(93 + i%10), 184, 216, 34})
			_, _, _, _ = routingMatcher.Match(
				srcAddr.As16(),
				dstAddr.As16(),
				12345+uint16(i%1000),
				443,
				consts.IpVersion_4,
				consts.L4ProtoType_TCP,
				fmt.Sprintf("domain%d.com", i%100),
				[16]byte{},
				0,
				[16]byte{},
			)
			i++
		}
	})
}

// =============================================================================
// Section 5: LPM Trie Performance (IP Matching)
// =============================================================================

// BenchmarkLpmTrie_Lookup measures IP prefix matching performance
func BenchmarkLpmTrie_Lookup(b *testing.B) {
	prefixes := []netip.Prefix{
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("93.184.216.0/24"),
		netip.MustParsePrefix("2001:db8::/32"),
	}

	t, err := trie.NewTrieFromPrefixes(prefixes)
	if err != nil {
		b.Fatalf("failed to create trie: %v", err)
	}

	// Pre-compute binary representations (using /32 for IPv4, /128 for IPv6 is invalid)
	testCases := []struct {
		name string
		bin  string
	}{
		{"IPv4_Match", trie.Prefix2bin128(netip.MustParsePrefix("192.168.1.100/32"))},
		{"IPv4_NoMatch", trie.Prefix2bin128(netip.MustParsePrefix("8.8.8.8/32"))},
		{"IPv6_Match", trie.Prefix2bin128(netip.MustParsePrefix("2001:db8::1/64"))},
		{"IPv6_NoMatch", trie.Prefix2bin128(netip.MustParsePrefix("2001:1::1/64"))},
	}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = t.HasPrefix(tc.bin)
			}
		})
	}
}

// BenchmarkLpmTrie_Lookup_Parallel measures parallel IP matching
func BenchmarkLpmTrie_Lookup_Parallel(b *testing.B) {
	prefixes := []netip.Prefix{
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
	}

	t, err := trie.NewTrieFromPrefixes(prefixes)
	if err != nil {
		b.Fatalf("failed to create trie: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			// Use valid prefix length (32 for IPv4)
			prefix := netip.MustParsePrefix(fmt.Sprintf("192.%d.%d.%d/32", 168+i%2, i%256, i%256))
			bin := trie.Prefix2bin128(prefix)
			_ = t.HasPrefix(bin)
			i++
		}
	})
}

// =============================================================================
// Section 6: Latency Distribution Analysis
// =============================================================================

// BenchmarkRoutingMatcher_LatencyDistribution measures latency distribution
func BenchmarkRoutingMatcher_LatencyDistribution(b *testing.B) {
	matcher := buildTestRoutingMatcher(b, 100)
	srcAddr := netip.AddrFrom4([4]byte{192, 168, 1, 100})
	dstAddr := netip.AddrFrom4([4]byte{93, 184, 216, 34})

	latencies := make([]time.Duration, 0, 1000)
	warmup := 1000

	// Warmup
	for i := 0; i < warmup; i++ {
		_, _, _, _ = matcher.Match(
			srcAddr.As16(),
			dstAddr.As16(),
			12345,
			443,
			consts.IpVersion_4,
			consts.L4ProtoType_TCP,
			"example.com",
			[16]byte{},
			0,
			[16]byte{},
		)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		start := time.Now()
		_, _, _, _ = matcher.Match(
			srcAddr.As16(),
			dstAddr.As16(),
			12345,
			443,
			consts.IpVersion_4,
			consts.L4ProtoType_TCP,
			"example.com",
			[16]byte{},
			0,
			[16]byte{},
		)
		latencies = append(latencies, time.Since(start))
	}

	// Report percentiles
	reportLatencyPercentiles(b, latencies)
}

// =============================================================================
// Helper Functions
// =============================================================================

func buildTestRoutingMatcher(b *testing.B, ruleCount int) *RoutingMatcher {
	matches := make([]bpfMatchSet, 0, ruleCount+1)
	lpmMatchers := make([]*trie.Trie, 0)

	// Add IP rules
	for i := 0; i < ruleCount/4; i++ {
		prefixes := []netip.Prefix{
			netip.MustParsePrefix(fmt.Sprintf("10.%d.0.0/16", i%256)),
		}
		t, err := trie.NewTrieFromPrefixes(prefixes)
		if err != nil {
			b.Fatalf("failed to create trie: %v", err)
		}
		lpmIndex := len(lpmMatchers)
		lpmMatchers = append(lpmMatchers, t)

		value := [16]byte{}
		binary.LittleEndian.PutUint32(value[:], uint32(lpmIndex))

		matches = append(matches, bpfMatchSet{
			Type:     uint8(consts.MatchType_IpSet),
			Value:    value,
			Outbound: uint8(i % 10),
		})
	}

	// Add port rules
	for i := 0; i < ruleCount/4; i++ {
		value := [16]byte{}
		binary.LittleEndian.PutUint16(value[0:2], uint16(80+i%100))
		binary.LittleEndian.PutUint16(value[2:4], uint16(80+i%100+10))

		matches = append(matches, bpfMatchSet{
			Type:     uint8(consts.MatchType_Port),
			Value:    value,
			Outbound: uint8(i % 10),
		})
	}

	// Add domain rules (simulated - bitmap based)
	for i := 0; i < ruleCount/4; i++ {
		matches = append(matches, bpfMatchSet{
			Type:     uint8(consts.MatchType_DomainSet),
			Outbound: uint8(i % 10),
		})
	}

	// Add fallback
	matches = append(matches, bpfMatchSet{
		Type:     uint8(consts.MatchType_Fallback),
		Outbound: 0,
	})

	// Create domain matcher with enough bitmap size
	totalRules := len(matches)
	return &RoutingMatcher{
		lpmMatcher:    lpmMatchers,
		domainMatcher: &mockDomainMatcher{domainCount: totalRules},
		matches:       matches,
	}
}

func buildTestDomainMatcher(b *testing.B, domainCount int) routing.DomainMatcher {
	return &mockDomainMatcher{domainCount: domainCount}
}

// mockDomainMatcher is a simple mock for benchmarking
type mockDomainMatcher struct {
	domainCount int
}

func (m *mockDomainMatcher) AddSet(bitIndex int, patterns []string, typ consts.RoutingDomainKey) {}

func (m *mockDomainMatcher) MatchDomainBitmap(domain string) (bitmap []uint32) {
	N := m.domainCount / 32
	if m.domainCount%32 != 0 {
		N++
	}
	// Ensure at least 1 element to avoid index out of range
	if N == 0 {
		N = 1
	}
	bitmap = make([]uint32, N)
	// Simulate a match in the first position
	bitmap[0] = 1
	return bitmap
}

func (m *mockDomainMatcher) Build() error { return nil }

func reportLatencyPercentiles(b *testing.B, latencies []time.Duration) {
	if len(latencies) == 0 {
		return
	}

	// Sort latencies
	sorted := make([]time.Duration, len(latencies))
	copy(sorted, latencies)
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j] < sorted[i] {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	p50 := sorted[len(sorted)*50/100]
	p90 := sorted[len(sorted)*90/100]
	p95 := sorted[len(sorted)*95/100]
	p99 := sorted[len(sorted)*99/100]

	b.ReportMetric(float64(p50.Nanoseconds()), "p50(ns)")
	b.ReportMetric(float64(p90.Nanoseconds()), "p90(ns)")
	b.ReportMetric(float64(p95.Nanoseconds()), "p95(ns)")
	b.ReportMetric(float64(p99.Nanoseconds()), "p99(ns)")
}

// =============================================================================
// DNS Matcher Builders (for DNS request/response routing benchmarks)
// =============================================================================

// dnsRequestMatchSet simulates the request match set from dns package
type dnsRequestMatchSet struct {
	Value    uint16
	Not      bool
	Type     consts.MatchType
	Upstream uint8
}

// dnsResponseMatchSet simulates the response match set from dns package
type dnsResponseMatchSet struct {
	Value    uint16
	Not      bool
	Type     consts.MatchType
	Upstream uint8
}

// mockDnsRequestMatcher simulates DNS request routing matcher
type mockDnsRequestMatcher struct {
	domainMatcher *mockDomainMatcher
	matches       []dnsRequestMatchSet
}

func (m *mockDnsRequestMatcher) Match(qName string, qType uint16) (upstreamIndex consts.DnsRequestOutboundIndex, err error) {
	var domainMatchBitmap []uint32
	if qName != "" {
		domainMatchBitmap = m.domainMatcher.MatchDomainBitmap(qName)
	}

	goodSubrule := false
	badRule := false
	for i, match := range m.matches {
		if badRule || goodSubrule {
			goto beforeNextLoop
		}
		switch match.Type {
		case consts.MatchType_DomainSet:
			if domainMatchBitmap != nil && (domainMatchBitmap[i/32]>>(i%32))&1 > 0 {
				goodSubrule = true
			}
		case consts.MatchType_QType:
			if qType == match.Value {
				goodSubrule = true
			}
		case consts.MatchType_Fallback:
			goodSubrule = true
		}
	beforeNextLoop:
		upstream := consts.DnsRequestOutboundIndex(match.Upstream)
		if upstream != consts.DnsRequestOutboundIndex_LogicalOr {
			if goodSubrule == match.Not {
				badRule = true
			}
			goodSubrule = false
		}

		if upstream&consts.DnsRequestOutboundIndex_LogicalMask != consts.DnsRequestOutboundIndex_LogicalMask {
			if !badRule {
				return upstream, nil
			}
			badRule = false
		}
	}
	return 0, fmt.Errorf("no match set hit")
}

// mockDnsResponseMatcher simulates DNS response routing matcher
type mockDnsResponseMatcher struct {
	domainMatcher *mockDomainMatcher
	ipSet         []*trie.Trie
	matches       []dnsResponseMatchSet
}

func (m *mockDnsResponseMatcher) Match(qName string, qType uint16, ips []netip.Addr, upstream consts.DnsRequestOutboundIndex) (upstreamIndex consts.DnsResponseOutboundIndex, err error) {
	domainMatchBitmap := m.domainMatcher.MatchDomainBitmap(qName)
	bin128List := make([]string, 0, len(ips))
	for _, ip := range ips {
		bin128List = append(bin128List, trie.Prefix2bin128(netip.MustParsePrefix(ip.String()+"/32")))
	}

	goodSubrule := false
	badRule := false
	for i, match := range m.matches {
		if badRule || goodSubrule {
			goto beforeNextLoop
		}
		switch match.Type {
		case consts.MatchType_DomainSet:
			if domainMatchBitmap != nil && (domainMatchBitmap[i/32]>>(i%32))&1 > 0 {
				goodSubrule = true
			}
		case consts.MatchType_IpSet:
			for _, bin128 := range bin128List {
				if m.ipSet[match.Value].HasPrefix(bin128) {
					goodSubrule = true
					break
				}
			}
		case consts.MatchType_QType:
			if qType == uint16(match.Value) {
				goodSubrule = true
			}
		case consts.MatchType_Upstream:
			if upstream == consts.DnsRequestOutboundIndex(match.Value) {
				goodSubrule = true
			}
		case consts.MatchType_Fallback:
			goodSubrule = true
		}
	beforeNextLoop:
		upstream := consts.DnsResponseOutboundIndex(match.Upstream)
		if upstream != consts.DnsResponseOutboundIndex_LogicalOr {
			if goodSubrule == match.Not {
				badRule = true
			}
			goodSubrule = false
		}

		if upstream&consts.DnsResponseOutboundIndex_LogicalMask != consts.DnsResponseOutboundIndex_LogicalMask {
			if !badRule {
				return upstream, nil
			}
			badRule = false
		}
	}
	return 0, fmt.Errorf("no match set hit")
}

func buildTestDnsRequestMatcher(b *testing.B, ruleCount int) *mockDnsRequestMatcher {
	matches := make([]dnsRequestMatchSet, 0, ruleCount+1)

	// Add domain rules
	for i := 0; i < ruleCount/2; i++ {
		matches = append(matches, dnsRequestMatchSet{
			Type:     consts.MatchType_DomainSet,
			Upstream: uint8(i % 10),
		})
	}

	// Add QType rules
	qtypes := []uint16{dnsmessage.TypeA, dnsmessage.TypeAAAA, dnsmessage.TypeMX, dnsmessage.TypeTXT}
	for i := 0; i < ruleCount/4; i++ {
		matches = append(matches, dnsRequestMatchSet{
			Type:     consts.MatchType_QType,
			Value:    qtypes[i%len(qtypes)],
			Upstream: uint8(i % 10),
		})
	}

	// Add fallback
	matches = append(matches, dnsRequestMatchSet{
		Type:     consts.MatchType_Fallback,
		Upstream: 0,
	})

	return &mockDnsRequestMatcher{
		domainMatcher: &mockDomainMatcher{domainCount: len(matches)},
		matches:       matches,
	}
}

func buildTestDnsResponseMatcher(b *testing.B, ruleCount int) *mockDnsResponseMatcher {
	matches := make([]dnsResponseMatchSet, 0, ruleCount+1)
	ipSets := make([]*trie.Trie, 0)

	// Add domain rules
	for i := 0; i < ruleCount/4; i++ {
		matches = append(matches, dnsResponseMatchSet{
			Type:     consts.MatchType_DomainSet,
			Upstream: uint8(i % 10),
		})
	}

	// Add IP rules
	for i := 0; i < ruleCount/4; i++ {
		prefixes := []netip.Prefix{
			netip.MustParsePrefix(fmt.Sprintf("10.%d.0.0/16", i%256)),
		}
		t, err := trie.NewTrieFromPrefixes(prefixes)
		if err != nil {
			b.Fatalf("failed to create trie: %v", err)
		}
		ipSets = append(ipSets, t)
		matches = append(matches, dnsResponseMatchSet{
			Type:     consts.MatchType_IpSet,
			Value:    uint16(len(ipSets) - 1),
			Upstream: uint8(i % 10),
		})
	}

	// Add upstream rules
	for i := 0; i < ruleCount/4; i++ {
		matches = append(matches, dnsResponseMatchSet{
			Type:     consts.MatchType_Upstream,
			Value:    uint16(i % 10),
			Upstream: uint8(i % 10),
		})
	}

	// Add fallback
	matches = append(matches, dnsResponseMatchSet{
		Type:     consts.MatchType_Fallback,
		Upstream: 0,
	})

	return &mockDnsResponseMatcher{
		domainMatcher: &mockDomainMatcher{domainCount: len(matches)},
		ipSet:         ipSets,
		matches:       matches,
	}
}

// =============================================================================
// Section 8: End-to-End DNS Query Flow Analysis
// =============================================================================

// BenchmarkDnsFlow_StageBreakdown analyzes each stage of DNS query processing
// This helps identify which part of the DNS flow is the bottleneck
func BenchmarkDnsFlow_StageBreakdown(b *testing.B) {
	// Setup components
	reqMatcher := buildTestDnsRequestMatcher(b, 100)
	respMatcher := buildTestDnsResponseMatcher(b, 100)

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

	dnsCache := &DnsCache{
		DomainBitmap:     []uint32{1, 2, 3},
		Answer:           answers,
		Deadline:         time.Now().Add(5 * time.Minute),
		OriginalDeadline: time.Now().Add(5 * time.Minute),
	}
	_ = dnsCache.PrepackResponse("example.com.", dnsmessage.TypeA)

	var cache sync.Map
	cache.Store("example.com.:1", dnsCache)

	ips := []netip.Addr{netip.MustParseAddr("93.184.216.34")}

	b.ResetTimer()

	// Measure each stage separately
	b.Run("1_CacheKeyGen", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = fmt.Sprintf("%s.:1", "example.com")
		}
	})

	b.Run("2_CacheLookup", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if val, ok := cache.Load("example.com.:1"); ok {
				_ = val.(*DnsCache)
			}
		}
	})

	b.Run("3_CacheHitResponse", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = dnsCache.GetPackedResponseWithApproximateTTL("example.com.", dnsmessage.TypeA, time.Now())
		}
	})

	b.Run("4_RequestRouting", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = reqMatcher.Match("example.com", dnsmessage.TypeA)
		}
	})

	b.Run("5_ResponseRouting", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = respMatcher.Match("example.com", dnsmessage.TypeA, ips, consts.DnsRequestOutboundIndex(0))
		}
	})

	b.Run("6_MessageParsing", func(b *testing.B) {
		msg := new(dnsmessage.Msg)
		msg.SetQuestion("example.com.", dnsmessage.TypeA)
		data, _ := msg.Pack()

		for i := 0; i < b.N; i++ {
			parsed := new(dnsmessage.Msg)
			_ = parsed.Unpack(data)
		}
	})

	b.Run("7_MessagePacking", func(b *testing.B) {
		msg := new(dnsmessage.Msg)
		msg.SetQuestion("example.com.", dnsmessage.TypeA)
		msg.Answer = answers

		for i := 0; i < b.N; i++ {
			_, _ = msg.Pack()
		}
	})
}

// BenchmarkDnsFlow_CompleteCacheHit measures complete DNS cache hit flow
// This simulates the entire path for a cache hit scenario
func BenchmarkDnsFlow_CompleteCacheHit(b *testing.B) {
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

	dnsCache := &DnsCache{
		DomainBitmap:     []uint32{1, 2, 3},
		Answer:           answers,
		Deadline:         time.Now().Add(5 * time.Minute),
		OriginalDeadline: time.Now().Add(5 * time.Minute),
	}
	_ = dnsCache.PrepackResponse("example.com.", dnsmessage.TypeA)

	var cache sync.Map
	cache.Store("example.com.:1", dnsCache)

	// Pre-create query
	query := new(dnsmessage.Msg)
	query.SetQuestion("example.com.", dnsmessage.TypeA)
	queryData, _ := query.Pack()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Step 1: Parse query
		parsedQuery := new(dnsmessage.Msg)
		_ = parsedQuery.Unpack(queryData)

		// Step 2: Generate cache key
		qname := parsedQuery.Question[0].Name
		qtype := parsedQuery.Question[0].Qtype
		cacheKey := fmt.Sprintf("%s:%d", qname, qtype)

		// Step 3: Lookup cache
		if val, ok := cache.Load(cacheKey); ok {
			c := val.(*DnsCache)
			// Step 4: Get pre-packed response
			if resp := c.GetPackedResponseWithApproximateTTL(qname, qtype, time.Now()); resp != nil {
				// Step 5: Response ready (would patch DNS ID here)
				_ = resp
			}
		}
	}
}

// BenchmarkDnsFlow_CompleteCacheHit_Parallel measures parallel DNS cache hit flow
func BenchmarkDnsFlow_CompleteCacheHit_Parallel(b *testing.B) {
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
	for i := 0; i < 1000; i++ {
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
			domain := fmt.Sprintf("domain%d.com", i%1000)
			cacheKey := fmt.Sprintf("%s.:1", domain)

			if val, ok := cache.Load(cacheKey); ok {
				c := val.(*DnsCache)
				_ = c.GetPackedResponseWithApproximateTTL(fmt.Sprintf("%s.", domain), dnsmessage.TypeA, time.Now())
			}
			i++
		}
	})
}

// BenchmarkDnsFlow_SyncMapOverhead measures sync.Map overhead at various sizes
func BenchmarkDnsFlow_SyncMapOverhead(b *testing.B) {
	sizes := []int{100, 1000, 10000, 100000}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("Size_%d", size), func(b *testing.B) {
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
						_ = val.(*DnsCache)
					}
					i++
				}
			})
		})
	}
}

// =============================================================================
// Section 9: BPF Map Update Overhead Analysis (Potential Bottleneck)
// =============================================================================

// BenchmarkDnsCache_RouteBindingRefresh measures the overhead of route binding refresh check
// This is called on every cache access and involves:
// 1. atomic load of lastRouteSyncNano
// 2. time comparison
// 3. potential CompareAndSwap
func BenchmarkDnsCache_RouteBindingRefresh(b *testing.B) {
	cache := &DnsCache{
		DomainBitmap:     []uint32{1, 2, 3},
		Answer:           []dnsmessage.RR{},
		Deadline:         time.Now().Add(5 * time.Minute),
		OriginalDeadline: time.Now().Add(5 * time.Minute),
	}
	cache.MarkRouteBindingRefreshed(time.Now())

	minInterval := 10 * time.Second

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Simulate the check in LookupDnsRespCache
		cache.ShouldRefreshRouteBinding(time.Now(), minInterval)
	}
}

// BenchmarkDnsCache_RouteBindingRefresh_Contention measures under contention
func BenchmarkDnsCache_RouteBindingRefresh_Contention(b *testing.B) {
	cache := &DnsCache{
		DomainBitmap:     []uint32{1, 2, 3},
		Answer:           []dnsmessage.RR{},
		Deadline:         time.Now().Add(5 * time.Minute),
		OriginalDeadline: time.Now().Add(5 * time.Minute),
	}
	cache.MarkRouteBindingRefreshed(time.Now())

	minInterval := 10 * time.Second

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			cache.ShouldRefreshRouteBinding(time.Now(), minInterval)
		}
	})
}

// BenchmarkTime_Now measures time.Now() overhead (called multiple times in cache lookup)
func BenchmarkTime_Now(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = time.Now()
	}
}

// BenchmarkTime_After measures time.After comparison overhead
func BenchmarkTime_After(b *testing.B) {
	now := time.Now()
	deadline := now.Add(5 * time.Minute)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = deadline.After(now)
	}
}

// BenchmarkTime_Sub measures time.Sub overhead
func BenchmarkTime_Sub(b *testing.B) {
	now := time.Now()
	deadline := now.Add(5 * time.Minute)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = deadline.Sub(now)
	}
}

// BenchmarkAtomic_Int64 measures atomic int64 operations
func BenchmarkAtomic_Int64(b *testing.B) {
	var val atomic.Int64
	val.Store(time.Now().UnixNano())

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = val.Load()
	}
}

func BenchmarkAtomic_CompareAndSwap(b *testing.B) {
	var val atomic.Int64
	val.Store(time.Now().UnixNano())

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		old := val.Load()
		val.CompareAndSwap(old, old+1)
	}
}

// BenchmarkSlice_Copy measures slice copy overhead (used in FillInto)
func BenchmarkSlice_Copy(b *testing.B) {
	src := make([]uint32, 256) // Typical DomainBitmap size
	dst := make([]uint32, 256)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy(dst, src)
	}
}

// BenchmarkSlice_Append measures slice append overhead
func BenchmarkSlice_Append(b *testing.B) {
	items := []netip.Addr{
		netip.MustParseAddr("192.168.1.1"),
		netip.MustParseAddr("192.168.1.2"),
		netip.MustParseAddr("192.168.1.3"),
		netip.MustParseAddr("192.168.1.4"),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var ips []netip.Addr
		ips = append(ips, items...)
		_ = ips
	}
}

// =============================================================================
// Section 10: Complete DNS Listener Flow Simulation
// =============================================================================

// BenchmarkDnsFlow_CompleteListenerPath simulates the complete DNS listener flow
// This includes all overhead that may not be captured in individual stage tests
func BenchmarkDnsFlow_CompleteListenerPath(b *testing.B) {
	// Setup - simulates DnsController setup
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

	dnsCache := &DnsCache{
		DomainBitmap:     []uint32{1, 2, 3},
		Answer:           answers,
		Deadline:         time.Now().Add(5 * time.Minute),
		OriginalDeadline: time.Now().Add(5 * time.Minute),
	}
	_ = dnsCache.PrepackResponse("example.com.", dnsmessage.TypeA)

	var cache sync.Map
	cache.Store("example.com.:1", dnsCache)

	// Pre-create request (simulates incoming DNS query)
	reqQuery := new(dnsmessage.Msg)
	reqQuery.SetQuestion("example.com.", dnsmessage.TypeA)
	reqData, _ := reqQuery.Pack()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Step 1: Parse incoming query (simulates receiving from UDP)
		incomingMsg := new(dnsmessage.Msg)
		if err := incomingMsg.Unpack(reqData); err != nil {
			b.Fatalf("unpack: %v", err)
		}

		// Step 2: Extract qname, qtype
		qname := incomingMsg.Question[0].Name
		qtype := incomingMsg.Question[0].Qtype

		// Step 3: Generate cache key
		cacheKey := fmt.Sprintf("%s:%d", qname, qtype)

		// Step 4: Lookup cache
		val, ok := cache.Load(cacheKey)
		if !ok {
			b.Fatalf("cache miss")
		}
		cached := val.(*DnsCache)

		// Step 5: Get pre-packed response
		now := time.Now()
		resp := cached.GetPackedResponseWithApproximateTTL(qname, qtype, now)
		if resp == nil {
			b.Fatalf("no response")
		}

		// Step 6: For DNS listener, we need to unpack and repack (SLOW PATH!)
		// This is what writeCachedResponse does when responseWriter != nil
		var respMsg dnsmessage.Msg
		if err := respMsg.Unpack(resp); err != nil {
			b.Fatalf("unpack response: %v", err)
		}
		respMsg.Id = incomingMsg.Id

		// Step 7: WriteMsg internally calls Pack()
		finalResp, err := respMsg.Pack()
		if err != nil {
			b.Fatalf("pack: %v", err)
		}
		_ = finalResp
	}
}

// BenchmarkDnsFlow_OptimizedListenerPath simulates optimized path (direct ID patch)
func BenchmarkDnsFlow_OptimizedListenerPath(b *testing.B) {
	// Setup
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

	dnsCache := &DnsCache{
		DomainBitmap:     []uint32{1, 2, 3},
		Answer:           answers,
		Deadline:         time.Now().Add(5 * time.Minute),
		OriginalDeadline: time.Now().Add(5 * time.Minute),
	}
	_ = dnsCache.PrepackResponse("example.com.", dnsmessage.TypeA)

	var cache sync.Map
	cache.Store("example.com.:1", dnsCache)

	// Pre-create request
	reqQuery := new(dnsmessage.Msg)
	reqQuery.SetQuestion("example.com.", dnsmessage.TypeA)
	reqData, _ := reqQuery.Pack()

	// Buffer pool simulation
	var bufPool = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, 1024)
			return &buf
		},
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Step 1: Parse incoming query
		incomingMsg := new(dnsmessage.Msg)
		if err := incomingMsg.Unpack(reqData); err != nil {
			b.Fatalf("unpack: %v", err)
		}

		// Step 2: Extract and lookup
		qname := incomingMsg.Question[0].Name
		qtype := incomingMsg.Question[0].Qtype
		cacheKey := fmt.Sprintf("%s:%d", qname, qtype)

		val, ok := cache.Load(cacheKey)
		if !ok {
			b.Fatalf("cache miss")
		}
		cached := val.(*DnsCache)

		// Step 3: Get pre-packed response
		resp := cached.GetPackedResponseWithApproximateTTL(qname, qtype, time.Now())
		if resp == nil {
			b.Fatalf("no response")
		}

		// Step 4: OPTIMIZED - Direct ID patch (no Unpack/Pack cycle)
		if len(resp) >= 2 && len(resp) <= 1024 {
			bufPtr := bufPool.Get().(*[]byte)
			patchedResp := (*bufPtr)[:len(resp)]
			copy(patchedResp, resp)
			binary.BigEndian.PutUint16(patchedResp[0:2], incomingMsg.Id)
			bufPool.Put(bufPtr)
			_ = patchedResp
		}
	}
}

// BenchmarkDnsFlow_ResponseWriterOverhead measures the overhead of responseWriter path
// This is the SLOW path that causes high latency
func BenchmarkDnsFlow_ResponseWriterOverhead(b *testing.B) {
	// Pre-packed response
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

	msg := &dnsmessage.Msg{
		MsgHdr: dnsmessage.MsgHdr{
			Rcode:              dnsmessage.RcodeSuccess,
			Response:           true,
			RecursionAvailable: true,
		},
		Question: []dnsmessage.Question{
			{Name: "example.com.", Qtype: dnsmessage.TypeA, Qclass: dnsmessage.ClassINET},
		},
		Answer:   answers,
		Compress: true,
	}
	prepacked, _ := msg.Pack()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// SLOW PATH: Unpack -> Set ID -> Pack (what writeCachedResponse does)
		var respMsg dnsmessage.Msg
		_ = respMsg.Unpack(prepacked)
		respMsg.Id = uint16(i)
		_, _ = respMsg.Pack()
	}
}

// BenchmarkDnsFlow_DirectIDPatch measures the fast path
func BenchmarkDnsFlow_DirectIDPatch(b *testing.B) {
	// Pre-packed response
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

	msg := &dnsmessage.Msg{
		MsgHdr: dnsmessage.MsgHdr{
			Rcode:              dnsmessage.RcodeSuccess,
			Response:           true,
			RecursionAvailable: true,
		},
		Question: []dnsmessage.Question{
			{Name: "example.com.", Qtype: dnsmessage.TypeA, Qclass: dnsmessage.ClassINET},
		},
		Answer:   answers,
		Compress: true,
	}
	prepacked, _ := msg.Pack()

	var bufPool = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, 1024)
			return &buf
		},
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// FAST PATH: Direct ID patch
		bufPtr := bufPool.Get().(*[]byte)
		patchedResp := (*bufPtr)[:len(prepacked)]
		copy(patchedResp, prepacked)
		binary.BigEndian.PutUint16(patchedResp[0:2], uint16(i))
		bufPool.Put(bufPtr)
		_ = patchedResp
	}
}

// =============================================================================
// Section 11: Complete DNS Listener Path Analysis
// =============================================================================

// BenchmarkDnsFlow_FullListenerPath simulates the exact path in ServeDNS
func BenchmarkDnsFlow_FullListenerPath(b *testing.B) {
	// Setup - simulates cache with pre-packed response
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

	dnsCache := &DnsCache{
		DomainBitmap:     []uint32{1, 2, 3},
		Answer:           answers,
		Deadline:         time.Now().Add(5 * time.Minute),
		OriginalDeadline: time.Now().Add(5 * time.Minute),
	}
	_ = dnsCache.PrepackResponse("example.com.", dnsmessage.TypeA)

	var cache sync.Map
	cache.Store("example.com.:1", dnsCache)

	// Pre-create request
	reqQuery := new(dnsmessage.Msg)
	reqQuery.SetQuestion("example.com.", dnsmessage.TypeA)
	reqData, _ := reqQuery.Pack()

	// Simulate client address
	clientAddr := "192.168.1.100:12345"

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// ===== ServeDNS starts here =====

		// Step 1: Parse client address (what ServeDNS does)
		host, portStr, _ := net.SplitHostPort(clientAddr)
		_ = host
		port, _ := strconv.Atoi(portStr)
		_ = port
		clientIP, _ := netip.ParseAddr(host)
		_ = netip.AddrPortFrom(clientIP, uint16(port))

		// Step 2: Parse incoming DNS query (miekg/dns does this before ServeDNS)
		incomingMsg := new(dnsmessage.Msg)
		_ = incomingMsg.Unpack(reqData)

		// Step 3: Extract qname, qtype
		qname := incomingMsg.Question[0].Name
		qtype := incomingMsg.Question[0].Qtype

		// Step 4: Generate cache key
		cacheKey := fmt.Sprintf("%s:%d", qname, qtype)

		// Step 5: Lookup cache
		val, ok := cache.Load(cacheKey)
		if !ok {
			b.Fatalf("cache miss")
		}
		cached := val.(*DnsCache)

		// Step 6: Get pre-packed response
		resp := cached.GetPackedResponseWithApproximateTTL(qname, qtype, time.Now())
		if resp == nil {
			b.Fatalf("no response")
		}

		// Step 7: writeCachedResponse for responseWriter path
		// THIS IS THE SLOW PATH - Unpack + Set ID + Pack
		var respMsg dnsmessage.Msg
		_ = respMsg.Unpack(resp)
		respMsg.Id = incomingMsg.Id
		finalResp, _ := respMsg.Pack()
		_ = finalResp
	}
}

// BenchmarkDnsFlow_RequestSelect measures the RequestSelect overhead
func BenchmarkDnsFlow_RequestSelect(b *testing.B) {
	// This would require actual DnsController setup, which is complex
	// For now, measure the routing lookup overhead
	routing := &mockRequestMatcher{
		domain: "example.com.",
		qtype:  dnsmessage.TypeA,
		result: 0,
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = routing.Match("example.com.", dnsmessage.TypeA)
	}
}

// mockRequestMatcher for benchmarking
type mockRequestMatcher struct {
	domain string
	qtype  uint16
	result int
}

func (m *mockRequestMatcher) Match(domain string, qtype uint16) (int, error) {
	return m.result, nil
}

// BenchmarkDnsFlow_AddressParsing measures the address parsing overhead in ServeDNS
func BenchmarkDnsFlow_AddressParsing(b *testing.B) {
	clientAddr := "192.168.1.100:12345"

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		host, portStr, _ := net.SplitHostPort(clientAddr)
		port, _ := strconv.Atoi(portStr)
		clientIP, _ := netip.ParseAddr(host)
		_ = netip.AddrPortFrom(clientIP, uint16(port))
		_ = host
		_ = port
	}
}

// BenchmarkDnsFlow_MiekgOverhead measures the overhead of miekg/dns server
func BenchmarkDnsFlow_MiekgOverhead(b *testing.B) {
	// Simulate what miekg/dns does for each request
	msg := new(dnsmessage.Msg)
	msg.SetQuestion("example.com.", dnsmessage.TypeA)
	packed, _ := msg.Pack()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// What miekg/dns does:
		// 1. Read from UDP
		incoming := new(dnsmessage.Msg)
		_ = incoming.Unpack(packed)

		// 2. Handler returns a message
		resp := new(dnsmessage.Msg)
		resp.SetReply(incoming)
		resp.Answer = []dnsmessage.RR{
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

		// 3. WriteMsg internally calls Pack()
		_, _ = resp.Pack()
	}
}

