/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@daeuniverse.org>
 *
 * Detailed routing matching benchmarks for optimization analysis
 */

package control

import (
	"fmt"
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
)

// BenchmarkRoutingMatcher_IPOnly_Match measures IP-only routing performance
func BenchmarkRoutingMatcher_IPOnly_Match(b *testing.B) {
	matcher := buildTestRoutingMatcher(b, 100)
	srcAddr := netip.AddrFrom4([4]byte{192, 168, 1, 100})
	dstAddr := netip.AddrFrom4([4]byte{93, 184, 216, 34})

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		matcher.Match(
			srcAddr.As16(),
			dstAddr.As16(),
			12345,
			443,
			consts.IpVersion_4,
			consts.L4ProtoType_TCP,
			"", // No domain
			[16]byte{},
			0,
			[16]byte{},
		)
	}
}

// BenchmarkRoutingMatcher_DomainMatch measures domain routing with pre-computed bitmap
func BenchmarkRoutingMatcher_DomainMatch(b *testing.B) {
	matcher := buildTestRoutingMatcher(b, 100)
	srcAddr := netip.AddrFrom4([4]byte{192, 168, 1, 100})
	dstAddr := netip.AddrFrom4([4]byte{93, 184, 216, 34})

	// Pre-generate domains to test
	domains := make([]string, 1000)
	for i := range 1000 {
		domains[i] = fmt.Sprintf("domain%d.example.com", i)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		matcher.Match(
			srcAddr.As16(),
			dstAddr.As16(),
			12345,
			443,
			consts.IpVersion_4,
			consts.L4ProtoType_TCP,
			domains[i%1000],
			[16]byte{},
			0,
			[16]byte{},
		)
	}
}

// BenchmarkRoutingMatcher_PortMatch measures port matching performance
func BenchmarkRoutingMatcher_PortMatch(b *testing.B) {
	matcher := buildTestRoutingMatcher(b, 100)
	srcAddr := netip.AddrFrom4([4]byte{192, 168, 1, 100})
	dstAddr := netip.AddrFrom4([4]byte{93, 184, 216, 34})

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		matcher.Match(
			srcAddr.As16(),
			dstAddr.As16(),
			12345,
			uint16(443+(i%100)), // Various ports
			consts.IpVersion_4,
			consts.L4ProtoType_TCP,
			"",
			[16]byte{},
			0,
			[16]byte{},
		)
	}
}

// BenchmarkRoutingMatcher_EarlyExit measures performance when rules hit early
func BenchmarkRoutingMatcher_EarlyExit(b *testing.B) {
	// Build matcher with rule that hits at position 5 (reusing existing helper)
	matcher := buildTestRoutingMatcher(b, 10) // Small rule set = early hit
	srcAddr := netip.AddrFrom4([4]byte{192, 168, 1, 100})
	dstAddr := netip.AddrFrom4([4]byte{93, 184, 216, 34})

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		matcher.Match(
			srcAddr.As16(),
			dstAddr.As16(),
			12345,
			443,
			consts.IpVersion_4,
			consts.L4ProtoType_TCP,
			"",
			[16]byte{},
			0,
			[16]byte{},
		)
	}
}

// BenchmarkRoutingMatcher_Parallel measures parallel routing performance
func BenchmarkRoutingMatcher_Parallel(b *testing.B) {
	matcher := buildTestRoutingMatcher(b, 100)
	srcAddr := netip.AddrFrom4([4]byte{192, 168, 1, 100})
	dstAddr := netip.AddrFrom4([4]byte{93, 184, 216, 34})

	var counter atomic.Int64

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			matcher.Match(
				srcAddr.As16(),
				dstAddr.As16(),
				12345,
				443,
				consts.IpVersion_4,
				consts.L4ProtoType_TCP,
				fmt.Sprintf("domain%d.example.com", i%100),
				[16]byte{},
				0,
				[16]byte{},
			)
			counter.Add(1)
			i++
		}
	})
}

// BenchmarkRoutingMatcher_SmallRules measures with small rule set
func BenchmarkRoutingMatcher_SmallRules(b *testing.B) {
	sizes := []int{5, 10, 20}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("Rules_%d", size), func(b *testing.B) {
			matcher := buildTestRoutingMatcher(b, size)
			srcAddr := netip.AddrFrom4([4]byte{192, 168, 1, 100})
			dstAddr := netip.AddrFrom4([4]byte{93, 184, 216, 34})

			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				matcher.Match(
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
