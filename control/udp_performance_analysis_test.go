/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@daeuniverse.org>
 *
 * UDP Performance Analysis and Benchmark Suite
 *
 * This suite analyzes the performance issues raised in code review:
 * 1. UDP routing cache effectiveness (issue #1)
 * 2. Closure per packet overhead (issue #2)
 * 3. Ordered vs unordered ingress (issue #3)
 * 4. Port-based QUIC heuristics impact
 */

package control

import (
	"fmt"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/sniffing"
	"github.com/daeuniverse/outbound/pool"
)

// =============================================================================
// Issue #1: UDP Routing Cache Effectiveness Analysis
// =============================================================================

// BenchmarkUdpRoutingCache_SymmetricNatHit measures cache hit rate when using
// Symmetric NAT keys {Src, Dst} for QUIC traffic (port 443)
func BenchmarkUdpRoutingCache_SymmetricNatHit(b *testing.B) {
	src := netip.MustParseAddrPort("192.168.1.100:50000")

	// Pre-create mock endpoints for benchmarking (without starting goroutines)
	type mockEndpoint struct {
		ue  *UdpEndpoint
		dst netip.AddrPort
	}
	dstPorts := []uint16{443, 8443, 443, 8443}
	endpoints := make([]mockEndpoint, len(dstPorts))
	for i, port := range dstPorts {
		dst := netip.AddrPortFrom(netip.AddrFrom4([4]byte{93, 184, 216, byte(i + 1)}), port)
		ue := &UdpEndpoint{}
		rr := &bpfRoutingResult{
			Mark:     uint32(i + 1),
			Outbound: uint8(i % 10),
		}
		ue.UpdateCachedRoutingResult(dst, 17, rr)
		endpoints[i] = mockEndpoint{ue: ue, dst: dst}
	}

	var hits, misses atomic.Int64

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			port := dstPorts[i%len(dstPorts)]
			dst := netip.AddrPortFrom(netip.AddrFrom4([4]byte{93, 184, 216, byte(i%4 + 1)}), port)

			// Simulate QUIC traffic classification
			_ = ClassifyUdpFlow(src, dst, make([]byte, 1200))

			// Find matching endpoint (simulating pool lookup)
			// In real scenario, this would use flowDecision.CachedRoutingEndpointKey()
			found := false
			for _, ep := range endpoints {
				if ep.dst == dst {
					if cached, hit := ep.ue.GetCachedRoutingResult(dst, 17); hit {
						_ = cached
						hits.Add(1)
						found = true
						break
					}
				}
			}
			if !found {
				misses.Add(1)
			}
			i++
		}
	})

	total := hits.Load() + misses.Load()
	if total > 0 {
		b.ReportMetric(float64(hits.Load())/float64(total)*100, "hit%")
		b.ReportMetric(float64(misses.Load())/float64(total)*100, "miss%")
	}
}

// BenchmarkUdpRoutingCache_FullConeHit measures cache hit rate when using
// Full Cone NAT keys {Src} for non-QUIC traffic
func BenchmarkUdpRoutingCache_FullConeHit(b *testing.B) {
	src := netip.MustParseAddrPort("192.168.1.100:50000")

	// Create mock endpoint for benchmarking
	ue := &UdpEndpoint{}

	// Cache routing results for multiple destinations
	for i := 0; i < 4; i++ {
		dst := netip.AddrPortFrom(netip.AddrFrom4([4]byte{8, 8, 8, byte(i + 1)}), uint16(100+i))
		rr := &bpfRoutingResult{
			Mark:     uint32(i + 1),
			Outbound: uint8(i % 10),
		}
		ue.UpdateCachedRoutingResult(dst, 17, rr)
	}

	var hits, misses atomic.Int64

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			dst := netip.AddrPortFrom(netip.AddrFrom4([4]byte{8, 8, 8, byte(i%4 + 1)}), uint16(100+i%4))

			// Non-QUIC traffic uses Full Cone NAT
			_ = ClassifyUdpFlow(src, dst, []byte{0x00, 0x01})

			// Simulate cache lookup (in real code this would pool.Get by CachedRoutingEndpointKey)
			if cached, hit := ue.GetCachedRoutingResult(dst, 17); hit {
				_ = cached
				hits.Add(1)
			} else {
				misses.Add(1)
			}
			i++
		}
	})

	total := hits.Load() + misses.Load()
	if total > 0 {
		b.ReportMetric(float64(hits.Load())/float64(total)*100, "hit%")
		b.ReportMetric(float64(misses.Load())/float64(total)*100, "miss%")
	}
}

// BenchmarkUdpRoutingCache_QuicMultiFlow analyzes cache behavior with
// multiple QUIC flows to different 443 destinations
func BenchmarkUdpRoutingCache_QuicMultiFlow(b *testing.B) {
	src := netip.MustParseAddrPort("192.168.1.100:50000")

	// Simulate multiple QUIC connections to different servers on port 443
	numServers := []int{1, 10, 50, 100}

	for _, numSrv := range numServers {
		b.Run(fmt.Sprintf("Servers_%d", numSrv), func(b *testing.B) {
			// Pre-create mock endpoints
			endpoints := make([]*UdpEndpoint, numSrv)
			dsts := make([]netip.AddrPort, numSrv)
			for i := 0; i < numSrv; i++ {
				dst := netip.AddrPortFrom(
					netip.AddrFrom4([4]byte{byte(i >> 8), byte(i), 216, 34}),
					443,
				)
				dsts[i] = dst
				endpoints[i] = &UdpEndpoint{}

				rr := &bpfRoutingResult{
					Mark:     uint32(i + 1),
					Outbound: uint8(i % 10),
				}
				endpoints[i].UpdateCachedRoutingResult(dst, 17, rr)
			}

			var hits, misses atomic.Int64

			b.ReportAllocs()
			b.ResetTimer()

			b.RunParallel(func(pb *testing.PB) {
				i := 0
				for pb.Next() {
					serverIdx := i % numSrv
					dst := dsts[serverIdx]

					_ = ClassifyUdpFlow(src, dst, make([]byte, 1200))

					// Simulate endpoint lookup by matching destination
					if cached, hit := endpoints[serverIdx].GetCachedRoutingResult(dst, 17); hit {
						_ = cached
						hits.Add(1)
					} else {
						misses.Add(1)
					}
					i++
				}
			})

			total := hits.Load() + misses.Load()
			if total > 0 {
				b.ReportMetric(float64(hits.Load())/float64(total)*100, "hit%")
				b.ReportMetric(float64(numSrv), "endpoints")
			}
		})
	}
}

// =============================================================================
// Issue #2: Closure Overhead Analysis
// =============================================================================

// BenchmarkUdpIngress_ClosurePerPacket measures baseline with closure per packet
func BenchmarkUdpIngress_ClosurePerPacket(b *testing.B) {
	src := netip.MustParseAddrPort("192.168.1.100:50000")
	dst := netip.MustParseAddrPort("93.184.216.34:443")

	var processed atomic.Int64

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			// Simulate current closure creation
			pktBuf := pool.Get(1200)

			task := func() {
				defer pktBuf.Put()
				// Simulate packet processing work
				flowDecision := ClassifyUdpFlow(src, dst, pktBuf)
				_ = flowDecision.CachedRoutingEndpointKey()
				processed.Add(1)
			}

			task()
		}
	})
}

// BenchmarkUdpIngress_ObjectPool measures alternative with object pool
type udpTask struct {
	pktBuf      pool.PB
	convergeSrc netip.AddrPort
	realDst     netip.AddrPort
}

var udpTaskObjectPool = sync.Pool{
	New: func() interface{} {
		return new(udpTask)
	},
}

func BenchmarkUdpIngress_ObjectPool(b *testing.B) {
	src := netip.MustParseAddrPort("192.168.1.100:50000")
	dst := netip.MustParseAddrPort("93.184.216.34:443")

	var processed atomic.Int64

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			task := udpTaskObjectPool.Get().(*udpTask)
			task.pktBuf = pool.Get(1200)
			task.convergeSrc = src
			task.realDst = dst

			// Simulate processing
			flowDecision := ClassifyUdpFlow(task.convergeSrc, task.realDst, task.pktBuf)
			_ = flowDecision.CachedRoutingEndpointKey()

			task.pktBuf.Put()
			task.pktBuf = nil // Avoid holding reference
			udpTaskObjectPool.Put(task)
			processed.Add(1)
		}
	})
}

// BenchmarkUdpIngress_DirectCall measures direct call without any indirection
func BenchmarkUdpIngress_DirectCall(b *testing.B) {
	src := netip.MustParseAddrPort("192.168.1.100:50000")
	dst := netip.MustParseAddrPort("93.184.216.34:443")

	var processed atomic.Int64

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			pktBuf := pool.Get(1200)
			// Direct inline processing
			flowDecision := ClassifyUdpFlow(src, dst, pktBuf)
			_ = flowDecision.CachedRoutingEndpointKey()
			pktBuf.Put()
			processed.Add(1)
		}
	})
}

// =============================================================================
// Issue #3: Ordered vs Unordered Ingress
// =============================================================================

// BenchmarkUdpIngress_OrderedVsUnordered compares performance
func BenchmarkUdpIngress_OrderedVsUnordered(b *testing.B) {
	packetTypes := []struct {
		name    string
		data    []byte
		dstPort uint16
		ordered bool
	}{
		{name: "DNS", data: make([]byte, 512), dstPort: 53, ordered: false},
		{name: "QUIC_443", data: make([]byte, 1200), dstPort: 443, ordered: true},
		{name: "QUIC_8443", data: make([]byte, 1200), dstPort: 8443, ordered: true},
		{name: "Generic_UDP", data: make([]byte, 512), dstPort: 12345, ordered: false},
	}

	for _, pktType := range packetTypes {
		b.Run(pktType.name, func(b *testing.B) {
			src := netip.MustParseAddrPort("192.168.1.100:50000")
			dst := netip.AddrPortFrom(netip.AddrFrom4([4]byte{93, 184, 216, 34}), pktType.dstPort)

			flowDecision := ClassifyUdpFlow(src, dst, pktType.data)
			shouldBeOrdered := flowDecision.ShouldUseOrderedIngress()

			b.ReportAllocs()
			b.ResetTimer()

			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					// Measure classification cost
					_ = flowDecision.ShouldUseOrderedIngress()
					_ = flowDecision.CachedRoutingEndpointKey()
					_ = flowDecision.EndpointKeyForDial("")
				}
			})

			if shouldBeOrdered != pktType.ordered {
				b.Errorf("Classification mismatch: got ordered=%v, expected=%v", shouldBeOrdered, pktType.ordered)
			}

			b.ReportMetric(float64(b2i(shouldBeOrdered)), "ordered")
		})
	}
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// BenchmarkUdpIngress_Hysteria2Port443 analyzes impact on Hysteria2-like traffic
func BenchmarkUdpIngress_Hysteria2Port443(b *testing.B) {
	src := netip.MustParseAddrPort("192.168.1.100:50000")
	// Use IP address instead of domain for parsing
	dst := netip.MustParseAddrPort("93.184.216.34:443")

	// Simulate Hysteria2 traffic (UDP on port 443, but not QUIC)
	nonQuicData := make([]byte, 1200)

	flowDecision := ClassifyUdpFlow(src, dst, nonQuicData)

	b.Run("Classification", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()

		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				_ = flowDecision.ShouldUseOrderedIngress()
				_ = flowDecision.PreferSymmetricNat()
				_ = flowDecision.EndpointKeyForDial("example.com")
			}
		})

		// Report classification result
		ordered := flowDecision.ShouldUseOrderedIngress()
		symmetric := flowDecision.PreferSymmetricNat()
		b.ReportMetric(float64(b2i(ordered)), "uses_ordered")
		b.ReportMetric(float64(b2i(symmetric)), "uses_symmetric")
	})

	b.Run("TaskPoolOverhead", func(b *testing.B) {
		taskPool := NewUdpTaskPool()
		var done atomic.Int64

		b.ReportAllocs()
		b.ResetTimer()

		// Only test if ordered ingress is used
		if flowDecision.ShouldUseOrderedIngress() {
			key := flowDecision.Key
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					taskPool.EmitTask(key, func() {
						done.Add(1)
					})
				}
			})

			deadline := time.Now().Add(5 * time.Second)
			for done.Load() < int64(b.N) && time.Now().Before(deadline) {
				runtime.Gosched()
			}
		} else {
			b.Skip("not using ordered ingress")
		}
	})
}

// =============================================================================
// Port Heuristics Analysis
// =============================================================================

// BenchmarkUdpFlowClassification_PortHeuristics analyzes port-based classification
func BenchmarkUdpFlowClassification_PortHeuristics(b *testing.B) {
	scenarios := []struct {
		name    string
		srcPort uint16
		dstPort uint16
		isQuic  bool
		data    []byte
	}{
		{name: "QUIC_Initial_443", srcPort: 50000, dstPort: 443, isQuic: true, data: createQuicInitialPacket()},
		{name: "Non_QUIC_443", srcPort: 50000, dstPort: 443, isQuic: false, data: make([]byte, 512)},
		{name: "QUIC_Initial_8443", srcPort: 50000, dstPort: 8443, isQuic: true, data: createQuicInitialPacket()},
		{name: "Non_QUIC_8443", srcPort: 50000, dstPort: 8443, isQuic: false, data: make([]byte, 512)},
		{name: "Generic_UDP", srcPort: 50000, dstPort: 12345, isQuic: false, data: make([]byte, 512)},
		{name: "DNS", srcPort: 50000, dstPort: 53, isQuic: false, data: createDnsPacket()},
	}

	for _, scenario := range scenarios {
		b.Run(scenario.name, func(b *testing.B) {
			src := netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 168, 1, 100}), scenario.srcPort)
			dst := netip.AddrPortFrom(netip.AddrFrom4([4]byte{93, 184, 216, 34}), scenario.dstPort)

			b.ReportAllocs()
			b.ResetTimer()

			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					decision := ClassifyUdpFlow(src, dst, scenario.data)

					// Verify expectations
					if scenario.isQuic && !decision.IsQuicInitial {
						b.Errorf("Expected QUIC initial detection")
					}

					// Track metrics
					_ = decision.ShouldUseOrderedIngress()
					_ = decision.PreferSymmetricNat()
					_ = decision.EndpointKeyForDial("")
				}
			})

			// Report classification characteristics
			decision := ClassifyUdpFlow(src, dst, scenario.data)
			b.ReportMetric(float64(b2i(decision.IsQuicInitial)), "is_quic_initial")
			b.ReportMetric(float64(b2i(decision.IsLikelyQuicData)), "is_likely_quic")
			b.ReportMetric(float64(b2i(decision.ShouldUseOrderedIngress())), "ordered_ingress")
			b.ReportMetric(float64(b2i(decision.PreferSymmetricNat())), "symmetric_nat")
		})
	}
}

// =============================================================================
// Issue #4: High PPS Stress Tests
// =============================================================================

// BenchmarkUdpIngress_HighPPS_Simulated simulates high PPS UDP traffic
func BenchmarkUdpIngress_HighPPS_Simulated(b *testing.B) {
	workers := runtime.GOMAXPROCS(0)
	packetRates := []int{
		10_000,    // 10K PPS
		50_000,    // 50K PPS
		100_000,   // 100K PPS
		500_000,   // 500K PPS
		1_000_000, // 1M PPS
	}

	trafficMixes := []struct {
		name           string
		quicPercent    int
		dnsPercent     int
		genericPercent int
	}{
		{name: "All_QUIC", quicPercent: 100, dnsPercent: 0, genericPercent: 0},
		{name: "Mixed_70QUIC", quicPercent: 70, dnsPercent: 20, genericPercent: 10},
		{name: "Mixed_50QUIC", quicPercent: 50, dnsPercent: 30, genericPercent: 20},
		{name: "All_Generic", quicPercent: 0, dnsPercent: 10, genericPercent: 90},
	}

	for _, rate := range packetRates {
		b.Run(fmt.Sprintf("Rate_%dpps", rate), func(b *testing.B) {
			for _, mix := range trafficMixes {
				b.Run(mix.name, func(b *testing.B) {
					src := netip.MustParseAddrPort("192.168.1.100:50000")

					var ops atomic.Int64
					b.SetParallelism(workers)
					b.ReportAllocs()
					b.ResetTimer()

					b.RunParallel(func(pb *testing.PB) {
						i := 0
						for pb.Next() {
							var dstPort uint16
							var data []byte
							pct := i % 100

							if pct < mix.quicPercent {
								dstPort = 443
								data = createQuicInitialPacket()
							} else if pct < mix.quicPercent+mix.dnsPercent {
								dstPort = 53
								data = createDnsPacket()
							} else {
								dstPort = 12345 + uint16(i%1000)
								data = make([]byte, 512)
							}

							dst := netip.AddrPortFrom(
								netip.AddrFrom4([4]byte{93, 184, 216, byte(i%100 + 1)}),
								dstPort,
							)

							flowDecision := ClassifyUdpFlow(src, dst, data)
							_ = flowDecision.CachedRoutingEndpointKey()
							_ = flowDecision.ShouldUseOrderedIngress()

							ops.Add(1)
							i++
						}
					})

					opsPerSec := float64(ops.Load()) / b.Elapsed().Seconds()
					b.ReportMetric(opsPerSec, "ops/s")
				})
			}
		})
	}
}

// =============================================================================
// Helper Functions
// =============================================================================

func createQuicInitialPacket() []byte {
	// Simplified QUIC Initial packet header
	data := make([]byte, 1200)
	data[0] = 0xC0 // Long header, Initial packet
	data[1] = 0x00 // Version (placeholder)
	// Rest is zeros for benchmark purposes
	return data
}

func createDnsPacket() []byte {
	// Simplified DNS query packet
	data := make([]byte, 512)
	data[0] = 0x12 // Transaction ID high
	data[1] = 0x34 // Transaction ID low
	data[2] = 0x01 // Standard query
	data[3] = 0x00 // Recursion desired
	data[4] = 0x00 // Query count high
	data[5] = 0x01 // Query count low
	return data
}

// IsLikelyQuicInitialPacket is a simplified version for testing
func isLikelyQuicInitialPacketForTest(data []byte) bool {
	if len(data) < 5 {
		return false
	}
	// QUIC Initial packet: Long header (0x80+) and Initial type (0x00-0x03 at bits)
	firstByte := data[0]
	if firstByte&0x80 == 0 {
		return false // Short header
	}
	// Check for Initial packet type
	packetType := (firstByte & 0x30) >> 4
	return packetType == 0x00 // Initial
}

// BenchmarkSniffing_IsLikelyQuicInitialPacket benchmarks the QUIC detection
func BenchmarkSniffing_IsLikelyQuicInitialPacket(b *testing.B) {
	scenarios := []struct {
		name string
		data []byte
	}{
		{name: "QUIC_Initial_1200", data: createQuicInitialPacket()},
		{name: "QUIC_Initial_500", data: createQuicInitialPacket()[:500]},
		{name: "DNS_512", data: createDnsPacket()},
		{name: "Generic_1200", data: make([]byte, 1200)},
		{name: "Generic_64", data: make([]byte, 64)},
	}

	for _, scenario := range scenarios {
		b.Run(scenario.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()

			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					_ = sniffing.IsLikelyQuicInitialPacket(scenario.data)
				}
			})
		})
	}
}

// =============================================================================
// Cache Key Comparison
// =============================================================================

// BenchmarkUdpEndpointKey_Hash benchmarks key hashing for map lookups
func BenchmarkUdpEndpointKey_Hash(b *testing.B) {
	keyTypes := []struct {
		name string
		key  UdpEndpointKey
	}{
		{name: "FullCone", key: UdpEndpointKey{
			Src: netip.MustParseAddrPort("192.168.1.100:50000"),
		}},
		{name: "Symmetric", key: UdpEndpointKey{
			Src: netip.MustParseAddrPort("192.168.1.100:50000"),
			Dst: netip.MustParseAddrPort("93.184.216.34:443"),
		}},
	}

	for _, kt := range keyTypes {
		b.Run(kt.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()

			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					_ = fmt.Sprintf("%v", kt.key) // Stringify for hash
				}
			})
		})
	}
}

// BenchmarkUdpFlowDecision_AllKeys benchmarks all key generation methods
func BenchmarkUdpFlowDecision_AllKeys(b *testing.B) {
	src := netip.MustParseAddrPort("192.168.1.100:50000")
	dst := netip.MustParseAddrPort("93.184.216.34:443")
	data := createQuicInitialPacket()

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			decision := ClassifyUdpFlow(src, dst, data)
			_ = decision.SymmetricNatEndpointKey()
			_ = decision.FullConeNatEndpointKey()
			_ = decision.CachedRoutingEndpointKey()
			_ = decision.EndpointKeyForDial("")
			_ = decision.EndpointKeyForDial("example.com")
		}
	})
}
