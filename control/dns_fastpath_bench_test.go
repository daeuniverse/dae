/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 *
 * DNS Fast Path Performance Benchmark
 *
 * This benchmark compares the performance impact of the DNS fast path optimization
 * that skips routing cache updates for DNS queries (port 53).
 *
 * Key measurements:
 * 1. BPF map lookup overhead with/without DNS bloat
 * 2. Userspace fallback routing overhead
 * 3. End-to-end DNS query latency
 */

package control

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/pkg/trie"
	dnsmessage "github.com/miekg/dns"
)

// =============================================================================
// Section 1: BPF Map Lookup Performance (simulated)
// =============================================================================

// mockRoutingTuplesMap simulates the BPF routing_tuples_map
type mockRoutingTuplesMap struct {
	mu        sync.RWMutex
	entries   map[string]*mockRoutingResult
	hitCount  atomic.Int64
	missCount atomic.Int64
}

// mockRoutingResult simulates the routing result stored in map
type mockRoutingResult struct {
	Outbound uint8
	Mark     uint32
	Must     uint8
	Mac      [6]uint8
	Pname    [16]uint8
	Pid      uint32
	Dscp     uint8
}

func newMockRoutingTuplesMap() *mockRoutingTuplesMap {
	return &mockRoutingTuplesMap{
		entries: make(map[string]*mockRoutingResult),
	}
}

// Lookup simulates bpf_map_lookup_elem
func (m *mockRoutingTuplesMap) Lookup(key string) (*mockRoutingResult, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	val, ok := m.entries[key]
	if ok {
		m.hitCount.Add(1)
	} else {
		m.missCount.Add(1)
	}
	return val, ok
}

// Update simulates bpf_map_update_elem
func (m *mockRoutingTuplesMap) Update(key string, val *mockRoutingResult) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries[key] = val
}

// Size returns current map size
func (m *mockRoutingTuplesMap) Size() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.entries)
}

// simulateOldPath simulates the OLD behavior: cache all DNS queries
// Each DNS query with random source port creates a new entry
func simulateOldPath(b *testing.B, mapSize int) {
	routingMap := newMockRoutingTuplesMap()

	// Pre-populate map with non-DNS entries (simulating normal traffic)
	for i := 0; i < mapSize; i++ {
		key := fmt.Sprintf("10.0.0.%d:443:93.184.216.34:443:6", i%256)
		routingMap.Update(key, &mockRoutingResult{
			Outbound: 1,
			Mark:     0,
		})
	}

	b.ResetTimer()
	b.ReportAllocs()

	queryNum := 0
	for i := 0; i < b.N; i++ {
		// Simulate DNS query with random source port (the problem!)
		srcPort := 20000 + (queryNum % 40000)
		key := fmt.Sprintf("192.168.1.100:%d:8.8.8.8:53:17", srcPort)

		// OLD PATH: Always write to map
		routingMap.Update(key, &mockRoutingResult{
			Outbound: 1,
			Mark:     0,
		})

		// Simulate response path lookup (will miss due to reverse tuple)
		respKey := fmt.Sprintf("8.8.8.8:53:192.168.1.100:%d:17", srcPort)
		routingMap.Lookup(respKey)

		queryNum++
	}
}

// simulateNewPath simulates the NEW behavior: skip DNS cache writes
func simulateNewPath(b *testing.B, mapSize int) {
	routingMap := newMockRoutingTuplesMap()

	// Pre-populate map with non-DNS entries
	for i := 0; i < mapSize; i++ {
		key := fmt.Sprintf("10.0.0.%d:443:93.184.216.34:443:6", i%256)
		routingMap.Update(key, &mockRoutingResult{
			Outbound: 1,
			Mark:     0,
		})
	}

	b.ResetTimer()
	b.ReportAllocs()

	queryNum := 0
	for i := 0; i < b.N; i++ {
		srcPort := 20000 + (queryNum % 40000)
		key := fmt.Sprintf("192.168.1.100:%d:8.8.8.8:53:17", srcPort)

		// NEW PATH: Skip DNS cache writes
		// (do nothing, just check if it's DNS)
		_ = key // would check dport == 53

		// Response path still misses
		respKey := fmt.Sprintf("8.8.8.8:53:192.168.1.100:%d:17", srcPort)
		routingMap.Lookup(respKey)

		queryNum++
	}
}

// BenchmarkBpfMap_OldPath measures performance with DNS entries bloating the map
func BenchmarkBpfMap_OldPath(b *testing.B) {
	mapSizes := []int{1000, 10000, 50000, 100000}

	for _, size := range mapSizes {
		b.Run(fmt.Sprintf("MapSize_%d", size), func(b *testing.B) {
			simulateOldPath(b, size)
		})
	}
}

// BenchmarkBpfMap_NewPath measures performance WITHOUT DNS bloat
func BenchmarkBpfMap_NewPath(b *testing.B) {
	mapSizes := []int{1000, 10000, 50000, 100000}

	for _, size := range mapSizes {
		b.Run(fmt.Sprintf("MapSize_%d", size), func(b *testing.B) {
			simulateNewPath(b, size)
		})
	}
}

// BenchmarkBpfMap_LookupScalability compares lookup performance as map grows
func BenchmarkBpfMap_LookupScalability(b *testing.B) {
	mapSizes := []int{100, 1000, 10000, 50000, 100000}

	for _, size := range mapSizes {
		b.Run(fmt.Sprintf("Size_%d", size), func(b *testing.B) {
			routingMap := newMockRoutingTuplesMap()

			// Pre-populate with mixed traffic
			for i := 0; i < size; i++ {
				// 70% non-DNS, 30% DNS (old behavior)
				if i%10 < 7 {
					key := fmt.Sprintf("10.0.0.%d:443:93.184.216.%d:443:6", i%256, i%256)
					routingMap.Update(key, &mockRoutingResult{Outbound: 1})
				} else {
					srcPort := 20000 + (i % 40000)
					key := fmt.Sprintf("192.168.1.100:%d:8.8.8.8:53:17", srcPort)
					routingMap.Update(key, &mockRoutingResult{Outbound: 1})
				}
			}

			// Benchmark lookups
			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				key := fmt.Sprintf("10.0.0.%d:443:93.184.216.34:443:6", i%256)
				routingMap.Lookup(key)
			}
		})
	}
}

// =============================================================================
// Section 2: Userspace Fallback Overhead
// =============================================================================

// mockRoutingMatcher simulates userspace routing matcher
type mockRoutingMatcher struct {
	lpmMatchers []*trie.Trie
	rules       int
}

func (m *mockRoutingMatcher) Match(src, dst [16]byte, sport, dport uint16, ipVersion consts.IpVersionType, l4proto consts.L4ProtoType, domain string) (uint8, uint32, bool, error) {
	// Simplified routing logic
	if dport == 53 {
		return 1, 0, false, nil // DNS -> direct
	}
	return 0, 0, false, nil
}

func buildMockRoutingMatcher(ruleCount int) *mockRoutingMatcher {
	matchers := make([]*trie.Trie, 0, ruleCount/10)

	// Create some LPM tries for IP matching
	for i := 0; i < ruleCount/10 && i < 50; i++ {
		prefixes := []netip.Prefix{
			netip.MustParsePrefix(fmt.Sprintf("10.%d.0.0/16", i%256)),
		}
		t, _ := trie.NewTrieFromPrefixes(prefixes)
		matchers = append(matchers, t)
	}

	return &mockRoutingMatcher{
		lpmMatchers: matchers,
		rules:       ruleCount,
	}
}

// BenchmarkUserspaceFallback measures the cost of userspace routing (fallback path)
func BenchmarkUserspaceFallback(b *testing.B) {
	ruleCounts := []int{50, 100, 500, 1000}

	for _, ruleCount := range ruleCounts {
		b.Run(fmt.Sprintf("Rules_%d", ruleCount), func(b *testing.B) {
			matcher := buildMockRoutingMatcher(ruleCount)

			srcAddr := netip.AddrFrom4([4]byte{192, 168, 1, 100}).As16()
			dstAddr := netip.MustParseAddr("8.8.8.8").As16()

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				srcPort := uint16(20000 + i%40000)
				_, _, _, _ = matcher.Match(srcAddr, dstAddr, srcPort, 53, consts.IpVersion_4, consts.L4ProtoType_UDP, "")
			}
		})
	}
}

// =============================================================================
// Section 3: End-to-End DNS Query Flow Comparison
// =============================================================================

// dnsQueryScenario simulates a realistic DNS query scenario
type dnsQueryScenario struct {
	routingMap  *mockRoutingTuplesMap
	matcher     *mockRoutingMatcher
	useFastPath bool // true = new optimization, false = old behavior
}

func (s *dnsQueryScenario) processQuery(srcPort uint16, dstIP string) time.Duration {
	start := time.Now()

	// Step 1: Check BPF cache
	key := fmt.Sprintf("192.168.1.100:%d:%s:53:17", srcPort, dstIP)

	if !s.useFastPath {
		// OLD: Write to map (bloating)
		s.routingMap.Update(key, &mockRoutingResult{Outbound: 1})
	}

	// Step 2: Cache miss (both old and new)
	if _, ok := s.routingMap.Lookup(key); !ok {
		// Step 3: Userspace fallback routing
		srcAddr := netip.AddrFrom4([4]byte{192, 168, 1, 100}).As16()
		dstAddr := netip.MustParseAddr(dstIP).As16()
		_, _, _, _ = s.matcher.Match(srcAddr, dstAddr, srcPort, 53, consts.IpVersion_4, consts.L4ProtoType_UDP, "")
	}

	return time.Since(start)
}

// BenchmarkDnsFlow_Comparison directly compares old vs new path
func BenchmarkDnsFlow_Comparison(b *testing.B) {
	ruleCounts := []int{100, 500}
	queriesPerRun := []int{1000, 10000}

	for _, ruleCount := range ruleCounts {
		for _, numQueries := range queriesPerRun {
			b.Run(fmt.Sprintf("Rules_%d_Queries_%d", ruleCount, numQueries), func(b *testing.B) {
				matcher := buildMockRoutingMatcher(ruleCount)

				b.Run("OldPath", func(b *testing.B) {
					routingMap := newMockRoutingTuplesMap()
					scenario := &dnsQueryScenario{
						routingMap:  routingMap,
						matcher:     matcher,
						useFastPath: false,
					}

					b.ResetTimer()

					for i := 0; i < b.N; i++ {
						srcPort := uint16(20000 + (i % numQueries))
						scenario.processQuery(srcPort, "8.8.8.8")
					}

					b.ReportMetric(float64(routingMap.Size()), "entries")
				})

				b.Run("NewPath", func(b *testing.B) {
					routingMap := newMockRoutingTuplesMap()
					scenario := &dnsQueryScenario{
						routingMap:  routingMap,
						matcher:     matcher,
						useFastPath: true,
					}

					b.ResetTimer()

					for i := 0; i < b.N; i++ {
						srcPort := uint16(20000 + (i % numQueries))
						scenario.processQuery(srcPort, "8.8.8.8")
					}

					b.ReportMetric(float64(routingMap.Size()), "entries")
				})
			})
		}
	}
}

// =============================================================================
// Section 4: Memory Allocation Comparison
// =============================================================================

// BenchmarkMemory_MapGrowth compares memory usage as map grows
func BenchmarkMemory_MapGrowth(b *testing.B) {
	b.Run("OldPath_WithDNS", func(b *testing.B) {
		routingMap := newMockRoutingTuplesMap()

		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			srcPort := 20000 + (i % 50000)
			key := fmt.Sprintf("192.168.1.100:%d:8.8.8.8:53:17", srcPort)
			routingMap.Update(key, &mockRoutingResult{Outbound: 1})
		}
	})

	b.Run("NewPath_SkipDNS", func(b *testing.B) {
		routingMap := newMockRoutingTuplesMap()

		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			// Only store non-DNS entries
			if i%10 != 0 { // 90% are DNS, skip those
				continue
			}
			key := fmt.Sprintf("192.168.1.100:%d:93.184.216.34:443:6", 10000+i%1000)
			routingMap.Update(key, &mockRoutingResult{Outbound: 1})
		}
	})
}

// =============================================================================
// Section 5: Concurrent DNS Query Simulation
// =============================================================================

// BenchmarkConcurrent_DnsQueries simulates concurrent DNS traffic
func BenchmarkConcurrent_DnsQueries(b *testing.B) {
	b.Run("OldPath", func(b *testing.B) {
		routingMap := newMockRoutingTuplesMap()
		_ = buildMockRoutingMatcher(100)

		b.ResetTimer()
		b.ReportAllocs()

		b.RunParallel(func(pb *testing.PB) {
			id := 0
			for pb.Next() {
				srcPort := uint16(20000 + (id % 50000))
				key := fmt.Sprintf("192.168.1.100:%d:8.8.8.8:53:17", srcPort)

				// Old path: always update
				routingMap.Update(key, &mockRoutingResult{Outbound: 1})

				// Simulated lookup miss
				routingMap.Lookup(key)

				id++
			}
		})
	})

	b.Run("NewPath", func(b *testing.B) {
		routingMap := newMockRoutingTuplesMap()
		_ = buildMockRoutingMatcher(100)

		b.ResetTimer()
		b.ReportAllocs()

		b.RunParallel(func(pb *testing.PB) {
			id := 0
			for pb.Next() {
				srcPort := uint16(20000 + (id % 50000))
				key := fmt.Sprintf("192.168.1.100:%d:8.8.8.8:53:17", srcPort)

				// New path: skip DNS
				_ = key // Check is DNS (dport == 53)

				// Simulated lookup
				routingMap.Lookup(key)

				id++
			}
		})
	})
}

// =============================================================================
// Section 6: Port Check Overhead
// =============================================================================

// BenchmarkPortCheck measures the overhead of checking if dport == 53
func BenchmarkPortCheck(b *testing.B) {
	packets := make([]uint16, 10000)
	for i := range packets {
		packets[i] = uint16(i)
	}

	b.Run("BranchCheck", func(b *testing.B) {
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			dport := packets[i%len(packets)]
			if dport == 53 {
				// Skip
			}
		}
	})

	b.Run("NoCheck", func(b *testing.B) {
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			_ = packets[i%len(packets)]
		}
	})
}

// =============================================================================
// Section 7: Key Generation Overhead
// =============================================================================

// BenchmarkKeyGeneration compares key generation overhead
func BenchmarkKeyGeneration(b *testing.B) {
	b.Run("WithStringFormat", func(b *testing.B) {
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			srcPort := uint16(20000 + i%50000)
			_ = fmt.Sprintf("192.168.1.100:%d:8.8.8.8:53:17", srcPort)
		}
	})

	b.Run("WithStruct", func(b *testing.B) {
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			srcPort := uint16(20000 + i%50000)
			key := [40]byte{}
			copy(key[0:], []byte("192.168.1.100"))
			binary.BigEndian.PutUint16(key[15:17], srcPort)
			copy(key[17:], []byte("8.8.8.8"))
			binary.BigEndian.PutUint16(key[24:26], 53)
			key[35] = 17 // UDP
			_ = key
		}
	})
}

// =============================================================================
// Section 8: DNS Fast Path vs Old Path Benchmarks
// =============================================================================

// BenchmarkHandlePkt_DNSFastPath compares the performance of the DNS fast path
// optimization versus the old path that always performs UdpEndpoint lookup
func BenchmarkHandlePkt_DNSFastPath(b *testing.B) {
	// Create a valid DNS query packet
	req := new(dnsmessage.Msg)
	req.SetQuestion("example.com.", dnsmessage.TypeA)
	req.RecursionDesired = true
	dnsQuery, _ := req.Pack()

	b.Run("FastPath_Port53Only", func(b *testing.B) {
		// Simulate the new fast path: just check port
		dstPort := uint16(53)
		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			// This is what DNS fast path does first
			_ = dstPort == 53
		}
	})

	b.Run("OldPath_WithDNSValidation", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			// This simulates what the old path did: always validate DNS
			var dnsmsg dnsmessage.Msg
			_ = dnsmsg.Unpack(dnsQuery)
		}
	})

	b.Run("FastPath_PortPlusValidation", func(b *testing.B) {
		dstPort := uint16(53)
		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			// New fast path: check port first, then validate
			if dstPort == 53 {
				var dnsmsg dnsmessage.Msg
				_ = dnsmsg.Unpack(dnsQuery)
			}
		}
	})
}

// BenchmarkHandlePkt_MixedTraffic simulates mixed DNS and non-DNS traffic
func BenchmarkHandlePkt_MixedTraffic(b *testing.B) {
	// Create test packets
	dnsReq := new(dnsmessage.Msg)
	dnsReq.SetQuestion("example.com.", dnsmessage.TypeA)
	dnsQuery, _ := dnsReq.Pack()
	nonDnsPacket := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	scenarios := []struct {
		name     string
		dnsRatio int // Percentage of DNS traffic
	}{
		{"MostlyDNS", 90},
		{"HalfDNS", 50},
		{"MostlyNonDNS", 10},
	}

	for _, scenario := range scenarios {
		b.Run(scenario.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				isDNS := (i % 100) < scenario.dnsRatio
				dstPort := uint16(53)
				packet := dnsQuery

				if !isDNS {
					dstPort = uint16(443)
					packet = nonDnsPacket
				}

				// Simulate the fast path logic
				if dstPort == 53 {
					var dnsmsg dnsmessage.Msg
					_ = dnsmsg.Unpack(packet)
				}
				// For non-DNS, would fall through to normal UDP handling
			}
		})
	}
}

// BenchmarkHandlePkt_PortCheckOverhead measures the overhead of port 53 check
func BenchmarkHandlePkt_PortCheckOverhead(b *testing.B) {
	dstPorts := []uint16{53, 80, 443, 8080, 443, 53, 53, 443}

	b.Run("PortComparison", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			port := dstPorts[i%len(dstPorts)]
			_ = port == 53
		}
	})

	b.Run("NoCheck", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			_ = dstPorts[i%len(dstPorts)]
		}
	})
}

// BenchmarkChooseNatTimeout_DNS measures DNS validation performance
func BenchmarkChooseNatTimeout_DNS(b *testing.B) {
	// Create test DNS packets
	dnsReqA := new(dnsmessage.Msg)
	dnsReqA.SetQuestion("example.com.", dnsmessage.TypeA)
	dnsQueryA, _ := dnsReqA.Pack()

	dnsReqAAAA := new(dnsmessage.Msg)
	dnsReqAAAA.SetQuestion("example.com.", dnsmessage.TypeAAAA)
	dnsQueryAAAA, _ := dnsReqAAAA.Pack()

	dnsReqMX := new(dnsmessage.Msg)
	dnsReqMX.SetQuestion("example.com.", dnsmessage.TypeMX)
	dnsQueryMX, _ := dnsReqMX.Pack()

	b.Run("TypeA", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			ChooseNatTimeout(dnsQueryA, true)
		}
	})

	b.Run("TypeAAAA", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			ChooseNatTimeout(dnsQueryAAAA, true)
		}
	})

	b.Run("TypeMX", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			ChooseNatTimeout(dnsQueryMX, true)
		}
	})

	b.Run("Disabled", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			ChooseNatTimeout(dnsQueryA, false)
		}
	})
}

// BenchmarkHandlePkt_FastPathBenefit quantifies the benefit of DNS fast path
// by comparing operations saved
func BenchmarkHandlePkt_FastPathBenefit(b *testing.B) {
	srcAddrs := make([]netip.AddrPort, 100)
	for i := range srcAddrs {
		srcAddrs[i] = netip.MustParseAddrPort(fmt.Sprintf("192.168.1.%d:%d", i%256, 50000+i%1000))
	}

	b.Run("SyncMapLookup_Simulated", func(b *testing.B) {
		// Simulate the sync.Map.Load() operation that DNS fast path avoids
		// This is a rough approximation using a regular map with mutex
		m := make(map[netip.AddrPort]bool)
		var mu sync.RWMutex

		// Pre-populate some entries
		for _, addr := range srcAddrs[:10] {
			m[addr] = true
		}

		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			addr := srcAddrs[i%len(srcAddrs)]
			mu.RLock()
			_ = m[addr]
			mu.RUnlock()
		}
	})

	b.Run("PortCheck_DNSFastPath", func(b *testing.B) {
		dstPort := uint16(53)
		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			// This is what DNS fast path does instead of map lookup
			_ = dstPort == 53
		}
	})
}
