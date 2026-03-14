/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@daeuniverse.org>
 *
 * UDP Regression Test Suite
 *
 * This suite verifies correctness after potential performance optimizations:
 * 1. QUIC connection establishment
 * 2. Fragmented packet handling
 * 3. Routing cache consistency
 * 4. Protocol-specific behaviors (Hysteria2/TUIC/Juicity)
 * 5. Port heuristics correctness
 */

package control

import (
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// =============================================================================
// QUIC Connection Regression Tests
// =============================================================================

// TestQuicConnection_Establishment verifies QUIC connections can be established
func TestQuicConnection_Establishment(t *testing.T) {
	src := netip.MustParseAddrPort("192.168.1.100:50000")
	dst := netip.MustParseAddrPort("93.184.216.34:443")

	// QUIC Initial packet
	quicInitial := createQuicInitialPacket()
	decision := ClassifyUdpFlow(src, dst, quicInitial)

	require.True(t, decision.IsQuicInitial, "QUIC Initial packet should be detected")
	require.True(t, decision.PreferSymmetricNat(), "QUIC should prefer symmetric NAT")
	require.True(t, decision.ShouldUseOrderedIngress(), "QUIC should use ordered ingress")

	// Verify correct keys are used
	symKey := decision.SymmetricNatEndpointKey()
	require.Equal(t, src, symKey.Src, "Source should match")
	require.Equal(t, dst, symKey.Dst, "Destination should match for symmetric NAT")

	fullConeKey := decision.FullConeNatEndpointKey()
	require.Equal(t, src, fullConeKey.Src, "Source should match")
	require.Equal(t, netip.AddrPort{}, fullConeKey.Dst, "Destination should be empty for full cone")

	// Verify endpoint key for dial (no domain)
	dialKey := decision.EndpointKeyForDial("")
	require.Equal(t, src, dialKey.Src, "Source should match")
	require.Equal(t, dst, dialKey.Dst, "Destination should match for QUIC")

	// Verify endpoint key for dial (with domain)
	dialKeyWithDomain := decision.EndpointKeyForDial("example.com")
	require.Equal(t, src, dialKeyWithDomain.Src, "Source should match")
	require.Equal(t, dst, dialKeyWithDomain.Dst, "Destination should match for domain dial")
}

// TestQuicConnection_FollowUpPackets verifies follow-up QUIC packets
func TestQuicConnection_FollowUpPackets(t *testing.T) {
	src := netip.MustParseAddrPort("192.168.1.100:50000")
	dst := netip.MustParseAddrPort("93.184.216.34:443")

	// First packet: QUIC Initial
	quicInitial := createQuicInitialPacket()
	decision1 := ClassifyUdpFlow(src, dst, quicInitial)
	decision1 = decision1.EnsureSnifferSession()

	require.True(t, decision1.HasSnifferSession, "Sniffer session should be created")

	// Follow-up packet (not QUIC Initial, but same flow)
	followUpData := make([]byte, 1200)
	decision2 := ClassifyUdpFlow(src, dst, followUpData)

	require.False(t, decision2.IsQuicInitial, "Follow-up should not be QUIC Initial")
	require.True(t, decision2.HasSnifferSession, "Sniffer session should persist")
	require.True(t, decision2.ShouldUseOrderedIngress(), "Follow-up should use ordered ingress")
	require.True(t, decision2.PreferSymmetricNat(), "Follow-up should prefer symmetric NAT")
}

// TestQuicConnection_Port8443 verifies QUIC on port 8443
func TestQuicConnection_Port8443(t *testing.T) {
	src := netip.MustParseAddrPort("192.168.1.100:50000")
	dst := netip.MustParseAddrPort("93.184.216.34:8443")

	quicInitial := createQuicInitialPacket()
	decision := ClassifyUdpFlow(src, dst, quicInitial)

	require.True(t, decision.IsQuicInitial, "QUIC Initial should be detected on port 8443")
	require.True(t, decision.IsLikelyQuicData, "Port 8443 should trigger likely QUIC heuristic")
	require.True(t, decision.PreferSymmetricNat(), "Port 8443 QUIC should prefer symmetric NAT")
	require.True(t, decision.ShouldUseOrderedIngress(), "Port 8443 QUIC should use ordered ingress")
}

// =============================================================================
// Port Heuristics Regression Tests
// =============================================================================

// TestPortHeuristics_Port443NonQuic verifies port 443 non-QUIC traffic
func TestPortHeuristics_Port443NonQuic(t *testing.T) {
	src := netip.MustParseAddrPort("192.168.1.100:50003")
	dst := netip.MustParseAddrPort("93.184.216.34:443")

	// Non-QUIC data on port 443 (e.g., DTLS, Hysteria2)
	nonQuicData := make([]byte, 1200)
	decision := ClassifyUdpFlow(src, dst, nonQuicData)

	require.False(t, decision.IsQuicInitial, "Non-QUIC data should not be detected as QUIC Initial")
	require.True(t, decision.IsLikelyQuicData, "Port 443 should trigger likely QUIC heuristic")
	require.True(t, decision.PreferSymmetricNat(), "Port 443 should prefer symmetric NAT")
	require.False(t, decision.ShouldUseOrderedIngress(), "Port 443 should NOT use ordered ingress without sniffer session")
}

// TestPortHeuristics_NonQuicPorts verifies non-QUIC ports
func TestPortHeuristics_NonQuicPorts(t *testing.T) {
	src := netip.MustParseAddrPort("192.168.1.100:50000")

	testPorts := []uint16{53, 12345, 80, 443, 8443}
	expected := []bool{false, false, false, true, true} // IsLikelyQuicData

	for i, port := range testPorts {
		dst := netip.AddrPortFrom(netip.AddrFrom4([4]byte{93, 184, 216, 34}), port)
		decision := ClassifyUdpFlow(src, dst, make([]byte, 512))

		require.Equal(t, expected[i], decision.IsLikelyQuicData,
			"Port %d IsLikelyQuicData mismatch", port)
	}
}

// TestPortHeuristics_Dns verifies DNS traffic is handled correctly
func TestPortHeuristics_Dns(t *testing.T) {
	src := netip.MustParseAddrPort("192.168.1.100:50000")
	dst := netip.MustParseAddrPort("8.8.8.8:53")

	dnsPacket := createDnsPacket()
	decision := ClassifyUdpFlow(src, dst, dnsPacket)

	require.False(t, decision.IsQuicInitial, "DNS should not be QUIC Initial")
	require.False(t, decision.IsLikelyQuicData, "DNS port should not trigger QUIC heuristic")
	require.False(t, decision.PreferSymmetricNat(), "DNS should not prefer symmetric NAT")
	require.False(t, decision.ShouldUseOrderedIngress(), "DNS should not use ordered ingress")
}

// =============================================================================
// Routing Cache Consistency Tests
// =============================================================================

// TestRoutingCache_Consistency verifies cache key consistency
func TestRoutingCache_Consistency(t *testing.T) {
	src := netip.MustParseAddrPort("192.168.1.100:50000")

	// Test 1: Full Cone NAT endpoint caching
	t.Run("FullConeConsistency", func(t *testing.T) {
		dst1 := netip.MustParseAddrPort("8.8.8.8:53")
		dst2 := netip.MustParseAddrPort("1.1.1.1:53")

		decision := ClassifyUdpFlow(src, dst1, createDnsPacket())
		cacheKey := decision.CachedRoutingEndpointKey()

		// Should be Full Cone key (Src only)
		require.Equal(t, src, cacheKey.Src)
		require.Equal(t, netip.AddrPort{}, cacheKey.Dst)

		// Create endpoint directly for testing (without starting goroutines)
		ue := &UdpEndpoint{}

		// Cache routing result for dst1
		rr1 := &bpfRoutingResult{Mark: 100, Outbound: 5}
		ue.UpdateCachedRoutingResult(dst1, 17, rr1)

		// Verify cache hit for dst1
		cached, hit := ue.GetCachedRoutingResult(dst1, 17)
		require.True(t, hit, "Should hit cache for dst1")
		require.Equal(t, rr1.Mark, cached.Mark)

		// Verify cache miss for dst2 (different destination)
		cached, hit = ue.GetCachedRoutingResult(dst2, 17)
		require.False(t, hit, "Should miss cache for dst2")

		// Update cache for dst2
		rr2 := &bpfRoutingResult{Mark: 200, Outbound: 6}
		ue.UpdateCachedRoutingResult(dst2, 17, rr2)

		// Now both should hit
		cached, hit = ue.GetCachedRoutingResult(dst2, 17)
		require.True(t, hit, "Should hit cache for dst2 after update")
		require.Equal(t, rr2.Mark, cached.Mark)
	})

	// Test 2: Symmetric NAT endpoint caching
	t.Run("SymmetricConsistency", func(t *testing.T) {
		dst1 := netip.MustParseAddrPort("93.184.216.34:443")
		dst2 := netip.MustParseAddrPort("104.16.132.229:443")

		// QUIC traffic to dst1
		decision1 := ClassifyUdpFlow(src, dst1, createQuicInitialPacket())
		cacheKey1 := decision1.CachedRoutingEndpointKey()

		// Should be Symmetric key (Src + Dst)
		require.Equal(t, src, cacheKey1.Src)
		require.Equal(t, dst1, cacheKey1.Dst)

		// Create endpoint directly for testing
		ue1 := &UdpEndpoint{}

		rr1 := &bpfRoutingResult{Mark: 300, Outbound: 7}
		ue1.UpdateCachedRoutingResult(dst1, 17, rr1)

		// QUIC traffic to dst2
		decision2 := ClassifyUdpFlow(src, dst2, createQuicInitialPacket())
		cacheKey2 := decision2.CachedRoutingEndpointKey()

		// Should have different keys
		require.NotEqual(t, cacheKey1, cacheKey2, "Different QUIC destinations should have different keys")

		// Create another endpoint for dst2
		ue2 := &UdpEndpoint{}

		rr2 := &bpfRoutingResult{Mark: 400, Outbound: 8}
		ue2.UpdateCachedRoutingResult(dst2, 17, rr2)

		// Verify each endpoint has its own cache
		cached1, hit1 := ue1.GetCachedRoutingResult(dst1, 17)
		require.True(t, hit1)
		require.Equal(t, rr1.Mark, cached1.Mark)

		cached2, hit2 := ue2.GetCachedRoutingResult(dst2, 17)
		require.True(t, hit2)
		require.Equal(t, rr2.Mark, cached2.Mark)

		// Cross-check: dst1 should not be in ue2's cache
		_, hitCross := ue2.GetCachedRoutingResult(dst1, 17)
		require.False(t, hitCross, "dst1 should not be in ue2's cache")
	})
}

// TestRoutingCache_Expiration verifies cache TTL expiration
func TestRoutingCache_Expiration(t *testing.T) {
	oldTTL := UdpRoutingResultCacheTtl
	UdpRoutingResultCacheTtl = 50 * time.Millisecond
	defer func() { UdpRoutingResultCacheTtl = oldTTL }()

	ue := &UdpEndpoint{}
	dst := netip.MustParseAddrPort("1.1.1.1:443")

	rr := &bpfRoutingResult{Mark: 123, Outbound: 5}
	ue.UpdateCachedRoutingResult(dst, 17, rr)

	// Should hit immediately
	cached, hit := ue.GetCachedRoutingResult(dst, 17)
	require.True(t, hit)
	require.Equal(t, rr.Mark, cached.Mark)

	// Wait for expiration
	time.Sleep(2 * UdpRoutingResultCacheTtl)

	// Should miss after expiration
	cached, hit = ue.GetCachedRoutingResult(dst, 17)
	require.False(t, hit, "Cache should expire after TTL")
	require.Nil(t, cached)
}

// =============================================================================
// Sniffer Session Tests
// =============================================================================

// TestSnifferSession_Ensure verifies sniffer session creation
func TestSnifferSession_Ensure(t *testing.T) {
	// Use unique source port to avoid conflicts with other tests
	src := netip.MustParseAddrPort("192.168.1.100:54321")
	dst := netip.MustParseAddrPort("93.184.216.34:443")

	// Initial decision without sniffer session
	decision1 := ClassifyUdpFlow(src, dst, createQuicInitialPacket())
	if decision1.HasSnifferSession {
		// Clean up any existing session from previous tests
		key := decision1.PacketSnifferKey()
		if sniffer := DefaultPacketSnifferSessionMgr.Get(key); sniffer != nil {
			DefaultPacketSnifferSessionMgr.Remove(key, sniffer)
		}
		decision1 = ClassifyUdpFlow(src, dst, createQuicInitialPacket())
	}
	require.False(t, decision1.HasSnifferSession, "Initially no sniffer session")

	// Ensure sniffer session
	decision2 := decision1.EnsureSnifferSession()
	require.True(t, decision2.HasSnifferSession, "Should have sniffer session after Ensure")
	require.True(t, decision2.IsQuicInitial, "Should still be QUIC Initial")

	// Non-QUIC should not create sniffer session
	// Use a non-443 port to avoid port heuristic
	dstNonQuic := netip.MustParseAddrPort("93.184.216.34:12345")
	decision3 := ClassifyUdpFlow(src, dstNonQuic, make([]byte, 512))
	decision4 := decision3.EnsureSnifferSession()
	require.False(t, decision4.HasSnifferSession, "Non-QUIC should not create sniffer session")
}

// TestSnifferSession_Persistence verifies sniffer session persists across packets
func TestSnifferSession_Persistence(t *testing.T) {
	src := netip.MustParseAddrPort("192.168.1.100:50000")
	dst := netip.MustParseAddrPort("93.184.216.34:443")

	// Create sniffer session for QUIC Initial
	decision1 := ClassifyUdpFlow(src, dst, createQuicInitialPacket())
	decision1 = decision1.EnsureSnifferSession()

	key := decision1.PacketSnifferKey()
	sniffer := DefaultPacketSnifferSessionMgr.Get(key)
	require.NotNil(t, sniffer, "Sniffer should exist")

	// Follow-up packet should still have sniffer session
	decision2 := ClassifyUdpFlow(src, dst, make([]byte, 1200))
	require.True(t, decision2.HasSnifferSession, "Sniffer session should persist")

	// Clean up
	DefaultPacketSnifferSessionMgr.Remove(key, sniffer)
}

// =============================================================================
// Endpoint Key Selection Tests
// =============================================================================

// TestEndpointKeySelection_DomainDial verifies endpoint key for domain dial
func TestEndpointKeySelection_DomainDial(t *testing.T) {
	src := netip.MustParseAddrPort("192.168.1.100:50000")
	dst := netip.MustParseAddrPort("93.184.216.34:443")

	testCases := []struct {
		name            string
		domain          string
		isQuic          bool
		expectSymmetric bool
	}{
		{name: "QUIC_WithDomain", domain: "example.com", isQuic: true, expectSymmetric: true},
		{name: "QUIC_WithoutDomain", domain: "", isQuic: true, expectSymmetric: true},
		{name: "NonQUIC_WithDomain", domain: "example.com", isQuic: false, expectSymmetric: true},
		// Note: Non-QUIC traffic on port 443 still uses symmetric NAT due to port heuristic
		// This is the current design after the IsLikelyQuicData restoration
		{name: "NonQUIC_WithoutDomain_Port443", domain: "", isQuic: false, expectSymmetric: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var data []byte
			if tc.isQuic {
				data = createQuicInitialPacket()
			} else {
				data = make([]byte, 512)
			}

			decision := ClassifyUdpFlow(src, dst, data)
			key := decision.EndpointKeyForDial(tc.domain)

			if tc.expectSymmetric {
				require.Equal(t, dst, key.Dst, "Should use symmetric NAT key")
			} else {
				require.Equal(t, netip.AddrPort{}, key.Dst, "Should use full cone NAT key")
			}
		})
	}

	// Add a test for non-443 port to verify full cone behavior
	t.Run("NonQUIC_Non443Port", func(t *testing.T) {
		dstNon443 := netip.MustParseAddrPort("93.184.216.34:12345")
		decision := ClassifyUdpFlow(src, dstNon443, make([]byte, 512))
		key := decision.EndpointKeyForDial("")

		require.Equal(t, netip.AddrPort{}, key.Dst, "Non-443 port should use full cone NAT key")
	})
}

// TestEndpointKeySelection_PortHeuristics verifies port-based key selection
func TestEndpointKeySelection_PortHeuristics(t *testing.T) {
	src := netip.MustParseAddrPort("192.168.1.100:50000")

	testPorts := []struct {
		port           uint16
		expectSymmetric bool
		reason          string
	}{
		{port: 443, expectSymmetric: true, reason: "QUIC port heuristic"},
		{port: 8443, expectSymmetric: true, reason: "QUIC port heuristic"},
		{port: 53, expectSymmetric: false, reason: "DNS port"},
		{port: 12345, expectSymmetric: false, reason: "Generic port"},
	}

	for _, tp := range testPorts {
		t.Run(tp.reason, func(t *testing.T) {
			dst := netip.AddrPortFrom(netip.AddrFrom4([4]byte{93, 184, 216, 34}), tp.port)
			decision := ClassifyUdpFlow(src, dst, make([]byte, 512))

			// Port heuristic should affect PreferSymmetricNat
			isSymmetric := decision.PreferSymmetricNat()
			require.Equal(t, tp.expectSymmetric, isSymmetric,
				"Port %d symmetric expectation mismatch: %s", tp.port, tp.reason)
		})
	}
}

// =============================================================================
// Ordered Ingress Decision Tests
// =============================================================================

// TestOrderedIngress_DecisionLogic verifies ordered ingress decision logic
func TestOrderedIngress_DecisionLogic(t *testing.T) {
	// Use different source ports for each test case to avoid session leakage

	testCases := []struct {
		name            string
		dstPort         uint16
		data            []byte
		hasSniffer      bool
		expectOrdered   bool
	}{
		{
			name:          "QUIC_Initial",
			dstPort:       443,
			data:          createQuicInitialPacket(),
			hasSniffer:    false,
			expectOrdered: true,
		},
		{
			name:          "QUIC_WithSniffer",
			dstPort:       443,
			data:          createQuicInitialPacket(), // Must be QUIC Initial to create sniffer
			hasSniffer:    true,
			expectOrdered: true,
		},
		{
			name:          "Port443_NonQuic",
			dstPort:       443,
			data:          make([]byte, 1200),
			hasSniffer:    false,
			expectOrdered: false, // Optimized: port heuristic no longer forces ordered ingress
		},
		{
			name:          "Port8443_NonQuic",
			dstPort:       8443,
			data:          make([]byte, 1200),
			hasSniffer:    false,
			expectOrdered: false, // Optimized: port heuristic no longer forces ordered ingress
		},
		{
			name:          "DNS",
			dstPort:       53,
			data:          createDnsPacket(),
			hasSniffer:    false,
			expectOrdered: false,
		},
		{
			name:          "Generic_UDP",
			dstPort:       12345,
			data:          make([]byte, 512),
			hasSniffer:    false,
			expectOrdered: false,
		},
	}

	for i, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Use unique source port to avoid session leakage between tests
			src := netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 168, 1, 100}), uint16(50000+uint16(i)))
			dst := netip.AddrPortFrom(netip.AddrFrom4([4]byte{93, 184, 216, 34}), tc.dstPort)
			decision := ClassifyUdpFlow(src, dst, tc.data)

			if tc.hasSniffer {
				decision = decision.EnsureSnifferSession()
			}

			isOrdered := decision.ShouldUseOrderedIngress()
			require.Equal(t, tc.expectOrdered, isOrdered,
				"Ordered ingress decision mismatch for %s", tc.name)
		})
	}
}

// =============================================================================
// Concurrent Safety Tests
// =============================================================================

// TestConcurrent_UdpFlowClassification verifies thread safety of flow classification
func TestConcurrent_UdpFlowClassification(t *testing.T) {
	src := netip.MustParseAddrPort("192.168.1.100:50000")
	dst := netip.MustParseAddrPort("93.184.216.34:443")
	quicData := createQuicInitialPacket()

	const goroutines = 100
	const iterations = 1000

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				decision := ClassifyUdpFlow(src, dst, quicData)
				_ = decision.ShouldUseOrderedIngress()
				_ = decision.PreferSymmetricNat()
				_ = decision.EndpointKeyForDial("")
			}
		}()
	}

	wg.Wait()
}

// TestConcurrent_EndpointPoolOperations verifies thread safety of endpoint pool
func TestConcurrent_EndpointPoolOperations(t *testing.T) {
	// Note: This test creates mock endpoints without starting goroutines
	// Real endpoint pool operations with Handler would require more complex setup
	const goroutines = 50
	const iterations = 500

	var wg sync.WaitGroup
	wg.Add(goroutines)

	// Test key creation and classification (lightweight operations without full endpoints)
	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				src := netip.MustParseAddrPort("192.168.1.100:50000")
				dst := netip.AddrPortFrom(
					netip.AddrFrom4([4]byte{93, 184, 216, byte((idx*iterations + j) % 256)}),
					443,
				)
				decision := ClassifyUdpFlow(src, dst, createQuicInitialPacket())
				_ = decision.CachedRoutingEndpointKey()
				_ = decision.SymmetricNatEndpointKey()
			}
		}(i)
	}

	wg.Wait()
}

// TestConcurrent_RoutingCacheOperations verifies thread safety of routing cache
func TestConcurrent_RoutingCacheOperations(t *testing.T) {
	// Create endpoint directly without starting goroutines
	ue := &UdpEndpoint{}

	const goroutines = 50
	const iterations = 1000

	var wg sync.WaitGroup
	wg.Add(goroutines * 2) // Readers + writers

	// Readers
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				testDst := netip.AddrPortFrom(
					netip.AddrFrom4([4]byte{byte(j), byte(j >> 8), 216, 34}),
					443,
				)
				_, _ = ue.GetCachedRoutingResult(testDst, 17)
			}
		}()
	}

	// Writers
	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				testDst := netip.AddrPortFrom(
					netip.AddrFrom4([4]byte{byte(idx), byte(j), 216, 34}),
					443,
				)
				rr := &bpfRoutingResult{
					Mark:     uint32(idx*iterations + j),
					Outbound: uint8(idx % 10),
				}
				ue.UpdateCachedRoutingResult(testDst, 17, rr)
			}
		}(i)
	}

	wg.Wait()
}
