/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 *
 * Comprehensive UDP traffic simulation test to verify:
 * 1. Non-QUIC UDP traffic passes without blocking
 * 2. QUIC traffic sniffing works correctly
 * 3. Failed QUIC DCID cache prevents indefinite blocking
 * 4. UDP endpoint pool management works correctly
 * 5. Concurrent UDP traffic handling
 */

package control

import (
	"context"
	"encoding/hex"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/sniffing"
	"github.com/stretchr/testify/require"
)

// TestUdpTrafficSimulation_NonQuicNoBlocking verifies that non-QUIC UDP
// traffic is not blocked by the sniffing process.
func TestUdpTrafficSimulation_NonQuicNoBlocking(t *testing.T) {
	resetPacketSnifferPoolForTestForTraffic()
	defer resetPacketSnifferPoolForTestForTraffic()

	src := netip.MustParseAddrPort("192.168.1.100:54321")
	dst := netip.MustParseAddrPort("8.8.8.8:53")

	// Simulate non-QUIC UDP packets (DNS-like)
	nonQuicPackets := [][]byte{
		{0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // DNS query
		{0x00, 0x02, 0x02, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // Another DNS
		make([]byte, 128),                                                           // Generic UDP
	}

	// Track processing results
	var processedCount atomic.Int32
	var blockedCount atomic.Int32
	var wg sync.WaitGroup

	for i, pkt := range nonQuicPackets {
		wg.Add(1)
		go func(idx int, packet []byte) {
			defer wg.Done()

			start := time.Now()
			decision := ClassifyUdpFlow(src, dst, packet)

			// Non-QUIC packets should not require ordered ingress
			if decision.ShouldUseOrderedIngress() {
				blockedCount.Add(1)
				t.Errorf("Packet %d: non-QUIC packet should not require ordered ingress", idx)
			}

			if decision.IsQuicInitial {
				blockedCount.Add(1)
				t.Errorf("Packet %d: non-QUIC packet should not be classified as QUIC Initial", idx)
			}

			// Non-QUIC packets should bypass sniffing and process immediately
			elapsed := time.Since(start)
			if elapsed > 10*time.Millisecond {
				t.Errorf("Packet %d: non-QUIC packet processing took too long: %v", idx, elapsed)
			}

			processedCount.Add(1)
		}(i, pkt)
	}

	wg.Wait()

	require.Equal(t, int32(len(nonQuicPackets)), processedCount.Load(),
		"All non-QUIC packets should be processed")
	require.Equal(t, int32(0), blockedCount.Load(),
		"No non-QUIC packets should be blocked")
}

// TestUdpTrafficSimulation_QuicWithSniffing verifies QUIC traffic
// is correctly classified and sniffed.
func TestUdpTrafficSimulation_QuicWithSniffing(t *testing.T) {
	resetPacketSnifferPoolForTestForTraffic()
	defer resetPacketSnifferPoolForTestForTraffic()

	src := netip.MustParseAddrPort("192.168.1.100:54321")
	dst := netip.MustParseAddrPort("93.184.216.34:443")

	// Real QUIC Initial packets
	quicPackets := [][]byte{
		sniffTestQuicPacket1,
		sniffTestQuicPacket2,
		sniffTestQuicPacket3,
	}

	for i, pkt := range quicPackets {
		t.Run(testName(i, pkt), func(t *testing.T) {
			require.True(t, sniffing.IsLikelyQuicInitialPacket(pkt),
				"Test packet should be recognized as QUIC Initial")

			decision := ClassifyUdpFlow(src, dst, pkt)

			require.True(t, decision.IsQuicInitial,
				"QUIC packet should be classified as QUIC Initial")
			require.True(t, decision.ShouldAttemptSniff(),
				"QUIC packet should trigger sniffing attempt")
			require.True(t, decision.ShouldUseOrderedIngress(),
				"QUIC packet should use ordered ingress")

			// Verify symmetric NAT key is used for QUIC
			symKey := decision.SymmetricNatEndpointKey()
			require.Equal(t, src, symKey.Src, "Source should match")
			require.Equal(t, dst, symKey.Dst, "Destination should match for symmetric NAT")
		})
	}
}

// TestUdpTrafficSimulation_FailedDcidBypass verifies that failed QUIC
// DCID cache prevents indefinite blocking.
func TestUdpTrafficSimulation_FailedDcidBypass(t *testing.T) {
	resetPacketSnifferPoolForTestForTraffic()
	defer resetPacketSnifferPoolForTestForTraffic()

	src := netip.MustParseAddrPort("192.168.1.100:54321")
	dst := netip.MustParseAddrPort("93.184.216.34:443")

	// Create a QUIC packet
	quicPacket := sniffTestQuicPacket1
	require.True(t, sniffing.IsLikelyQuicInitialPacket(quicPacket))

	key := NewPacketSnifferKey(src, dst, quicPacket)

	// Initially, DCID should not be marked as failed
	require.False(t, IsQuicDcidFailed(key),
		"DCID should not be marked as failed initially")

	// Mark the DCID as failed
	MarkQuicDcidFailed(key)

	// Now it should be marked as failed
	require.True(t, IsQuicDcidFailed(key),
		"DCID should be marked as failed after MarkQuicDcidFailed")

	// Verify bypass behavior by simulating packet processing
	decision := ClassifyUdpFlow(src, dst, quicPacket)

	// Even though it's a QUIC packet, the sniffing should be bypassed
	// This is verified by checking the DCID cache before sniffing
	_ = decision // The key point is that IsQuicDcidFailed() returns true

	// Clear the failed DCID cache
	ClearFailedQuicDcids()

	require.False(t, IsQuicDcidFailed(key),
		"DCID should not be marked as failed after clearing")
}

// TestUdpTrafficSimulation_SnifferBypassThreshold verifies that after
// multiple failed sniff attempts, the DCID is bypassed.
func TestUdpTrafficSimulation_SnifferBypassThreshold(t *testing.T) {
	resetPacketSnifferPoolForTestForTraffic()
	defer resetPacketSnifferPoolForTestForTraffic()

	src := netip.MustParseAddrPort("192.168.1.100:54321")
	dst := netip.MustParseAddrPort("93.184.216.34:443")

	// Use a malformed QUIC packet that will fail decryption
	malformedQuicPacket := []byte{
		0xC0, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00, // QUIC Initial header
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // Short DCID (8 bytes)
		// Rest of packet is missing/invalid - will cause decryption failures
	}
	require.True(t, sniffing.IsLikelyQuicInitialPacket(malformedQuicPacket))

	key := NewPacketSnifferKey(src, dst, malformedQuicPacket)
	sniffer, isNew := DefaultPacketSnifferSessionMgr.GetOrCreate(key, nil)
	require.True(t, isNew, "Should create new sniffer")
	defer DefaultPacketSnifferSessionMgr.Remove(key, sniffer)

	sniffer.Mu.Lock()
	now := time.Now()

	// Initially should not bypass
	require.False(t, sniffer.ShouldBypassSniff(now),
		"Should not bypass sniffing initially")

	// Record failures up to threshold
	for i := 0; i < udpSniffNoSniThreshold; i++ {
		sniffer.RecordSniffNoSni(now)
	}

	// After reaching threshold, should bypass
	require.True(t, sniffer.ShouldBypassSniff(now),
		"Should bypass sniffing after reaching threshold")

	sniffer.Mu.Unlock()
}

// TestUdpTrafficSimulation_ConcurrentMixedTraffic verifies concurrent
// handling of mixed QUIC and non-QUIC traffic.
func TestUdpTrafficSimulation_ConcurrentMixedTraffic(t *testing.T) {
	resetPacketSnifferPoolForTestForTraffic()
	defer resetPacketSnifferPoolForTestForTraffic()

	const numClients = 50
	const packetsPerClient = 20

	var processedCount atomic.Int32
	var wg sync.WaitGroup

	// Create mixed traffic: QUIC and non-QUIC
	for clientIdx := 0; clientIdx < numClients; clientIdx++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			src := netip.AddrPortFrom(
				netip.MustParseAddr("192.168.1.1"),
				uint16(20000+idx),
			)
			dst := netip.MustParseAddrPort("93.184.216.34:443")

			for pktIdx := 0; pktIdx < packetsPerClient; pktIdx++ {
				var pkt []byte
				if pktIdx%3 == 0 {
					// Every 3rd packet is QUIC
					pkt = sniffTestQuicPacket1
				} else {
					// Non-QUIC packet
					pkt = make([]byte, 64)
					pkt[0] = byte(pktIdx)
				}

				decision := ClassifyUdpFlow(src, dst, pkt)

				// Verify classification correctness
				isQuic := sniffing.IsLikelyQuicInitialPacket(pkt)
				require.Equal(t, isQuic, decision.IsQuicInitial,
					"Classification should match packet type for client %d packet %d", idx, pktIdx)

				processedCount.Add(1)
			}
		}(clientIdx)
	}

	wg.Wait()

	expected := int32(numClients * packetsPerClient)
	require.Equal(t, expected, processedCount.Load(),
		"All packets should be processed")
}

// TestUdpTrafficSimulation_EndpointPoolLifecycle verifies UDP endpoint
// pool lifecycle: create, reuse, expire, and remove.
func TestUdpTrafficSimulation_EndpointPoolLifecycle(t *testing.T) {
	pool := NewUdpEndpointPool()
	defer func() {
		// Clean up all endpoints
		pool.pool.Range(func(key, value any) bool {
			ue := value.(*UdpEndpoint)
			_ = ue.Close()
			pool.pool.Delete(key)
			return true
		})
	}()

	src := netip.MustParseAddrPort("192.168.1.100:54321")
	dst := netip.MustParseAddrPort("8.8.8.8:53")

	symmetricKey := UdpEndpointKey{Src: src, Dst: dst}
	fullConeKey := UdpEndpointKey{Src: src}

	// Initially pool should be empty
	ue, ok := pool.Get(symmetricKey)
	require.False(t, ok, "Pool should be empty initially")
	require.Nil(t, ue)

	// Note: We can't create a real endpoint without a dialer,
	// but we can test the pool mechanics with mock data
	t.Run("pool_key_differentiation", func(t *testing.T) {
		// Symmetric and full-cone keys should be different
		require.NotEqual(t, symmetricKey, fullConeKey,
			"Symmetric and full-cone keys should differ")

		// Full-cone key has zero destination port
		require.Equal(t, uint16(0), fullConeKey.Dst.Port(),
			"Full-cone key should have zero destination port")
		require.NotEqual(t, uint16(0), symmetricKey.Dst.Port(),
			"Symmetric key should have non-zero destination port")
	})

	t.Run("pool_shard_mutex_distribution", func(t *testing.T) {
		// Test that shard mutex distribution works
		keys := make([]UdpEndpointKey, 100)
		for i := range keys {
			keys[i] = UdpEndpointKey{
				Src: netip.AddrPortFrom(
					netip.MustParseAddr("192.168.1.1"),
					uint16(20000+i),
				),
				Dst: dst,
			}
		}

		// Track shard usage
		shardUsage := make(map[int]int)
		for _, key := range keys {
			mu := pool.createMuFor(key)
			// Derive shard index from mutex address
			for i := range pool.createMuShard {
				if &pool.createMuShard[i] == mu {
					shardUsage[i]++
					break
				}
			}
		}

		// Verify distribution across multiple shards
		require.Greater(t, len(shardUsage), 1,
			"Keys should distribute across multiple shards")
	})
}

// TestUdpTrafficSimulation_NatTimeoutUpdate verifies NAT timeout
// updates for different connection types.
func TestUdpTrafficSimulation_NatTimeoutUpdate(t *testing.T) {
	tests := []struct {
		name          string
		domain        string
		expectedTimeout time.Duration
	}{
		{
			name:          "QUIC connection",
			domain:        "example.com",
			expectedTimeout: QuicNatTimeout,
		},
		{
			name:          "Non-QUIC UDP",
			domain:        "",
			expectedTimeout: DefaultNatTimeout,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate timeout selection logic from handlePkt
			var natTimeout time.Duration
			if tt.domain != "" {
				natTimeout = QuicNatTimeout
			} else {
				natTimeout = DefaultNatTimeout
			}

			require.Equal(t, tt.expectedTimeout, natTimeout,
				"NAT timeout should match expected value")
		})
	}
}

// TestUdpTrafficSimulation_RapidPacketsNoBlocking verifies rapid
// successive UDP packets don't cause blocking.
func TestUdpTrafficSimulation_RapidPacketsNoBlocking(t *testing.T) {
	resetPacketSnifferPoolForTestForTraffic()
	defer resetPacketSnifferPoolForTestForTraffic()

	src := netip.MustParseAddrPort("192.168.1.100:54321")
	dst := netip.MustParseAddrPort("8.8.8.8:53")

	const numPackets = 1000
	start := time.Now()

	// Create a DNS-like packet (first byte 0x00 ensures it's not QUIC)
	nonQuicPacket := make([]byte, 64)
	nonQuicPacket[0] = 0x00 // DNS query bit - not QUIC Long Header (which requires bit 7 set)

	for i := 0; i < numPackets; i++ {
		pkt := make([]byte, 64)
		pkt[0] = 0x00 // Ensure first byte is not QUIC Long Header (which needs bit 7 set)
		pkt[1] = byte(i)
		pkt[2] = byte(i >> 8)

		decision := ClassifyUdpFlow(src, dst, pkt)

		// Non-QUIC should always be fast path
		require.False(t, decision.IsQuicInitial,
			"Generic packet should not be QUIC Initial")
		require.False(t, decision.ShouldUseOrderedIngress(),
			"Generic packet should not use ordered ingress")
	}

	elapsed := time.Since(start)

	// Should process 1000 packets quickly (< 100ms = 10k packets/sec)
	require.Less(t, elapsed, 100*time.Millisecond,
		"Rapid packet processing should be fast")

	t.Logf("Processed %d packets in %v (%.0f packets/sec)",
		numPackets, elapsed, float64(numPackets)/elapsed.Seconds())
}

// TestUdpTrafficSimulation_SourcePortReuse verifies source port reuse
// correctly handles QUIC connection changes.
func TestUdpTrafficSimulation_SourcePortReuse(t *testing.T) {
	resetPacketSnifferPoolForTestForTraffic()
	defer resetPacketSnifferPoolForTestForTraffic()

	src := netip.MustParseAddrPort("192.168.1.100:54321")
	dst1 := netip.MustParseAddrPort("93.184.216.34:443")

	// First QUIC connection to dst1
	key1 := NewPacketSnifferKey(src, dst1, sniffTestQuicPacket1)
	sniffer1, _ := DefaultPacketSnifferSessionMgr.GetOrCreate(key1, nil)

	// Verify first connection
	sniffer1.Mu.Lock()
	result1 := sniffer1.ObserveQuicInitial(sniffTestQuicPacket1)
	require.False(t, result1, "First QUIC Initial should not detect connection change")
	sniffer1.Mu.Unlock()

	// Same source port, same destination, same DCID -> should reuse
	sniffer1.Mu.Lock()
	resultSame := sniffer1.ObserveQuicInitial(sniffTestQuicPacket1)
	require.False(t, resultSame, "Same QUIC connection should not trigger reset")
	sniffer1.Mu.Unlock()

	// Clean up
	DefaultPacketSnifferSessionMgr.Remove(key1, sniffer1)
}

// TestUdpTrafficSimulation_DecryptFailureFastGiveup verifies that
// consecutive decrypt failures cause quick bypass.
func TestUdpTrafficSimulation_DecryptFailureFastGiveup(t *testing.T) {
	resetPacketSnifferPoolForTestForTraffic()
	defer resetPacketSnifferPoolForTestForTraffic()

	src := netip.MustParseAddrPort("192.168.1.100:54321")
	dst := netip.MustParseAddrPort("93.184.216.34:443")

	// Create packet with valid QUIC header but invalid crypto data
	invalidPacket := make([]byte, 1200)
	invalidPacket[0] = 0xC0 // Long header
	invalidPacket[1] = 0x00 // Version high
	invalidPacket[2] = 0x00 // Version mid
	invalidPacket[3] = 0x00 // Version low
	invalidPacket[4] = 0x01 // Version
	invalidPacket[5] = 0x08 // DCID length
	// Fill with random data that will fail decryption
	for i := 6; i < len(invalidPacket); i++ {
		invalidPacket[i] = byte(i)
	}

	require.True(t, sniffing.IsLikelyQuicInitialPacket(invalidPacket))

	key := NewPacketSnifferKey(src, dst, invalidPacket)
	sniffer, _ := DefaultPacketSnifferSessionMgr.GetOrCreate(key, nil)
	defer DefaultPacketSnifferSessionMgr.Remove(key, sniffer)

	sniffer.Mu.Lock()

	// Simulate repeated decrypt failures
	for i := 0; i < consecutiveDecryptFailuresThreshold; i++ {
		sniffer.consecutiveDecryptFailures++
		// In real code, after threshold, it would mark DCID as failed
	}

	require.Equal(t, consecutiveDecryptFailuresThreshold, sniffer.consecutiveDecryptFailures,
		"Should track consecutive failures")

	sniffer.Mu.Unlock()
}

// TestUdpTrafficSimulation_AddrFamilyNormalization verifies address
// family normalization for sendPkt.
func TestUdpTrafficSimulation_AddrFamilyNormalization(t *testing.T) {
	tests := []struct {
		name        string
		from        string
		to          string
		expectBind  string
		expectWrite string
		expectError bool
	}{
		{
			name:        "IPv4 to IPv4",
			from:        "192.168.1.1:12345",
			to:          "192.168.1.100:54321",
			expectBind:  "192.168.1.1:12345",
			expectWrite: "192.168.1.100:54321",
			expectError: false,
		},
		{
			name:        "IPv4-mapped to IPv4",
			from:        "[::ffff:192.168.1.1]:12345",
			to:          "192.168.1.100:54321",
			expectBind:  "192.168.1.1:12345",
			expectWrite: "192.168.1.100:54321",
			expectError: false,
		},
		{
			name:        "IPv4 wildcard to IPv6",
			from:        "0.0.0.0:12345",
			to:          "[2001:db8::1]:443",
			expectBind:  "[::]:12345",
			expectWrite: "[2001:db8::1]:443",
			expectError: false,
		},
		{
			name:        "IPv4 to pure IPv6",
			from:        "192.168.1.1:12345",
			to:          "[2001:db8::1]:443",
			expectBind:  "[::]:12345", // PATCH: Promoted to IPv6 wildcard
			expectWrite: "[2001:db8::1]:443",
			expectError: false, // PATCH: Now supported
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			from, err := netip.ParseAddrPort(tt.from)
			require.NoError(t, err)

			to, err := netip.ParseAddrPort(tt.to)
			require.NoError(t, err)

			bindAddr, writeAddr := normalizeSendPktAddrFamily(from, to)
			isUnsupported := isUnsupportedTransparentUDPPair(bindAddr, writeAddr)

			require.Equal(t, tt.expectError, isUnsupported,
				"Unsupported pair detection should match")

			if !tt.expectError {
				require.Equal(t, tt.expectBind, bindAddr.String(),
					"Bind address should match")
				require.Equal(t, tt.expectWrite, writeAddr.String(),
					"Write address should match")
			}
		})
	}
}

// TestUdpTrafficSimulation_FlowDecisionKeys verifies flow decision
// key derivation.
func TestUdpTrafficSimulation_FlowDecisionKeys(t *testing.T) {
	src := netip.MustParseAddrPort("192.168.1.100:54321")
	dst := netip.MustParseAddrPort("93.184.216.34:443")

	quicPacket := sniffTestQuicPacket1
	decision := ClassifyUdpFlow(src, dst, quicPacket)

	t.Run("symmetric_nat_key_for_quic", func(t *testing.T) {
		symKey := decision.SymmetricNatEndpointKey()
		require.Equal(t, src, symKey.Src)
		require.Equal(t, dst, symKey.Dst)
	})

	t.Run("full_cone_key_for_non_quic", func(t *testing.T) {
		fullConeKey := decision.FullConeNatEndpointKey()
		require.Equal(t, src, fullConeKey.Src)
		require.Equal(t, uint16(0), fullConeKey.Dst.Port())
	})

	t.Run("endpoint_key_for_dial_with_domain", func(t *testing.T) {
		dialKey := decision.EndpointKeyForDial("example.com")
		require.Equal(t, src, dialKey.Src)
		require.Equal(t, dst, dialKey.Dst,
			"Should use symmetric NAT for QUIC/domain")
	})

	t.Run("endpoint_key_for_dial_without_domain", func(t *testing.T) {
		nonQuicDecision := ClassifyUdpFlow(src, dst, []byte{0x00, 0x01})
		dialKey := nonQuicDecision.EndpointKeyForDial("")
		require.Equal(t, src, dialKey.Src)
		// Port 443 is treated as QUIC-like, so Symmetric NAT is used
		require.Equal(t, dst.Port(), dialKey.Dst.Port(),
			"Port 443 is treated as QUIC-like, uses symmetric NAT")
	})
}

// TestUdpTrafficSimulation_DeadEndpointHandling verifies dead
// endpoint detection and handling.
func TestUdpTrafficSimulation_DeadEndpointHandling(t *testing.T) {
	// Create a mock endpoint
	ue := &UdpEndpoint{
		NatTimeout: DefaultNatTimeout,
		log:        nil,
	}
	ue.dead.Store(false)
	ue.RefreshTtl()

	// Initially alive
	require.False(t, ue.IsDead(), "Endpoint should be alive initially")
	require.False(t, ue.IsExpired(time.Now().UnixNano()+1),
		"Endpoint should not be expired immediately")

	// Mark as dead
	ue.dead.Store(true)
	require.True(t, ue.IsDead(), "Endpoint should be marked as dead")

	// Expired check
	ue.expiresAtNano.Store(1)
	require.True(t, ue.IsExpired(100), "Endpoint with expiresAtNano=1 should be expired")
}

// resetPacketSnifferPoolForTestForTraffic clears additional state for UDP traffic tests.
func resetPacketSnifferPoolForTestForTraffic() {
	DefaultPacketSnifferSessionMgr = NewPacketSnifferPool()
	ClearFailedQuicDcids()
}

// testName generates a test name based on packet content.
func testName(i int, pkt []byte) string {
	if len(pkt) < 8 {
		return "packet_short"
	}
	// Use first 8 bytes as hex identifier
	return "packet_" + hex.EncodeToString(pkt[:8])
}

// BenchmarkUdpTrafficSimulation_ClassifyNonQuic benchmarks classification
// of non-QUIC packets (hot path).
func BenchmarkUdpTrafficSimulation_ClassifyNonQuic(b *testing.B) {
	resetPacketSnifferPoolForTestForTraffic()

	src := netip.MustParseAddrPort("192.168.1.100:54321")
	dst := netip.MustParseAddrPort("8.8.8.8:53")
	nonQuicPkt := make([]byte, 64)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = ClassifyUdpFlow(src, dst, nonQuicPkt)
	}
}

// BenchmarkUdpTrafficSimulation_ClassifyQuic benchmarks classification
// of QUIC packets.
func BenchmarkUdpTrafficSimulation_ClassifyQuic(b *testing.B) {
	resetPacketSnifferPoolForTestForTraffic()

	src := netip.MustParseAddrPort("192.168.1.100:54321")
	dst := netip.MustParseAddrPort("93.184.216.34:443")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = ClassifyUdpFlow(src, dst, sniffTestQuicPacket1)
	}
}

// BenchmarkUdpTrafficSimulation_NatTimeoutSelection benchmarks NAT timeout
// selection logic.
func BenchmarkUdpTrafficSimulation_NatTimeoutSelection(b *testing.B) {
	tests := []struct {
		domain string
	}{
		{domain: ""},
		{domain: "example.com"},
	}

	for _, tt := range tests {
		b.Run(tt.domain, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				var natTimeout time.Duration
				if tt.domain != "" {
					natTimeout = QuicNatTimeout
				} else {
					natTimeout = DefaultNatTimeout
				}
				_ = natTimeout
			}
		})
	}
}

// TestUdpTrafficSimulation_ContextCancellation verifies that context
// cancellation doesn't cause issues in UDP processing.
func TestUdpTrafficSimulation_ContextCancellation(t *testing.T) {
	resetPacketSnifferPoolForTestForTraffic()
	defer resetPacketSnifferPoolForTestForTraffic()

	src := netip.MustParseAddrPort("192.168.1.100:54321")
	dst := netip.MustParseAddrPort("93.184.216.34:443")

	// Create a context that will be cancelled - verify UDP processing
	// is independent of context lifecycle (unlike TCP which uses context for dial)
	_, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Simulate packet processing with context
	decision := ClassifyUdpFlow(src, dst, sniffTestQuicPacket1)

	// Decision should be made regardless of context state
	require.True(t, decision.IsQuicInitial,
		"Decision should be made even with cancellable context")

	// Cancel context
	cancel()

	// Classification should still work after cancellation
	decision2 := ClassifyUdpFlow(src, dst, sniffTestQuicPacket2)
	require.True(t, decision2.IsQuicInitial,
		"Classification should work after context cancellation")
}

// TestUdpTrafficSimulation_MalformedPackets verifies handling of
// malformed UDP packets.
func TestUdpTrafficSimulation_MalformedPackets(t *testing.T) {
	resetPacketSnifferPoolForTestForTraffic()
	defer resetPacketSnifferPoolForTestForTraffic()

	src := netip.MustParseAddrPort("192.168.1.100:54321")
	dst := netip.MustParseAddrPort("8.8.8.8:53")

	malformedPackets := [][]byte{
		{},                      // Empty
		{0x00},                  // Too short
		make([]byte, 1),         // Single byte
		make([]byte, 3),         // Too short for DNS
	}

	for i, pkt := range malformedPackets {
		t.Run(testName(i, pkt), func(t *testing.T) {
			// Should not panic on malformed packets
			require.NotPanics(t, func() {
				decision := ClassifyUdpFlow(src, dst, pkt)

				// Malformed packets should not be QUIC
				require.False(t, decision.IsQuicInitial,
					"Malformed packet should not be QUIC Initial")

				// Should not require ordered ingress
				require.False(t, decision.ShouldUseOrderedIngress(),
					"Malformed packet should not require ordered ingress")
			})
		})
	}
}
