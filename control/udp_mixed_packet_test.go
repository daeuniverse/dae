/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 *
 * UDP Mixed Packet Test - verifies all packet types are processed without blocking
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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// PacketType represents different UDP packet types
type PacketType string

const (
	PacketTypeDNS        PacketType = "dns"
	PacketTypeQUIC       PacketType = "quic"
	PacketTypeSTUN       PacketType = "stun"
	PacketTypeWireGuard  PacketType = "wireguard"
	PacketTypeGeneric    PacketType = "generic"
	PacketTypeMalformed  PacketType = "malformed"
	PacketTypeDTLS       PacketType = "dtls"
)

// TestPacket represents a test UDP packet with metadata
type TestPacket struct {
	Type     PacketType
	Data     []byte
	Src      netip.AddrPort
	Dst      netip.AddrPort
	Expected struct {
		IsQuicInitial     bool
		ShouldUseOrderedIngress  bool
		ShouldAttemptSniff bool
	}
	Description string
}

// GenerateTestPackets generates a comprehensive set of test packets
func GenerateTestPackets() []TestPacket {
	baseSrc := netip.MustParseAddrPort("192.168.1.100:50000")
	baseDst := netip.MustParseAddrPort("8.8.8.8:53")
	httpsDst := netip.MustParseAddrPort("93.184.216.34:443")

	packets := []TestPacket{}

	// 1. DNS Query packets (port 53)
	for i := 0; i < 10; i++ {
		pkt := TestPacket{
			Type:        PacketTypeDNS,
			Data:        generateDNSQuery(uint16(i)),
			Src:         netip.AddrPortFrom(baseSrc.Addr(), uint16(50000+i)),
			Dst:         baseDst,
			Description: fmt.Sprintf("DNS Query %d", i),
		}
		pkt.Expected.IsQuicInitial = false
		pkt.Expected.ShouldUseOrderedIngress = false
		pkt.Expected.ShouldAttemptSniff = false
		packets = append(packets, pkt)
	}

	// 2. QUIC Initial packets (port 443)
	quicPackets := [][]byte{
		sniffTestQuicPacket1,
		sniffTestQuicPacket2,
		sniffTestQuicPacket3,
		generateQuicInitialPacket([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}), // Custom DCID
	}
	for i, qp := range quicPackets {
		pkt := TestPacket{
			Type:        PacketTypeQUIC,
			Data:        qp,
			Src:         netip.AddrPortFrom(baseSrc.Addr(), uint16(51000+i)),
			Dst:         httpsDst,
			Description: fmt.Sprintf("QUIC Initial %d", i),
		}
		pkt.Expected.IsQuicInitial = true
		pkt.Expected.ShouldUseOrderedIngress = true
		pkt.Expected.ShouldAttemptSniff = true
		packets = append(packets, pkt)
	}

	// 3. STUN packets (port 3478)
	stunDst := netip.MustParseAddrPort("1.2.3.4:3478")
	for i := 0; i < 5; i++ {
		pkt := TestPacket{
			Type:        PacketTypeSTUN,
			Data:        generateSTUNPacket(),
			Src:         netip.AddrPortFrom(baseSrc.Addr(), uint16(52000+i)),
			Dst:         stunDst,
			Description: fmt.Sprintf("STUN %d", i),
		}
		pkt.Expected.IsQuicInitial = false
		pkt.Expected.ShouldUseOrderedIngress = false
		pkt.Expected.ShouldAttemptSniff = false
		packets = append(packets, pkt)
	}

	// 4. WireGuard packets (port 51820)
	wgDst := netip.MustParseAddrPort("10.0.0.1:51820")
	for i := 0; i < 5; i++ {
		pkt := TestPacket{
			Type:        PacketTypeWireGuard,
			Data:        generateWireGuardPacket(),
			Src:         netip.AddrPortFrom(baseSrc.Addr(), uint16(53000+i)),
			Dst:         wgDst,
			Description: fmt.Sprintf("WireGuard %d", i),
		}
		pkt.Expected.IsQuicInitial = false
		pkt.Expected.ShouldUseOrderedIngress = false
		pkt.Expected.ShouldAttemptSniff = false
		packets = append(packets, pkt)
	}

	// 5. Generic UDP packets (various ports)
	for i := 0; i < 20; i++ {
		pkt := TestPacket{
			Type:        PacketTypeGeneric,
			Data:        generateGenericUDPPacket(64 + i*32),
			Src:         netip.AddrPortFrom(baseSrc.Addr(), uint16(54000+i)),
			Dst:         netip.AddrPortFrom(netip.MustParseAddr("203.0.113.1"), uint16(10000+i)),
			Description: fmt.Sprintf("Generic UDP %d", i),
		}
		pkt.Expected.IsQuicInitial = false
		pkt.Expected.ShouldUseOrderedIngress = false
		pkt.Expected.ShouldAttemptSniff = false
		packets = append(packets, pkt)
	}

	// 6. DTLS packets (port 443 but not QUIC)
	for i := 0; i < 3; i++ {
		pkt := TestPacket{
			Type:        PacketTypeDTLS,
			Data:        generateDTLSPacket(),
			Src:         netip.AddrPortFrom(baseSrc.Addr(), uint16(55000+i)),
			Dst:         httpsDst,
			Description: fmt.Sprintf("DTLS %d", i),
		}
		pkt.Expected.IsQuicInitial = false
		pkt.Expected.ShouldUseOrderedIngress = false
		pkt.Expected.ShouldAttemptSniff = false
		packets = append(packets, pkt)
	}

	// 7. Malformed packets
	malformedSizes := []int{0, 1, 3, 5}
	for i, size := range malformedSizes {
		pkt := TestPacket{
			Type:        PacketTypeMalformed,
			Data:        make([]byte, size),
			Src:         netip.AddrPortFrom(baseSrc.Addr(), uint16(56000+i)),
			Dst:         baseDst,
			Description: fmt.Sprintf("Malformed size %d", size),
		}
		pkt.Expected.IsQuicInitial = false
		pkt.Expected.ShouldUseOrderedIngress = false
		pkt.Expected.ShouldAttemptSniff = false
		packets = append(packets, pkt)
	}

	return packets
}

// generateDNSQuery creates a DNS query packet
func generateDNSQuery(id uint16) []byte {
	// DNS header: transaction ID, flags, questions, answer, authority, additional
	pkt := []byte{
		byte(id >> 8), byte(id & 0xff), // Transaction ID
		0x01, 0x00, // Flags: standard query
		0x00, 0x01, // Questions: 1
		0x00, 0x00, // Answer RRs: 0
		0x00, 0x00, // Authority RRs: 0
		0x00, 0x00, // Additional RRs: 0
	}
	// Query: www.example.com
	queries := []byte{
		0x03, 'w', 'w', 'w',
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00, // End of name
		0x00, 0x01, // Type: A
		0x00, 0x01, // Class: IN
	}
	return append(pkt, queries...)
}

// generateQuicInitialPacket creates a minimal QUIC Initial packet
func generateQuicInitialPacket(dcid []byte) []byte {
	if len(dcid) > 20 {
		dcid = dcid[:20]
	}
	dcidLen := len(dcid)

	// QUIC Initial header
	pkt := []byte{
		0xC0, // Long Header + Initial + Fixed Bit
		0x00, 0x00, 0x00, 0x01, // Version 1
		byte(dcidLen), // DCID Length
	}
	pkt = append(pkt, dcid...)
	pkt = append(pkt, 0x00) // SCID Length = 0
	pkt = append(pkt, 0x00, 0x00, 0x00) // Token Length = 0
	pkt = append(pkt, 0x00, 0x00, 0x00) // Length = 0

	return pkt
}

// generateSTUNPacket creates a STUN binding request
func generateSTUNPacket() []byte {
	// STUN magic cookie and method
	return []byte{
		0x00, 0x01, // Binding Request
		0x00, 0x00, // Message Length
		0x21, 0x12, 0xa4, 0x42, // Magic Cookie
		// Transaction ID (96 bits)
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b,
	}
}

// generateWireGuardPacket creates a WireGuard handshake initiation
func generateWireGuardPacket() []byte {
	// WireGuard Type 1: Handshake Initiation
	pkt := make([]byte, 148) // Minimum size
	pkt[0] = 0x01 // Message Type = 1
	pkt[1] = 0x00 // Reserved
	pkt[2] = 0x00 // Reserved
	pkt[3] = 0x00 // Reserved
	// Rest is sender key, ephemeral, etc.
	return pkt
}

// generateGenericUDPPacket creates a generic UDP packet
func generateGenericUDPPacket(size int) []byte {
	pkt := make([]byte, size)
	// First byte = 0 to avoid QUIC detection
	pkt[0] = 0x00
	for i := 1; i < size; i++ {
		pkt[i] = byte(i % 256)
	}
	return pkt
}

// generateDTLSPacket creates a DTLS ClientHello
func generateDTLSPacket() []byte {
	// DTLS 1.2 ClientHello
	return []byte{
		0x16, // Content Type: Handshake
		0xfe, 0xfd, // DTLS 1.2
		0x00, 0x00, // Epoch
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Sequence Number
		0x00, 0x20, // Length
		0x01, // Handshake Type: ClientHello
		// ... rest of handshake
	}
}

// TestUdpMixedPacket_NoBlocking verifies that all packet types are processed
// without blocking or hanging
func TestUdpMixedPacket_NoBlocking(t *testing.T) {
	resetPacketSnifferPoolForTestForTraffic()
	defer resetPacketSnifferPoolForTestForTraffic()

	packets := GenerateTestPackets()
	t.Logf("Testing %d different packet types", len(packets))

	var processedCount atomic.Int32
	var blockedCount atomic.Int32
	var unexpectedResult atomic.Int32

	var wg sync.WaitGroup
	results := make(chan packetResult, len(packets))

	// Process all packets with a timeout
	timeout := time.AfterFunc(30*time.Second, func() {
		t.Errorf("Test timeout after 30 seconds - some packets may be blocked!")
	})

	for i, pkt := range packets {
		wg.Add(1)
		go func(idx int, p TestPacket) {
			defer wg.Done()

			start := time.Now()
			decision := ClassifyUdpFlow(p.Src, p.Dst, p.Data)
			elapsed := time.Since(start)

			// Verify expected behavior
			if decision.IsQuicInitial != p.Expected.IsQuicInitial {
				t.Errorf("Packet %d (%s): IsQuicInitial = %v, expected %v",
					idx, p.Description, decision.IsQuicInitial, p.Expected.IsQuicInitial)
				unexpectedResult.Add(1)
			}

			if decision.ShouldUseOrderedIngress() != p.Expected.ShouldUseOrderedIngress {
				t.Errorf("Packet %d (%s): ShouldUseOrderedIngress = %v, expected %v",
					idx, p.Description, decision.ShouldUseOrderedIngress(), p.Expected.ShouldUseOrderedIngress)
				unexpectedResult.Add(1)
			}

			// Check for blocking
			if elapsed > 100*time.Millisecond {
				t.Errorf("Packet %d (%s): Processing took too long: %v",
					idx, p.Description, elapsed)
				blockedCount.Add(1)
			}

			results <- packetResult{
				Index:    idx,
				Type:     p.Type,
				Desc:     p.Description,
				Elapsed:  elapsed,
				Decision: decision,
			}
			processedCount.Add(1)
		}(i, pkt)
	}

	wg.Wait()
	timeout.Stop()
	close(results)

	// Verify all packets were processed
	total := int32(len(packets))
	require.Equal(t, total, processedCount.Load(),
		"All packets should be processed")

	// Print statistics by packet type
	stats := make(map[PacketType]processingStats)
	for r := range results {
		stats[r.Type] = processingStats{
			Count:  stats[r.Type].Count + 1,
			MaxLat: max(stats[r.Type].MaxLat, r.Elapsed),
		}
	}

	t.Logf("=== Processing Statistics ===")
	for _, pType := range []PacketType{
		PacketTypeDNS, PacketTypeQUIC, PacketTypeSTUN,
		PacketTypeWireGuard, PacketTypeGeneric, PacketTypeDTLS, PacketTypeMalformed,
	} {
		if stat, ok := stats[pType]; ok {
			t.Logf("  %s: %d packets, max latency: %v",
				pType, stat.Count, stat.MaxLat)
		}
	}

	// Verify no blocking occurred
	require.Equal(t, int32(0), blockedCount.Load(),
		"No packets should be blocked")

	require.Equal(t, int32(0), unexpectedResult.Load(),
		"All packet classifications should match expectations")
}

// TestUdpMixedPacket_SequentialProcessing verifies packets are processed
// correctly when sent sequentially
func TestUdpMixedPacket_SequentialProcessing(t *testing.T) {
	resetPacketSnifferPoolForTestForTraffic()
	defer resetPacketSnifferPoolForTestForTraffic()

	packets := GenerateTestPackets()

	for i, pkt := range packets {
		t.Run(pkt.Description, func(t *testing.T) {
			start := time.Now()
			decision := ClassifyUdpFlow(pkt.Src, pkt.Dst, pkt.Data)
			elapsed := time.Since(start)

			// Verify no blocking
			assert.Less(t, elapsed, 10*time.Millisecond,
				"Sequential packet processing should be fast")

			// Verify classification
			assert.Equal(t, pkt.Expected.IsQuicInitial, decision.IsQuicInitial,
				"IsQuicInitial should match expected")
			assert.Equal(t, pkt.Expected.ShouldUseOrderedIngress, decision.ShouldUseOrderedIngress(),
				"ShouldUseOrderedIngress should match expected")

			t.Logf("Packet %d (%s): processed in %v, quic=%v, ordered=%v",
				i, pkt.Description, elapsed, decision.IsQuicInitial, decision.ShouldUseOrderedIngress())
		})
	}
}

// TestUdpMixedPacket_ConcurrentBurst verifies rapid concurrent packet processing
func TestUdpMixedPacket_ConcurrentBurst(t *testing.T) {
	resetPacketSnifferPoolForTestForTraffic()
	defer resetPacketSnifferPoolForTestForTraffic()

	packets := GenerateTestPackets()
	const burstSize = 50 // Process 50 packets concurrently

	var totalProcessed atomic.Int64
	var totalLatency atomic.Int64
	var maxLatency atomic.Int64

	start := time.Now()

	for burst := 0; burst < (len(packets)+burstSize-1)/burstSize; burst++ {
		var wg sync.WaitGroup
		burstStart := burst * burstSize
		burstEnd := min(burstStart+burstSize, len(packets))

		for i := burstStart; i < burstEnd; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				pkt := packets[idx]

				pstart := time.Now()
				_ = ClassifyUdpFlow(pkt.Src, pkt.Dst, pkt.Data)
				latency := time.Since(pstart)

				totalProcessed.Add(1)
				totalLatency.Add(int64(latency))

				// Update max latency
				for {
					max := maxLatency.Load()
					if int64(latency) <= max || maxLatency.CompareAndSwap(max, int64(latency)) {
						break
					}
				}
			}(i)
		}
		wg.Wait()
	}

	totalElapsed := time.Since(start)
	avgLatency := time.Duration(totalLatency.Load() / totalProcessed.Load())

	t.Logf("Concurrent burst processing:")
	t.Logf("  Total packets: %d", totalProcessed.Load())
	t.Logf("  Total time: %v", totalElapsed)
	t.Logf("  Average latency: %v", avgLatency)
	t.Logf("  Max latency: %v", time.Duration(maxLatency.Load()))
	t.Logf("  Throughput: %.0f packets/sec",
		float64(totalProcessed.Load())/totalElapsed.Seconds())

	// Verify performance requirements
	assert.Less(t, avgLatency, 10*time.Millisecond,
		"Average latency should be under 10ms")
	assert.Greater(t, float64(totalProcessed.Load())/totalElapsed.Seconds(), 1000.0,
		"Should process at least 1000 packets/sec")
}

// TestUdpMixedPacket_QuicDcidIsolation verifies that different QUIC DCIDs
// are isolated in the sniffer pool
func TestUdpMixedPacket_QuicDcidIsolation(t *testing.T) {
	resetPacketSnifferPoolForTestForTraffic()
	defer resetPacketSnifferPoolForTestForTraffic()

	src := netip.MustParseAddrPort("192.168.1.100:50000")
	dst := netip.MustParseAddrPort("93.184.216.34:443")

	// Create QUIC packets with different DCIDs
	dcids := [][]byte{
		{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		{0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18},
		{0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88},
	}

	var keys []PacketSnifferKey
	for _, dcid := range dcids {
		pkt := generateQuicInitialPacket(dcid)
		key := NewPacketSnifferKey(src, dst, pkt)
		keys = append(keys, key)

		// Create sniffer for each DCID
		sniffer, isNew := DefaultPacketSnifferSessionMgr.GetOrCreate(key, nil)
		require.True(t, isNew, "Should create new sniffer for new DCID")
		require.NotNil(t, sniffer, "Sniffer should not be nil")

		// Verify DCID is in the key
		require.NotEqual(t, uint8(0), key.DCIDLen, "DCID length should be set")
		require.Equal(t, dcid, key.DCID[:len(dcid)], "DCID should match")
	}

	// Verify each DCID has a separate sniffer
	for i, key := range keys {
		sniffer := DefaultPacketSnifferSessionMgr.Get(key)
		require.NotNil(t, sniffer, "Sniffer for DCID %d should exist", i)

		// Verify DCID uniqueness
		for j, otherKey := range keys {
			if i != j {
				require.NotEqual(t, key, otherKey,
					"DCID %d key should differ from DCID %d", i, j)
			}
		}

		// Clean up
		DefaultPacketSnifferSessionMgr.Remove(key, sniffer)
	}
}

// TestUdpMixedPacket_PacketDropSimulation simulates packet drops
func TestUdpMixedPacket_PacketDropSimulation(t *testing.T) {
	resetPacketSnifferPoolForTestForTraffic()
	defer resetPacketSnifferPoolForTestForTraffic()

	src := netip.MustParseAddrPort("192.168.1.100:50000")
	dst := netip.MustParseAddrPort("93.184.216.34:443")

	// Simulate QUIC handshake with packet loss
	// Send only first packet, then timeout
	key := NewPacketSnifferKey(src, dst, sniffTestQuicPacket1)
	sniffer, _ := DefaultPacketSnifferSessionMgr.GetOrCreate(key, nil)

	sniffer.Mu.Lock()
	now := time.Now()

	// Simulate multiple failed sniff attempts
	for i := 0; i < udpSniffNoSniThreshold; i++ {
		sniffer.RecordSniffNoSni(now)
	}

	// Should now bypass sniffing
	require.True(t, sniffer.ShouldBypassSniff(now),
		"Should bypass after threshold failures")

	sniffer.Mu.Unlock()

	// Mark as failed for fast path
	MarkQuicDcidFailed(key)

	// Verify bypass works
	require.True(t, IsQuicDcidFailed(key),
		"DCID should be marked as failed")

	// Subsequent packets should not enter sniffing
	decision := ClassifyUdpFlow(src, dst, sniffTestQuicPacket1)
	// Classification still works, but sniffing is bypassed via DCID check
	require.True(t, decision.IsQuicInitial,
		"Classification should still work")

	// Clean up
	DefaultPacketSnifferSessionMgr.Remove(key, sniffer)
	ClearFailedQuicDcids()
}

// TestUdpMixedPacket_PortReuseDifferentDestinations verifies source port
// reuse with different destinations works correctly
func TestUdpMixedPacket_PortReuseDifferentDestinations(t *testing.T) {
	resetPacketSnifferPoolForTestForTraffic()
	defer resetPacketSnifferPoolForTestForTraffic()

	src := netip.MustParseAddrPort("192.168.1.100:50000")

	destinations := []netip.AddrPort{
		netip.MustParseAddrPort("8.8.8.8:53"),
		netip.MustParseAddrPort("93.184.216.34:443"),
		netip.MustParseAddrPort("1.1.1.1:443"),
		netip.MustParseAddrPort("10.0.0.1:853"),
	}

	for i, dst := range destinations {
		pkt := generateDNSQuery(uint16(i))
		decision := ClassifyUdpFlow(src, dst, pkt)

		// Verify decision keys are unique per destination
		symKey := decision.SymmetricNatEndpointKey()
		require.Equal(t, src, symKey.Src, "Source should match")
		require.Equal(t, dst, symKey.Dst, "Destination should match for symmetric NAT")

		t.Logf("Port %d to %s: key=%v",
			src.Port(), dst, symKey)
	}
}

// TestUdpMixedPacket_StressTest performs stress testing with many packets
func TestUdpMixedPacket_StressTest(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stress test in short mode")
	}

	resetPacketSnifferPoolForTestForTraffic()
	defer resetPacketSnifferPoolForTestForTraffic()

	const packetCount = 10000
	const numGoroutines = 100

	packetsPerGoroutine := packetCount / numGoroutines

	var processed atomic.Int64
	start := time.Now()

	var wg sync.WaitGroup
	for g := 0; g < numGoroutines; g++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()

			src := netip.AddrPortFrom(
				netip.MustParseAddr("192.168.1.1"),
				uint16(50000+goroutineID),
			)
			dst := netip.MustParseAddrPort("8.8.8.8:53")

			for i := 0; i < packetsPerGoroutine; i++ {
				pkt := generateDNSQuery(uint16(i))
				_ = ClassifyUdpFlow(src, dst, pkt)
				processed.Add(1)
			}
		}(g)
	}

	wg.Wait()
	elapsed := time.Since(start)

	throughput := float64(processed.Load()) / elapsed.Seconds()

	t.Logf("Stress test results:")
	t.Logf("  Packets processed: %d", processed.Load())
	t.Logf("  Total time: %v", elapsed)
	t.Logf("  Throughput: %.0f packets/sec", throughput)

	require.Equal(t, int64(packetCount), processed.Load(),
		"All packets should be processed")
	require.Greater(t, throughput, 10000.0,
		"Should process at least 10k packets/sec")
}

// TestUdpMixedPacket_MemoryUsage verifies memory usage stays bounded
func TestUdpMixedPacket_MemoryUsage(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping memory test in short mode")
	}

	resetPacketSnifferPoolForTestForTraffic()
	defer resetPacketSnifferPoolForTestForTraffic()

	// Force GC before starting
runtime.GC()
	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)

	// Process many packets
	const iterations = 1000
	for i := 0; i < iterations; i++ {
		src := netip.AddrPortFrom(
			netip.MustParseAddr("192.168.1.1"),
			uint16(50000+(i%1000)), // Reuse source ports
		)
		dst := netip.MustParseAddrPort("8.8.8.8:53")

		pkt := generateDNSQuery(uint16(i))
		_ = ClassifyUdpFlow(src, dst, pkt)
	}

	// Force GC and check memory
runtime.GC()
	var m2 runtime.MemStats
	runtime.ReadMemStats(&m2)

	// Calculate heap difference (handle overflow)
	var heapDiff int64
	if m2.HeapAlloc >= m1.HeapAlloc {
		heapDiff = int64(m2.HeapAlloc - m1.HeapAlloc)
	} else {
		heapDiff = -int64(m1.HeapAlloc-m2.HeapAlloc) // Memory was freed
	}

	t.Logf("Memory usage:")
	t.Logf("  Heap before: %d bytes", m1.HeapAlloc)
	t.Logf("  Heap after: %d bytes", m2.HeapAlloc)
	t.Logf("  Difference: %d bytes", heapDiff)
	t.Logf("  Per packet: %.2f bytes", float64(heapDiff)/float64(iterations))

	// Memory growth should be reasonable (< 1KB per packet)
	// Allow negative values (memory freed) which is good
	avgPerPacket := float64(heapDiff) / float64(iterations)
	if avgPerPacket > 0 {
		assert.Less(t, avgPerPacket, 1024.0,
			"Memory growth per packet should be reasonable")
	} else {
		t.Logf("  Memory was freed: %.2f bytes/packet", -avgPerPacket)
	}
}

// Helper types and functions

type packetResult struct {
	Index    int
	Type     PacketType
	Desc     string
	Elapsed  time.Duration
	Decision UdpFlowDecision
}

type processingStats struct {
	Count  int
	MaxLat time.Duration
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}

// BenchmarkUdpMixedPacket_ClassifyAllTypes benchmarks classification
// of all packet types
func BenchmarkUdpMixedPacket_ClassifyAllTypes(b *testing.B) {
	resetPacketSnifferPoolForTest()
	packets := GenerateTestPackets()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		pkt := packets[i%len(packets)]
		_ = ClassifyUdpFlow(pkt.Src, pkt.Dst, pkt.Data)
	}
}

// BenchmarkUdpMixedPacket_ParallelClassification benchmarks parallel
// classification
func BenchmarkUdpMixedPacket_ParallelClassification(b *testing.B) {
	resetPacketSnifferPoolForTest()
	packets := GenerateTestPackets()

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			pkt := packets[i%len(packets)]
			_ = ClassifyUdpFlow(pkt.Src, pkt.Dst, pkt.Data)
			i++
		}
	})
}
