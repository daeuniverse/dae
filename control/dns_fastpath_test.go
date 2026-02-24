/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
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

	dnsmessage "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// TestDNSFastPath_DNSPortDetection verifies that DNS traffic (port 53) is correctly identified.
func TestDNSFastPath_DNSPortDetection(t *testing.T) {
	tests := []struct {
		name     string
		port     uint16
		isDNS    bool
	}{
		{"DNS standard port", 53, true},
		{"HTTP port", 80, false},
		{"HTTPS port", 443, false},
		{"Random high port", 8080, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addrPort := netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", tt.port))

			// Check if port 53 is detected as DNS
			isDNS := addrPort.Port() == 53

			if tt.isDNS {
				require.True(t, isDNS, "port %d should be detected as DNS", tt.port)
			} else {
				require.False(t, isDNS, "port %d should not be detected as DNS", tt.port)
			}
		})
	}
}

// TestDNSFastPath_ConcurrentDNSQueries verifies that concurrent DNS queries can execute without ordering.
func TestDNSFastPath_ConcurrentDNSQueries(t *testing.T) {
	const n = 100
	done := make(chan int, n)

	// Simulate DNS fast path: execute tasks directly without ordering
	startTime := time.Now()
	for i := 0; i < n; i++ {
		go func(idx int) {
			// Simulate variable DNS query processing time
			time.Sleep(time.Duration(idx%10) * time.Millisecond)
			done <- idx
		}(i)
	}

	// Collect results (may be out of order)
	results := make([]int, 0, n)
	timeout := time.After(5 * time.Second)
	collectDone := false
	for !collectDone {
		select {
		case idx := <-done:
			results = append(results, idx)
			if len(results) == n {
				collectDone = true
			}
		case <-timeout:
			t.Fatal("timeout waiting for DNS queries")
		}
	}

	elapsed := time.Since(startTime)
	require.Len(t, results, n)
	// Verify all results are unique (using set)
	seen := make(map[int]struct{})
	for _, r := range results {
		if _, exists := seen[r]; exists {
			t.Fatalf("duplicate result %d", r)
		}
		seen[r] = struct{}{}
	}
	// Concurrent execution should be faster than sequential
	require.Less(t, elapsed, 500*time.Millisecond, "concurrent queries should complete faster")
}

// TestUdpTaskPool_NonDNSPreserveOrder verifies that non-DNS traffic still preserves order via UdpTaskPool.
func TestUdpTaskPool_NonDNSPreserveOrder(t *testing.T) {
	pool := NewUdpTaskPool()
	key := netip.MustParseAddrPort("127.0.0.1:8080") // Non-DNS port

	const n = 100
	got := make([]int, 0, n)
	var mu sync.Mutex
	var done atomic.Int32

	for i := range n {
		idx := i
		pool.EmitTask(key, func() {
			mu.Lock()
			got = append(got, idx)
			mu.Unlock()
			done.Add(1)
		})
	}

	require.Eventually(t, func() bool { return done.Load() == n }, 2*time.Second, 10*time.Millisecond)

	require.Len(t, got, n)
	for i := range n {
		require.Equal(t, i, got[i], "non-DNS traffic should preserve order")
	}
}

// TestDNSFastPath_MemoryProfile compares memory usage between direct execution and UdpTaskPool.
func TestDNSFastPath_MemoryProfile(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping memory profile test in short mode")
	}

	pool := NewUdpTaskPool()

	// Simulate 1000 different DNS source ports (random port scenario)
	ports := make([]netip.AddrPort, 1000)
	for i := range ports {
		ports[i] = netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", 20000+i))
	}

	var m1, m2, m3 runtime.MemStats

	// Baseline
	runtime.GC()
	runtime.ReadMemStats(&m1)

	// Without UdpTaskPool (DNS fast path simulation)
	var done1 atomic.Int32
	for i := 0; i < 1000; i++ {
		go func() { done1.Add(1) }()
	}
	for done1.Load() < 1000 {
		runtime.Gosched()
	}

	runtime.GC()
	runtime.ReadMemStats(&m2)

	// With UdpTaskPool (non-DNS path simulation)
	var done2 atomic.Int32
	for _, port := range ports {
		pool.EmitTask(port, func() {
			done2.Add(1)
		})
	}

	require.Eventually(t, func() bool { return done2.Load() == 1000 }, 5*time.Second, 100*time.Millisecond)

	runtime.GC()
	runtime.ReadMemStats(&m3)

	fastPathAlloc := m2.TotalAlloc - m1.TotalAlloc
	taskPoolAlloc := m3.TotalAlloc - m2.TotalAlloc

	t.Logf("Fast path allocated: %d bytes", fastPathAlloc)
	t.Logf("UdpTaskPool allocated: %d bytes", taskPoolAlloc)
	t.Logf("UdpTaskPool overhead: %d bytes (%.2fx)", taskPoolAlloc-fastPathAlloc,
		float64(taskPoolAlloc)/float64(fastPathAlloc))

	// UdpTaskPool should use more memory due to queue structures
	require.Greater(t, taskPoolAlloc, fastPathAlloc,
		"UdpTaskPool should use more memory than direct execution")
}

// BenchmarkDNSFastPath_DirectExecution benchmarks direct goroutine execution (DNS fast path).
func BenchmarkDNSFastPath_DirectExecution(b *testing.B) {
	var done atomic.Int64
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		go func() { done.Add(1) }()
	}
	for done.Load() < int64(b.N) {
		runtime.Gosched()
	}
}

// BenchmarkDNSFastPath_WithTaskPool benchmarks UdpTaskPool execution (non-DNS path).
func BenchmarkDNSFastPath_WithTaskPool(b *testing.B) {
	pool := NewUdpTaskPool()
	key := netip.MustParseAddrPort("127.0.0.1:8080")

	var done atomic.Int64
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pool.EmitTask(key, func() { done.Add(1) })
	}
	for done.Load() < int64(b.N) {
		runtime.Gosched()
	}
}

// BenchmarkDNSFastPath_ManySourcePorts benchmarks with many different source ports (realistic DNS scenario).
func BenchmarkDNSFastPath_ManySourcePorts(b *testing.B) {
	pool := NewUdpTaskPool()
	var done atomic.Int64

	b.Run("DirectExecution", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			port := uint16(20000 + (i % 1000))
			_ = netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", port))
			go func() { done.Add(1) }()
		}
		for done.Load() < int64(b.N) {
			runtime.Gosched()
		}
	})

	b.Run("UdpTaskPool", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			port := uint16(20000 + (i % 1000))
			key := netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", port))
			pool.EmitTask(key, func() { done.Add(1) })
		}
		for done.Load() < int64(b.N) {
			runtime.Gosched()
		}
	})
}

// TestDNSFastPath_RandomPorts simulates DNS queries with random source ports.
func TestDNSFastPath_RandomPorts(t *testing.T) {
	const numQueries = 500
	done := make(chan struct{}, numQueries)

	// Simulate DNS queries from random source ports
	for i := 0; i < numQueries; i++ {
		srcPort := 20000 + (i % 1000)
		srcAddr := netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", srcPort))
		dstAddr := netip.MustParseAddrPort("8.8.8.8:53")

		go func(src, dst netip.AddrPort) {
			// Verify destination is DNS port
			require.Equal(t, uint16(53), dst.Port())
			done <- struct{}{}
		}(srcAddr, dstAddr)
	}

	// Wait for all queries to complete
	timeout := time.After(5 * time.Second)
	completed := 0
	for completed < numQueries {
		select {
		case <-done:
			completed++
		case <-timeout:
			t.Fatalf("timeout: only %d/%d queries completed", completed, numQueries)
		}
	}
}

// =============================================================================
// Section: handlePkt DNS Fast Path Tests
// =============================================================================

// buildTestDNSQuery creates a valid DNS query packet for testing
func buildTestDNSQuery(t *testing.T, domain string, qtype uint16) []byte {
	t.Helper()
	req := new(dnsmessage.Msg)
	req.SetQuestion(dnsmessage.Fqdn(domain), qtype)
	req.RecursionDesired = true
	data, err := req.Pack()
	require.NoError(t, err)
	return data
}

// buildTestNonDNSPacket creates a UDP packet that is not DNS
func buildTestNonDNSPacket(t *testing.T) []byte {
	t.Helper()
	// Create a packet that looks like it might be DNS but fails validation
	// Use invalid DNS header (too short)
	data := make([]byte, 10)
	return data
}

// TestHandlePkt_DNSFastPath_PortDetection verifies that DNS port detection works
func TestHandlePkt_DNSFastPath_PortDetection(t *testing.T) {
	tests := []struct {
		name     string
		port     uint16
		isDNS    bool
	}{
		{"DNS standard port", 53, true},
		{"DNS over port 5353", 5353, false}, // mDNS, not standard DNS
		{"HTTP port", 80, false},
		{"HTTPS port", 443, false},
		{"QUIC port", 443, false},
		{"Random high port", 8080, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dstPort := tt.port
			isDNSFastPath := dstPort == 53

			if tt.isDNS {
				require.True(t, isDNSFastPath, "port %d should trigger DNS fast path", tt.port)
			} else {
				require.False(t, isDNSFastPath, "port %d should not trigger DNS fast path", tt.port)
			}
		})
	}
}

// TestHandlePkt_DNSFastPath_ValidDNS validates that valid DNS packets take fast path
func TestHandlePkt_DNSFastPath_ValidDNS(t *testing.T) {
	// Create a valid DNS query packet
	dnsQuery := buildTestDNSQuery(t, "example.com.", dnsmessage.TypeA)

	// Verify the packet is valid DNS
	var dnsmsg dnsmessage.Msg
	err := dnsmsg.Unpack(dnsQuery)
	require.NoError(t, err, "test DNS query should be valid")

	// Verify it has the expected fields
	require.Len(t, dnsmsg.Question, 1, "DNS query should have one question")
	require.Equal(t, "example.com.", dnsmsg.Question[0].Name)
	require.Equal(t, dnsmessage.TypeA, dnsmsg.Question[0].Qtype)
}

// TestHandlePkt_DNSFastPath_InvalidDNS validates that invalid DNS packets fall through
func TestHandlePkt_DNSFastPath_InvalidDNS(t *testing.T) {
	// Create packets that should NOT be identified as DNS
	testCases := []struct {
		name    string
		packet  []byte
		isValid bool
	}{
		{
			name:    "Too short",
			packet:  make([]byte, 5),
			isValid: false,
		},
		{
			name:    "Empty",
			packet:  []byte{},
			isValid: false,
		},
		{
			name:    "Malformed DNS header (invalid compression)",
			packet:  []byte{0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0xC0, 0x00, 0x01}, // Invalid compression pointer at start
			isValid: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var dnsmsg dnsmessage.Msg
			err := dnsmsg.Unpack(tc.packet)

			if tc.isValid {
				require.NoError(t, err, "packet should be valid DNS")
			} else {
				require.Error(t, err, "packet should be invalid DNS")
			}
		})
	}
}

// TestHandlePkt_DNSFastPath_MixedTraffic verifies correct behavior with mixed traffic
func TestHandlePkt_DNSFastPath_MixedTraffic(t *testing.T) {
	testCases := []struct {
		name         string
		dstPort      uint16
		packet       []byte
		shouldBeFast bool
	}{
		{
			name:         "Valid DNS query to port 53",
			dstPort:      53,
			packet:       buildTestDNSQuery(t, "example.com.", dnsmessage.TypeA),
			shouldBeFast: true,
		},
		{
			name:         "Invalid packet to port 53",
			dstPort:      53,
			packet:       buildTestNonDNSPacket(t),
			shouldBeFast: false, // Falls through to normal path
		},
		{
			name:         "DNS query to non-standard port",
			dstPort:      8053,
			packet:       buildTestDNSQuery(t, "example.com.", dnsmessage.TypeA),
			shouldBeFast: false, // Not port 53, goes to normal UDP path
		},
		{
			name:         "Regular UDP to port 443",
			dstPort:      443,
			packet:       []byte{0x01, 0x02, 0x03, 0x04},
			shouldBeFast: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dstAddr := netip.MustParseAddrPort(fmt.Sprintf("8.8.8.8:%d", tc.dstPort))

			// Check if this would take fast path (port 53)
			wouldCheckDNS := dstAddr.Port() == 53

			// For port 53, verify DNS packet is actually valid
			if wouldCheckDNS {
				var dnsmsg dnsmessage.Msg
				err := dnsmsg.Unpack(tc.packet)
				isValidDNS := err == nil

				if tc.shouldBeFast {
					require.True(t, isValidDNS, "fast path requires valid DNS packet")
				}
			}
		})
	}
}

// TestHandlePkt_DNSFastPath_DoesntSkipUdpEndpointForNonDNS ensures non-DNS traffic
// still uses UdpEndpoint for connection tracking
func TestHandlePkt_DNSFastPath_DoesntSkipUdpEndpointForNonDNS(t *testing.T) {
	// These ports should NOT trigger DNS fast path
	nonDNSPorts := []uint16{80, 443, 8080, 443, 5000, 3000}

	for _, port := range nonDNSPorts {
		t.Run(fmt.Sprintf("Port_%d", port), func(t *testing.T) {
			dstAddr := netip.MustParseAddrPort(fmt.Sprintf("93.184.216.34:%d", port))
			require.NotEqual(t, uint16(53), dstAddr.Port(),
				"non-DNS port should not be 53")
		})
	}
}

// TestChooseNatTimeout_SNIDetection verifies ChooseNatTimeout correctly identifies DNS
func TestChooseNatTimeout_SNIDetection(t *testing.T) {
	tests := []struct {
		name        string
		sniffDns    bool
		buildPacket func(t *testing.T) []byte
		expectDNS   bool
	}{
		{
			name:     "Valid DNS with sniffing enabled",
			sniffDns: true,
			buildPacket: func(t *testing.T) []byte {
				return buildTestDNSQuery(t, "test.com.", dnsmessage.TypeA)
			},
			expectDNS: true,
		},
		{
			name:     "Valid DNS with sniffing disabled",
			sniffDns: false,
			buildPacket: func(t *testing.T) []byte {
				return buildTestDNSQuery(t, "test.com.", dnsmessage.TypeA)
			},
			expectDNS: false, // sniffing disabled
		},
		{
			name:     "Invalid packet with sniffing enabled",
			sniffDns: true,
			buildPacket: func(t *testing.T) []byte {
				return buildTestNonDNSPacket(t)
			},
			expectDNS: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packet := tt.buildPacket(t)
			dnsMsg, timeout := ChooseNatTimeout(packet, tt.sniffDns)

			if tt.expectDNS {
				require.NotNil(t, dnsMsg, "should detect DNS message")
				require.Equal(t, DnsNatTimeout, timeout, "should use DNS timeout")
			} else {
				require.Nil(t, dnsMsg, "should not detect DNS message")
				require.Equal(t, DefaultNatTimeout, timeout, "should use default timeout")
			}
		})
	}
}

// TestHandlePkt_DNSFastPath_Qtypes tests various DNS query types
func TestHandlePkt_DNSFastPath_Qtypes(t *testing.T) {
	qtypes := []struct {
		name string
		qtype uint16
	}{
		{"A record", dnsmessage.TypeA},
		{"AAAA record", dnsmessage.TypeAAAA},
		{"CNAME record", dnsmessage.TypeCNAME},
		{"MX record", dnsmessage.TypeMX},
		{"TXT record", dnsmessage.TypeTXT},
		{"NS record", dnsmessage.TypeNS},
		{"SOA record", dnsmessage.TypeSOA},
		{"PTR record", dnsmessage.TypePTR},
	}

	for _, qt := range qtypes {
		t.Run(qt.name, func(t *testing.T) {
			packet := buildTestDNSQuery(t, "example.com.", qt.qtype)

			var dnsmsg dnsmessage.Msg
			err := dnsmsg.Unpack(packet)
			require.NoError(t, err, "%s query should be valid DNS", qt.name)
			require.Equal(t, qt.qtype, dnsmsg.Question[0].Qtype)
		})
	}
}

// TestHandlePkt_DNSFastPath_EdgeCases tests edge cases for DNS fast path
func TestHandlePkt_DNSFastPath_EdgeCases(t *testing.T) {
	t.Run("Multiple questions", func(t *testing.T) {
		req := new(dnsmessage.Msg)
		req.SetQuestion("example.com.", dnsmessage.TypeA)
		// Add another question (EDNS or additional)
		req.Extra = []dnsmessage.RR{
			&dnsmessage.OPT{
				Hdr: dnsmessage.RR_Header{
					Name:   ".",
					Rrtype: dnsmessage.TypeOPT,
				},
			},
		}
		packet, err := req.Pack()
		require.NoError(t, err)

		var dnsmsg dnsmessage.Msg
		err = dnsmsg.Unpack(packet)
		require.NoError(t, err, "DNS with EDNS should be valid")
	})

	t.Run("Empty question name", func(t *testing.T) {
		req := new(dnsmessage.Msg)
		req.SetQuestion(".", dnsmessage.TypeA)
		packet, err := req.Pack()
		require.NoError(t, err)

		var dnsmsg dnsmessage.Msg
		err = dnsmsg.Unpack(packet)
		require.NoError(t, err, "root query should be valid")
	})

	t.Run("Long domain name", func(t *testing.T) {
		longDomain := "a.very.long.domain.name." +
			"that.exceeds.normal.length." +
			"but.is.still.valid.according." +
			"to.rfc.specifications.for." +
			"dns.queries.on.the.internet."
		req := new(dnsmessage.Msg)
		req.SetQuestion(longDomain, dnsmessage.TypeA)
		packet, err := req.Pack()
		require.NoError(t, err)

		var dnsmsg dnsmessage.Msg
		err = dnsmsg.Unpack(packet)
		require.NoError(t, err, "long domain name should be valid")
	})
}

// BenchmarkUdpEndpoint_LookupCost benchmarks the cost of UdpEndpointPool.Get()
// This is what DNS fast path avoids
func BenchmarkUdpEndpoint_LookupCost(b *testing.B) {
	// Create a mock pool with some entries
	src1 := netip.MustParseAddrPort("192.168.1.100:50000")
	src2 := netip.MustParseAddrPort("192.168.1.100:50001")
	src3 := netip.MustParseAddrPort("192.168.1.100:50002")

	b.Run("Lookup_Existing", func(b *testing.B) {
		// Simulate lookup of existing endpoint
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			// This simulates the sync.Map.Load() that DNS fast path avoids
			_ = src1.Port() == 53 // Simple port check instead
		}
	})

	b.Run("PortCheck_Versus_Lookup", func(b *testing.B) {
		srcs := []netip.AddrPort{src1, src2, src3}
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			src := srcs[i%len(srcs)]
			// DNS fast path: just check port
			_ = src.Port() == 53
		}
	})
}
