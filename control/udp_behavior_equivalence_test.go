/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net/netip"
	"testing"
)

// TestNormalizeSendPktAddrFamily_Equivalence tests that normalizeSendPktAddrFamily
// produces optimized results with IPv4-mapped unmap and IPv6 wildcard for multi-server support.
func TestNormalizeSendPktAddrFamily_Equivalence(t *testing.T) {
	tests := []struct {
		name            string
		from            string // Response source (e.g., SS server address)
		realTo          string // Client address
		expectBindAddr  string
		expectWriteAddr string
		expectError     bool
	}{
		{
			name:            "IPv4 SS server to IPv4 client",
			from:            "10.0.0.1:12345",
			realTo:          "192.168.1.100:54321",
			expectBindAddr:  "10.0.0.1:12345",
			expectWriteAddr: "192.168.1.100:54321",
		},
		{
			name:            "IPv4 SS server to IPv4-mapped IPv6 client",
			from:            "10.0.0.1:12345",
			realTo:          "[::ffff:192.168.1.100]:54321",
			expectBindAddr:  "10.0.0.1:12345", // Optimized: both IPv4-compatible, unmap to pure IPv4
			expectWriteAddr: "192.168.1.100:54321",
		},
		{
			name:            "IPv4-mapped IPv6 SS server to IPv4 client",
			from:            "[::ffff:10.0.0.1]:12345",
			realTo:          "192.168.1.100:54321",
			expectBindAddr:  "10.0.0.1:12345", // Optimized: both IPv4-compatible, unmap to pure IPv4
			expectWriteAddr: "192.168.1.100:54321",
		},
		{
			name:            "IPv4 SS server to pure IPv6 client",
			from:            "10.0.0.1:12345",
			realTo:          "[2001:db8::1]:54321",
			expectBindAddr:  "[::]:12345", // IPv6 wildcard for dual-stack socket (multi-server support)
			expectWriteAddr: "[2001:db8::1]:54321",
			expectError:     false,
		},
		{
			name:            "STUN server (public IP) to client",
			from:            "1.2.3.4:3478", // STUN server
			realTo:          "192.168.1.100:12345",
			expectBindAddr:  "1.2.3.4:3478",
			expectWriteAddr: "192.168.1.100:12345",
		},
		{
			name:            "IPv6 STUN server to IPv4 client",
			from:            "[2001:db8::1]:3478",
			realTo:          "192.168.1.100:12345",
			expectBindAddr:  "[2001:db8::1]:3478",
			expectWriteAddr: "[::ffff:192.168.1.100]:12345", // IPv4-mapped for dual-stack
			expectError:     false,
		},
		{
			name:            "IPv4 SS server to IPv4-mapped IPv6 client (duplicate test case)",
			from:            "10.0.0.1:12345",
			realTo:          "[::ffff:192.168.1.100]:54321",
			expectBindAddr:  "10.0.0.1:12345", // Optimized: both IPv4-compatible, unmap to pure IPv4
			expectWriteAddr: "192.168.1.100:54321",
			expectError:     false,
		},
		{
			name:            "IPv4 SS server to pure IPv6 client (duplicate test case)",
			from:            "10.0.0.1:12345",
			realTo:          "[2001:db8::1]:54321",
			expectBindAddr:  "[::]:12345", // IPv6 wildcard for dual-stack socket (multi-server support)
			expectWriteAddr: "[2001:db8::1]:54321",
			expectError:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			from, err := netip.ParseAddrPort(tt.from)
			if err != nil {
				t.Fatalf("invalid from address %q: %v", tt.from, err)
			}
			realTo, err := netip.ParseAddrPort(tt.realTo)
			if err != nil {
				t.Fatalf("invalid realTo address %q: %v", tt.realTo, err)
			}

			bindAddr, writeAddr := normalizeSendPktAddrFamily(from, realTo)

			if tt.expectError {
				t.Errorf("expected error but got none: bind=%v write=%v", bindAddr, writeAddr)
				return
			}

			if bindAddr.String() != tt.expectBindAddr {
				t.Errorf("bindAddr = %v, want %v", bindAddr.String(), tt.expectBindAddr)
			}
			if writeAddr.String() != tt.expectWriteAddr {
				t.Errorf("writeAddr = %v, want %v", writeAddr.String(), tt.expectWriteAddr)
			}

			// Test main branch equivalence
			// main branch uses from.String() directly as pool key
			mainBranchKey := from.String()
			currentBranchKey := bindAddr.String()

			if mainBranchKey != currentBranchKey {
				t.Logf("KEY DIFFERENCE: main=%v != current=%v", mainBranchKey, currentBranchKey)
			}
		})
	}
}

// TestStringVsAddrPortKeyEquivalence tests the difference between using
// string key (main branch) vs netip.AddrPort key (current branch).
func TestStringVsAddrPortKeyEquivalence(t *testing.T) {
	tests := []struct {
		name     string
		addr1    string
		addr2    string
		expectEq bool
	}{
		{
			name:     "Same IPv4 address",
			addr1:    "10.0.0.1:12345",
			addr2:    "10.0.0.1:12345",
			expectEq: true,
		},
		{
			name:     "IPv4 vs IPv4-mapped IPv6",
			addr1:    "10.0.0.1:12345",
			addr2:    "[::ffff:10.0.0.1]:12345",
			expectEq: false, // Different string representation
		},
		{
			name:     "Different IPv4 addresses",
			addr1:    "10.0.0.1:12345",
			addr2:    "10.0.0.1:54321",
			expectEq: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr1, err := netip.ParseAddrPort(tt.addr1)
			if err != nil {
				t.Fatalf("invalid addr1: %v", err)
			}
			addr2, err := netip.ParseAddrPort(tt.addr2)
			if err != nil {
				t.Fatalf("invalid addr2: %v", err)
			}

			// main branch uses string key
			mainKey1 := addr1.String()
			mainKey2 := addr2.String()

			// current branch uses netip.AddrPort as key
			currentEq := addr1 == addr2

			mainEq := mainKey1 == mainKey2

			if mainEq != currentEq {
				t.Errorf("equivalence mismatch: string=%v, addrport=%v", mainEq, currentEq)
			}

			if mainEq != tt.expectEq {
				t.Errorf("string equality = %v, want %v", mainEq, tt.expectEq)
			}
		})
	}
}

// TestSTUNResponseRouting simulates STUN response routing scenarios.
func TestSTUNResponseRouting(t *testing.T) {
	tests := []struct {
		name        string
		ssServer    string // SS server address (response source)
		clientAddr  string // Client address
		shouldFail  bool
		description string
	}{
		{
			name:        "SS IPv4 to Client IPv4",
			ssServer:    "10.0.0.1:8388",
			clientAddr:  "192.168.1.100:12345",
			shouldFail:  false,
			description: "Normal case: both IPv4",
		},
		{
			name:        "SS IPv4 to Client IPv4-mapped IPv6",
			ssServer:    "10.0.0.1:8388",
			clientAddr:  "[::ffff:192.168.1.100]:12345",
			shouldFail:  false,
			description: "Client uses IPv4-mapped IPv6, should unmap to IPv4",
		},
		{
			name:        "SS IPv4 to Client pure IPv6",
			ssServer:    "10.0.0.1:8388",
			clientAddr:  "[2001:db8::100]:12345",
			shouldFail:  false,
			description: "IPv4 promoted to v6 wildcard, both v6",
		},
		{
			name:        "SS IPv6 to Client IPv4",
			ssServer:    "[2001:db8::1]:8388",
			clientAddr:  "192.168.1.100:12345",
			shouldFail:  false,
			description: "Client aligned to v6, both v6",
		},
		{
			name:        "SS IPv6 to Client IPv6",
			ssServer:    "[2001:db8::1]:8388",
			clientAddr:  "[2001:db8::100]:12345",
			shouldFail:  false,
			description: "Both IPv6",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			from, err := netip.ParseAddrPort(tt.ssServer)
			if err != nil {
				t.Fatalf("invalid SS server address: %v", err)
			}
			realTo, err := netip.ParseAddrPort(tt.clientAddr)
			if err != nil {
				t.Fatalf("invalid client address: %v", err)
			}

			bindAddr, writeAddr := normalizeSendPktAddrFamily(from, realTo)

			t.Logf("SS: %v, Client: %v", tt.ssServer, tt.clientAddr)
			t.Logf("bindAddr: %v, writeAddr: %v", bindAddr, writeAddr)
			t.Logf("Description: %s", tt.description)

			// Verify address normalization produces valid results
			// The actual socket creation will fail if the address pair is truly unsupported
			if !bindAddr.IsValid() || !writeAddr.IsValid() {
				if !tt.shouldFail {
					t.Errorf("invalid address produced: bind=%v write=%v", bindAddr, writeAddr)
				}
			}

			// Compare with main branch behavior
			mainBranchKey := from.String()
			currentBranchKey := bindAddr.String()

			t.Logf("Main branch pool key: %s", mainBranchKey)
			t.Logf("Current branch pool key: %s", currentBranchKey)

			if mainBranchKey != currentBranchKey {
				t.Logf("WARNING: Pool key mismatch - this may cause different socket reuse behavior")
			}
		})
	}
}

// TestIPv4MappedAddressHandling tests the handling of IPv4-mapped IPv6 addresses.
func TestIPv4MappedAddressHandling(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string // After Is4In6().Unmap()
	}{
		{
			name:     "Pure IPv4",
			input:    "192.168.1.1:12345",
			expected: "192.168.1.1:12345",
		},
		{
			name:     "IPv4-mapped IPv6",
			input:    "[::ffff:192.168.1.1]:12345",
			expected: "192.168.1.1:12345",
		},
		{
			name:     "Pure IPv6",
			input:    "[2001:db8::1]:12345",
			expected: "[2001:db8::1]:12345",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, err := netip.ParseAddrPort(tt.input)
			if err != nil {
				t.Fatalf("failed to parse %q: %v", tt.input, err)
			}

			result := addr
			if addr.Addr().Is4In6() {
				result = netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port())
			}

			if result.String() != tt.expected {
				t.Errorf("after Is4In6().Unmap() = %v, want %v", result.String(), tt.expected)
			}
		})
	}
}

// BenchmarkNormalizeSendPktAddrFamily benchmarks the address normalization function.
func BenchmarkNormalizeSendPktAddrFamily(b *testing.B) {
	from, _ := netip.ParseAddrPort("10.0.0.1:12345")
	to, _ := netip.ParseAddrPort("192.168.1.100:54321")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		normalizeSendPktAddrFamily(from, to)
	}
}
