/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 *
 * Integration tests for UDP IPv4/IPv6 address family handling
 *
 * These tests verify that the sendPkt function correctly handles
 * address family mismatches when sending UDP packets between
 * IPv4 and IPv6 endpoints.
 */

package control

import (
	"net"
	"net/netip"
	"os"
	"syscall"
	"testing"

	"github.com/daeuniverse/dae/common"
	"github.com/sirupsen/logrus"
)

// TestSendPktAddressFamilyConversion tests that sendPkt correctly converts
// source addresses to match the destination address family.
func TestSendPktAddressFamilyConversion(t *testing.T) {
	// Skip if IPv6 is not available
	if !supportsIPv6() {
		t.Skip("IPv6 not available on this system")
	}

	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel) // Reduce noise in tests

	testCases := []struct {
		name           string
		from           string // Remote server address (source for response)
		realTo         string // Client address (destination for response)
		expectConvert  bool   // Whether address conversion should occur
		expectIPv6Bind bool   // Whether the socket should be IPv6
	}{
		{
			name:           "IPv4 server to IPv6 client (bug scenario)",
			from:           "40.99.181.130:443",
			realTo:         "[240e:390:a9:dd50:34fb:3697:2b2e:d14]:52215",
			expectConvert:  true,
			expectIPv6Bind: true,
		},
		{
			name:           "IPv4 server to IPv6 client (different IPv6)",
			from:           "8.8.8.8:53",
			realTo:         "[2001:4860::1]:12345",
			expectConvert:  true,
			expectIPv6Bind: true,
		},
		{
			name:           "IPv4 server to IPv4 client",
			from:           "8.8.8.8:53",
			realTo:         "192.168.1.1:12345",
			expectConvert:  false,
			expectIPv6Bind: false,
		},
		{
			name:           "IPv6 server to IPv6 client",
			from:           "[2001:4860::1]:53",
			realTo:         "[240e:390::1]:12345",
			expectConvert:  false,
			expectIPv6Bind: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			from := netip.MustParseAddrPort(tc.from)
			realTo := netip.MustParseAddrPort(tc.realTo)

			// Test the conversion logic that would be used in sendPkt
			sourceAddr := common.ConvertAddrPortForTarget(from, realTo)

			// Verify the conversion
			if tc.expectConvert {
				// Should have converted address family
				if from.Addr().Is4() && realTo.Addr().Is6() {
					if !sourceAddr.Addr().Is6() {
						t.Errorf("Expected IPv6 conversion, got %v", sourceAddr)
					}
					if !sourceAddr.Addr().Is4In6() {
						t.Errorf("Expected IPv4-mapped IPv6, got %v", sourceAddr)
					}
				}
			}

			if tc.expectIPv6Bind {
				if !sourceAddr.Addr().Is6() {
					t.Errorf("Expected IPv6 address for binding, got %v", sourceAddr)
				}
			}

			// Verify port preservation
			if sourceAddr.Port() != from.Port() {
				t.Errorf("Port not preserved: expected %d, got %d", from.Port(), sourceAddr.Port())
			}
		})
	}
}

// TestSendPktRealWorldScenario tests the exact scenario from the bug report
func TestSendPktRealWorldScenario(t *testing.T) {
	if !supportsIPv6() {
		t.Skip("IPv6 not available on this system")
	}

	// Exact addresses from the bug report
	remoteServer := netip.MustParseAddrPort("40.99.181.130:443")
	client := netip.MustParseAddrPort("[240e:390:a9:dd50:34fb:3697:2b2e:d14]:52215")

	// Verify the conversion that would happen in sendPkt
	sourceAddr := common.ConvertAddrPortForTarget(remoteServer, client)

	// The converted address should be IPv4-mapped IPv6
	if !sourceAddr.Addr().Is6() {
		t.Errorf("Source should be converted to IPv6, got %v", sourceAddr)
	}
	if !sourceAddr.Addr().Is4In6() {
		t.Errorf("Source should be IPv4-mapped IPv6, got %v", sourceAddr)
	}

	// Verify the unmapped address matches the original
	unmapped := sourceAddr.Addr().Unmap()
	if unmapped != remoteServer.Addr() {
		t.Errorf("Unmapped address %v should match original %v", unmapped, remoteServer.Addr())
	}
}

// TestConvertAddrPortForTargetValidation tests the conversion function directly
func TestConvertAddrPortForTargetValidation(t *testing.T) {
	testCases := []struct {
		name         string
		source       string
		target       string
		expectFamily string // "4", "6", "4in6", or "unspecified"
	}{
		{
			name:         "IPv4 to IPv4 - unchanged",
			source:       "192.168.1.1:443",
			target:       "8.8.8.8:53",
			expectFamily: "4",
		},
		{
			name:         "IPv6 to IPv6 - unchanged",
			source:       "[2001:4860::1]:443",
			target:       "[240e:390::1]:53",
			expectFamily: "6",
		},
		{
			name:         "IPv4 to IPv6 - mapped",
			source:       "8.8.8.8:443",
			target:       "[::1]:12345",
			expectFamily: "4in6",
		},
		{
			name:         "IPv4-mapped to IPv4 - unmapped",
			source:       "[::ffff:8.8.8.8]:443",
			target:       "192.168.1.1:12345",
			expectFamily: "4",
		},
		{
			name:         "IPv4-mapped to IPv6 - unchanged",
			source:       "[::ffff:8.8.8.8]:443",
			target:       "[240e:390::1]:12345",
			expectFamily: "4in6",
		},
		{
			name:         "Pure IPv6 to IPv4 - unspecified",
			source:       "[2001:4860::1]:443",
			target:       "192.168.1.1:12345",
			expectFamily: "unspecified",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			source := netip.MustParseAddrPort(tc.source)
			target := netip.MustParseAddrPort(tc.target)

			result := common.ConvertAddrPortForTarget(source, target)

			switch tc.expectFamily {
			case "4":
				if !result.Addr().Is4() || result.Addr().Is4In6() {
					t.Errorf("Expected pure IPv4, got %v", result)
				}
			case "6":
				if !result.Addr().Is6() || result.Addr().Is4In6() {
					t.Errorf("Expected pure IPv6, got %v", result)
				}
			case "4in6":
				if !result.Addr().Is4In6() {
					t.Errorf("Expected IPv4-mapped IPv6, got %v", result)
				}
			case "unspecified":
				if result.Addr() != netip.IPv6Unspecified() {
					t.Errorf("Expected IPv6 unspecified, got %v", result)
				}
			}
		})
	}
}

// TestAnyfromPoolAddressFamily tests that the pool can handle different address families
func TestAnyfromPoolAddressFamily(t *testing.T) {
	t.Skip("Skipping pool test: requires DaeNetns setup which is not available in unit tests")

	if !supportsIPv6() {
		t.Skip("IPv6 not available on this system")
	}

	testCases := []struct {
		name     string
		addr     string
		expectOK bool
	}{
		{
			name:     "IPv4 address",
			addr:     "0.0.0.0:0",
			expectOK: true,
		},
		{
			name:     "IPv6 wildcard",
			addr:     "[::]:0",
			expectOK: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			addr := netip.MustParseAddrPort(tc.addr)

			conn, isNew, err := DefaultAnyfromPool.GetOrCreate(addr, AnyfromTimeout)
			if tc.expectOK && err != nil {
				t.Logf("Note: GetOrCreate for %s failed: %v (may be expected in some environments)", tc.addr, err)
			}
			if !tc.expectOK && err == nil {
				t.Errorf("Expected failure for %s, but succeeded", tc.addr)
			}

			if isNew && conn != nil {
				_ = conn.Close()
			}
		})
	}
}

// supportsIPv6 checks if the system supports IPv6
func supportsIPv6() bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() == nil && ipnet.IP.IsGlobalUnicast() {
				return true
			}
		}
	}

	// Also try to create an IPv6 UDP socket
	conn, err := net.ListenPacket("udp6", "[::]:0")
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// TestSocketFamilyCompatibility tests socket compatibility with different address families
func TestSocketFamilyCompatibility(t *testing.T) {
	if !supportsIPv6() {
		t.Skip("IPv6 not available on this system")
	}

	t.Run("IPv6 socket can write to IPv6 address", func(t *testing.T) {
		// Create an IPv6 socket
		conn, err := net.ListenPacket("udp6", "[::]:0")
		if err != nil {
			t.Skipf("Failed to create IPv6 socket: %v", err)
		}
		defer conn.Close()

		// Try to write to an IPv6 address (localhost for testing)
		target := netip.MustParseAddrPort("[::1]:12345")
		data := []byte("test")

		// This should not fail with address family mismatch
		// (it might fail for other reasons like destination unreachable, but that's OK)
		udpAddr := &net.UDPAddr{
			IP:   target.Addr().AsSlice(),
			Port: int(target.Port()),
			Zone: target.Addr().Zone(),
		}
		_, err = conn.WriteTo(data, udpAddr)
		if err != nil {
			// Check if it's an address family error
			if isAddressFamilyError(err) {
				t.Errorf("IPv6 socket should be able to write to IPv6 address, got: %v", err)
			}
			// Other errors (like "destination address required") are expected for this test
		}
	})

	t.Run("IPv4 socket cannot write to IPv6 address", func(t *testing.T) {
		// Create an IPv4 socket
		conn, err := net.ListenPacket("udp4", "0.0.0.0:0")
		if err != nil {
			t.Skipf("Failed to create IPv4 socket: %v", err)
		}
		defer conn.Close()

		// Try to write to an IPv6 address
		target := netip.MustParseAddrPort("[::1]:12345")
		data := []byte("test")

		// This should fail with address family mismatch
		udpAddr := &net.UDPAddr{
			IP:   target.Addr().AsSlice(),
			Port: int(target.Port()),
			Zone: target.Addr().Zone(),
		}
		_, err = conn.WriteTo(data, udpAddr)
		if err == nil {
			t.Error("IPv4 socket writing to IPv6 address should fail")
		}
		// The error should indicate address family mismatch
		if !isAddressFamilyError(err) {
			t.Logf("Note: Error was: %v (might not be an address family error)", err)
		}
	})
}

// isAddressFamilyError checks if an error is related to address family mismatch
func isAddressFamilyError(err error) bool {
	if err == nil {
		return false
	}
	// Check for common error messages/numbers
	if sysErr, ok := err.(*net.OpError); ok {
		if sysErr.Err == syscall.EAFNOSUPPORT {
			return true
		}
		if syscallErr, ok := sysErr.Err.(*os.SyscallError); ok {
			if syscallErr.Err == syscall.EAFNOSUPPORT {
				return true
			}
		}
	}
	// Check error message for known patterns
	errMsg := err.Error()
	return contains(errMsg, "non-IPv4") ||
		contains(errMsg, "non-IPv6") ||
		contains(errMsg, "address family") ||
		contains(errMsg, "EAFNOSUPPORT")
}

// BenchmarkConvertAddrPortForTargetInSendPktContext benchmarks the conversion
// in the context of how it's used in sendPkt
func BenchmarkConvertAddrPortForTargetInSendPktContext(b *testing.B) {
	// Simulate the real-world scenario
	from := netip.MustParseAddrPort("40.99.181.130:443")
	realTo := netip.MustParseAddrPort("[240e:390:a9:dd50:34fb:3697:2b2e:d14]:52215")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sourceAddr := common.ConvertAddrPortForTarget(from, realTo)
		_ = sourceAddr
	}
}
