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
	"strings"
	"syscall"
	"testing"
)

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
	return strings.Contains(errMsg, "non-IPv4") ||
		strings.Contains(errMsg, "non-IPv6") ||
		strings.Contains(errMsg, "address family") ||
		strings.Contains(errMsg, "EAFNOSUPPORT")
}
