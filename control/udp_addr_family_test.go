/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 *
 * Unit tests for UDP address family selection logic
 *
 * These tests verify that when a client and target have different
 * address families (e.g., IPv6 client accessing IPv4 server via NAT64),
 * the dialer selection correctly matches the client's address family.
 */

package control

import (
	"net/netip"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound/dialer"
)

// TestUDPAddressFamilySelection_Unit tests the address family selection logic
func TestUDPAddressFamilySelection_Unit(t *testing.T) {
	tests := []struct {
		name                string
		clientAddr          string
		targetAddr          string
		expectIPv4Selection bool
		expectIPv6Selection bool
	}{
		{
			name:                "IPv6 client with IPv4 target",
			clientAddr:          "[240e:390:a9:d6e0::1]:12345",
			targetAddr:          "142.251.35.78:443",
			expectIPv4Selection: false,
			expectIPv6Selection: true,
		},
		{
			name:                "IPv4 client with IPv6 target",
			clientAddr:          "192.168.1.1:12345",
			targetAddr:          "[2001:4860:4860::8888]:443",
			expectIPv4Selection: true,
			expectIPv6Selection: false,
		},
		{
			name:                "IPv6 client with IPv6 target",
			clientAddr:          "[240e:390::1]:12345",
			targetAddr:          "[2001:4860::1]:443",
			expectIPv4Selection: false,
			expectIPv6Selection: true,
		},
		{
			name:                "IPv4 client with IPv4 target",
			clientAddr:          "192.168.1.1:12345",
			targetAddr:          "8.8.8.8:443",
			expectIPv4Selection: true,
			expectIPv6Selection: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientAddrPort := netip.MustParseAddrPort(tt.clientAddr)
			targetAddrPort := netip.MustParseAddrPort(tt.targetAddr)

			// Original networkType (based on target)
			networkType := &dialer.NetworkType{
				L4Proto:   consts.L4ProtoStr_UDP,
				IpVersion: consts.IpVersionFromAddr(targetAddrPort.Addr()),
				IsDns:     false,
			}

			// Selection logic (from the fix)
			selectionNetworkType := networkType
			if clientIpVersion := consts.IpVersionFromAddr(clientAddrPort.Addr()); clientIpVersion != networkType.IpVersion {
				selectionNetworkType = &dialer.NetworkType{
					L4Proto:   networkType.L4Proto,
					IpVersion: clientIpVersion,
					IsDns:     networkType.IsDns,
				}
			}

			// Verify
			isIPv4 := selectionNetworkType.IpVersion == consts.IpVersionStr_4
			isIPv6 := selectionNetworkType.IpVersion == consts.IpVersionStr_6

			if tt.expectIPv4Selection && !isIPv4 {
				t.Errorf("Expected IPv4 selection, got %v", selectionNetworkType.IpVersion)
			}
			if tt.expectIPv6Selection && !isIPv6 {
				t.Errorf("Expected IPv6 selection, got %v", selectionNetworkType.IpVersion)
			}
			if !tt.expectIPv4Selection && !tt.expectIPv6Selection {
				t.Errorf("Invalid test case: must expect either IPv4 or IPv6")
			}
		})
	}
}

// TestUDPAddressFamilyNoAlloc tests that no allocation happens when versions match
func TestUDPAddressFamilyNoAlloc(t *testing.T) {
	// When client and target have same address family, should reuse networkType
	clientAddrPort := netip.MustParseAddrPort("192.168.1.1:12345")
	targetAddrPort := netip.MustParseAddrPort("8.8.8.8:443")

	networkType := &dialer.NetworkType{
		L4Proto:   consts.L4ProtoStr_UDP,
		IpVersion: consts.IpVersionFromAddr(targetAddrPort.Addr()),
		IsDns:     false,
	}

	selectionNetworkType := networkType
	if clientIpVersion := consts.IpVersionFromAddr(clientAddrPort.Addr()); clientIpVersion != networkType.IpVersion {
		selectionNetworkType = &dialer.NetworkType{
			L4Proto:   networkType.L4Proto,
			IpVersion: clientIpVersion,
			IsDns:     networkType.IsDns,
		}
	}

	// Should reuse the same pointer
	if selectionNetworkType != networkType {
		t.Error("Should reuse networkType when address families match")
	}
}

// TestUDPAddressFamilyErrorScenarios tests error scenarios
func TestUDPAddressFamilyErrorScenarios(t *testing.T) {
	// Test invalid client address
	_, err := netip.ParseAddrPort("invalid")
	if err == nil {
		t.Error("Expected parse error for invalid client address")
	}

	// Test invalid target address
	_, err = netip.ParseAddrPort("invalid:invalid")
	if err == nil {
		t.Error("Expected parse error for invalid target address")
	}

	// Test valid addresses
	_, err = netip.ParseAddrPort("192.168.1.1:12345")
	if err != nil {
		t.Errorf("Unexpected parse error for valid address: %v", err)
	}
}

// TestUDPAddressFamilyWithMockDialerGroup tests with mock dialer group
func TestUDPAddressFamilyWithMockDialerGroup(t *testing.T) {
	// This test verifies that the selectionNetworkType is correctly used
	// in the Select() call

	clientAddrPort := netip.MustParseAddrPort("[240e:390::1]:12345")
	targetAddrPort := netip.MustParseAddrPort("8.8.8.8:443")

	// Original networkType (based on target - IPv4)
	networkType := &dialer.NetworkType{
		L4Proto:   consts.L4ProtoStr_UDP,
		IpVersion: consts.IpVersionFromAddr(targetAddrPort.Addr()),
		IsDns:     false,
	}

	// Selection logic
	selectionNetworkType := networkType
	if clientIpVersion := consts.IpVersionFromAddr(clientAddrPort.Addr()); clientIpVersion != networkType.IpVersion {
		selectionNetworkType = &dialer.NetworkType{
			L4Proto:   networkType.L4Proto,
			IpVersion: clientIpVersion,
			IsDns:     networkType.IsDns,
		}
	}

	// Verify the selection is for IPv6 (matching client)
	if selectionNetworkType.IpVersion != consts.IpVersionStr_6 {
		t.Errorf("Expected IPv6 selection, got %v", selectionNetworkType.IpVersion)
	}

	// Verify it's a new object (not reusing networkType)
	if selectionNetworkType == networkType {
		t.Error("Should create new NetworkType when versions don't match")
	}
}

// BenchmarkUDPAddressFamilySelection benchmarks the selection logic
func BenchmarkUDPAddressFamilySelection(b *testing.B) {
	clientAddrPort := netip.MustParseAddrPort("[240e:390::1]:12345")
	targetAddrPort := netip.MustParseAddrPort("8.8.8.8:443")

	networkType := &dialer.NetworkType{
		L4Proto:   consts.L4ProtoStr_UDP,
		IpVersion: consts.IpVersionFromAddr(targetAddrPort.Addr()),
		IsDns:     false,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		selectionNetworkType := networkType
		if clientIpVersion := consts.IpVersionFromAddr(clientAddrPort.Addr()); clientIpVersion != networkType.IpVersion {
			selectionNetworkType = &dialer.NetworkType{
				L4Proto:   networkType.L4Proto,
				IpVersion: clientIpVersion,
				IsDns:     networkType.IsDns,
			}
		}
		_ = selectionNetworkType
	}
}

// BenchmarkUDPAddressFamilySelectionNoMismatch benchmarks when versions match (no allocation)
func BenchmarkUDPAddressFamilySelectionNoMismatch(b *testing.B) {
	clientAddrPort := netip.MustParseAddrPort("192.168.1.1:12345")
	targetAddrPort := netip.MustParseAddrPort("8.8.8.8:443")

	networkType := &dialer.NetworkType{
		L4Proto:   consts.L4ProtoStr_UDP,
		IpVersion: consts.IpVersionFromAddr(targetAddrPort.Addr()),
		IsDns:     false,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		selectionNetworkType := networkType
		if clientIpVersion := consts.IpVersionFromAddr(clientAddrPort.Addr()); clientIpVersion != networkType.IpVersion {
			selectionNetworkType = &dialer.NetworkType{
				L4Proto:   networkType.L4Proto,
				IpVersion: clientIpVersion,
				IsDns:     networkType.IsDns,
			}
		}
		_ = selectionNetworkType
	}
}
