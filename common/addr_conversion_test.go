/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 *
 * Unit tests for IPv4/IPv6 address family conversion
 *
 * These tests verify that ConvertAddrPortForTarget correctly handles
 * address family mismatches when sending UDP packets.
 */

package common

import (
	"net/netip"
	"testing"
)

func TestConvertAddrPortForTarget_IPv4ToIPv6(t *testing.T) {
	// IPv4 client with IPv4 target - no conversion
	ipv4Client := netip.MustParseAddrPort("192.168.1.1:12345")
	ipv4Target := netip.MustParseAddrPort("8.8.8.8:53")

	result := ConvertAddrPortForTarget(ipv4Client, ipv4Target)
	if result.Addr().Is6() {
		t.Errorf("IPv4 to IPv4 should remain IPv4, got %v", result)
	}
	if result != ipv4Client {
		t.Errorf("IPv4 to IPv4 should be unchanged, got %v", result)
	}
}

func TestConvertAddrPortForTarget_IPv6ToIPv6(t *testing.T) {
	// IPv6 client with IPv6 target - no conversion
	ipv6Client := netip.MustParseAddrPort("[240e:390::1]:12345")
	ipv6Target := netip.MustParseAddrPort("[2001:4860::1]:53")

	result := ConvertAddrPortForTarget(ipv6Client, ipv6Target)
	if !result.Addr().Is6() {
		t.Errorf("IPv6 to IPv6 should remain IPv6, got %v", result)
	}
	if result != ipv6Client {
		t.Errorf("IPv6 to IPv6 should be unchanged, got %v", result)
	}
}

func TestConvertAddrPortForTarget_IPv4ToIPv6Mapped(t *testing.T) {
	// IPv4 source with IPv6 target - should convert to IPv4-mapped IPv6
	ipv4Source := netip.MustParseAddrPort("40.99.181.130:443")
	ipv6Target := netip.MustParseAddrPort("[240e:390:a9:dd50:34fb:3697:2b2e:d14]:52215")

	result := ConvertAddrPortForTarget(ipv4Source, ipv6Target)

	// Should be IPv6 now
	if !result.Addr().Is6() {
		t.Errorf("IPv4 source with IPv6 target should convert to IPv6, got %v", result)
	}
	// Should be IPv4-mapped IPv6
	if !result.Addr().Is4In6() {
		t.Errorf("Expected IPv4-mapped IPv6 address, got %v (Is4In6: %v)", result, result.Addr().Is4In6())
	}
	// Should preserve the port
	if result.Port() != ipv4Source.Port() {
		t.Errorf("Port should be preserved, expected %d got %d", ipv4Source.Port(), result.Port())
	}
	// Unmapping should give us the original IPv4 address
	unmapped := result.Addr().Unmap()
	if unmapped != ipv4Source.Addr() {
		t.Errorf("Unmapped address %v should equal original %v", unmapped, ipv4Source.Addr())
	}
}

func TestConvertAddrPortForTarget_IPv4MappedToIPv4(t *testing.T) {
	// IPv4-mapped IPv6 source with IPv4 target - should unmap to IPv4
	ipv4mappedSource := netip.MustParseAddrPort("[::ffff:40.99.181.130]:443")
	ipv4Target := netip.MustParseAddrPort("192.168.1.1:12345")

	result := ConvertAddrPortForTarget(ipv4mappedSource, ipv4Target)

	// Should be IPv4 now
	if !result.Addr().Is4() {
		t.Errorf("IPv4-mapped source with IPv4 target should unmap to IPv4, got %v", result)
	}
	// Should not be IPv4-mapped anymore
	if result.Addr().Is4In6() {
		t.Errorf("Should not be IPv4-mapped, got %v", result)
	}
	// Unmapped should equal the original IPv4
	expectedIPv4 := netip.MustParseAddr("40.99.181.130")
	if result.Addr() != expectedIPv4 {
		t.Errorf("Expected %v, got %v", expectedIPv4, result.Addr())
	}
}

func TestConvertAddrPortForTarget_PureIPv6ToIPv4(t *testing.T) {
	// Pure IPv6 source with IPv4 target - can't convert, returns unspecified
	pureIPv6Source := netip.MustParseAddrPort("[2001:4860::1]:443")
	ipv4Target := netip.MustParseAddrPort("192.168.1.1:12345")

	result := ConvertAddrPortForTarget(pureIPv6Source, ipv4Target)

	// Should return IPv6 unspecified (can't convert pure IPv6 to IPv4)
	if !result.Addr().Is6() || result.Addr() != netip.IPv6Unspecified() {
		t.Errorf("Pure IPv6 source with IPv4 target should return IPv6 unspecified, got %v", result)
	}
}

func TestConvertAddrPortForTarget_IPv4MappedToIPv6(t *testing.T) {
	// IPv4-mapped IPv6 source with IPv6 target - should remain unchanged
	ipv4mappedSource := netip.MustParseAddrPort("[::ffff:40.99.181.130]:443")
	ipv6Target := netip.MustParseAddrPort("[240e:390::1]:12345")

	result := ConvertAddrPortForTarget(ipv4mappedSource, ipv6Target)

	// Should still be IPv4-mapped IPv6
	if !result.Addr().Is4In6() {
		t.Errorf("IPv4-mapped source with IPv6 target should remain IPv4-mapped, got %v", result)
	}
	// Should be unchanged
	if result != ipv4mappedSource {
		t.Errorf("IPv4-mapped to IPv6 should be unchanged, got %v", result)
	}
}

func TestConvertAddrPortForTarget_RealWorldScenario(t *testing.T) {
	// Real-world scenario from the bug report
	// Remote server: 40.99.181.130:443 (IPv4)
	// Client: 240e:390:a9:dd50:34fb:3697:2b2e:d14:52215 (IPv6)

	remoteServer := netip.MustParseAddrPort("40.99.181.130:443")
	client := netip.MustParseAddrPort("[240e:390:a9:dd50:34fb:3697:2b2e:d14]:52215")

	result := ConvertAddrPortForTarget(remoteServer, client)

	// Verify the conversion
	if !result.Addr().Is6() {
		t.Errorf("Should convert to IPv6 for IPv6 client, got %v", result)
	}
	if !result.Addr().Is4In6() {
		t.Errorf("Should be IPv4-mapped IPv6, got %v", result)
	}

	// Verify string representation
	expectedStr := "[::ffff:40.99.181.130]:443"
	if result.String() != expectedStr {
		t.Errorf("Expected %s, got %s", expectedStr, result.String())
	}
}

func TestConvertAddrPortForTarget_PortPreservation(t *testing.T) {
	testCases := []struct {
		name     string
		source   string
		target   string
		expected uint16
	}{
		{
			name:     "IPv4 to IPv6 preserves port",
			source:   "192.168.1.1:8080",
			target:   "[::1]:12345",
			expected: 8080,
		},
		{
			name:     "IPv6 to IPv4 preserves port",
			source:   "[::ffff:192.168.1.1]:9090",
			target:   "192.168.1.2:12345",
			expected: 9090,
		},
		{
			name:     "Same family preserves port",
			source:   "192.168.1.1:7777",
			target:   "192.168.1.2:12345",
			expected: 7777,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			source := netip.MustParseAddrPort(tc.source)
			target := netip.MustParseAddrPort(tc.target)
			result := ConvertAddrPortForTarget(source, target)

			if result.Port() != tc.expected {
				t.Errorf("Port not preserved: expected %d, got %d", tc.expected, result.Port())
			}
		})
	}
}

// BenchmarkConvertAddrPortForTarget_IPv4ToIPv6 benchmarks the conversion from IPv4 to IPv6
func BenchmarkConvertAddrPortForTarget_IPv4ToIPv6(b *testing.B) {
	source := netip.MustParseAddrPort("40.99.181.130:443")
	target := netip.MustParseAddrPort("[240e:390::1]:52215")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ConvertAddrPortForTarget(source, target)
	}
}

// BenchmarkConvertAddrPortForTarget_SameFamily benchmarks when no conversion is needed
func BenchmarkConvertAddrPortForTarget_SameFamily(b *testing.B) {
	source := netip.MustParseAddrPort("192.168.1.1:443")
	target := netip.MustParseAddrPort("8.8.8.8:53")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ConvertAddrPortForTarget(source, target)
	}
}
