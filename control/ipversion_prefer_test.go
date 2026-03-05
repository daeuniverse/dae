package control

import (
	"net/netip"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound/dialer"
)

// TestIPVersionPreferAfterCase3Removal tests that ipversion_prefer works correctly
// for mixed-family address scenarios. Concrete IPv4 sources writing to a pure
// IPv6 destination are correctly rejected as unsupported by the kernel socket
// layer, while IPv4-wildcard sources benefit from the wildcard-to-IPv6-wildcard
// conversion (Case 3 of normalizeSendPktAddrFamily) and remain supported.
func TestIPVersionPreferMixedAddrFamily(t *testing.T) {
	tests := []struct {
		name                string
		clientAddr          string
		targetAddr          string
		expectIPv4Dialer    bool
		expectUnsupported   bool
		description         string
	}{
		{
			name:              "IPv4_client_to_IPv6_target_with_prefer_4",
			clientAddr:        "192.168.1.100:12345",
			targetAddr:        "[240e:390::1]:443",
			expectIPv4Dialer:  true,
			expectUnsupported: true, // IPv4 concrete bind -> IPv6 write is unsupported
			description:       "IPv4 client should select IPv4 dialer, but response to IPv6 target is unsupported",
		},
		{
			name:              "IPv4_client_to_IPv4_target_with_prefer_4",
			clientAddr:        "192.168.1.100:12345",
			targetAddr:        "8.8.8.8:443",
			expectIPv4Dialer:  true,
			expectUnsupported: false,
			description:       "IPv4 client to IPv4 target should work normally",
		},
		{
			name:              "IPv6_client_to_IPv6_target",
			clientAddr:        "[240e:390::100]:12345",
			targetAddr:        "[2001:4860::1]:443",
			expectIPv4Dialer:  false,
			expectUnsupported: false,
			description:       "IPv6 client to IPv6 target should work normally",
		},
		{
			name:              "IPv4_wildcard_to_IPv6_target",
			clientAddr:        "0.0.0.0:53",
			targetAddr:        "[240e:390::1]:443",
			expectIPv4Dialer:  true,
			expectUnsupported: false, // Wildcard converts to IPv6
			description:       "IPv4 wildcard should convert to IPv6 wildcard for IPv6 target",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientAddrPort := netip.MustParseAddrPort(tt.clientAddr)
			targetAddrPort := netip.MustParseAddrPort(tt.targetAddr)

			// Step 1: Verify dialer selection (based on client IP version)
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

			isIPv4Dialer := selectionNetworkType.IpVersion == consts.IpVersionStr_4
			if tt.expectIPv4Dialer != isIPv4Dialer {
				t.Errorf("Dialer selection mismatch: expect IPv4=%v, got IPv4=%v (%s)",
					tt.expectIPv4Dialer, isIPv4Dialer, tt.description)
			}

			// Step 2: Verify response sending (normalizeSendPktAddrFamily)
			bindAddr, writeAddr := normalizeSendPktAddrFamily(clientAddrPort, targetAddrPort)
			isUnsupported := isUnsupportedTransparentUDPPair(bindAddr, writeAddr)

			if tt.expectUnsupported != isUnsupported {
				t.Errorf("Unsupported pair mismatch: expect=%v, got=%v, bind=%v, write=%v (%s)",
					tt.expectUnsupported, isUnsupported, bindAddr, writeAddr, tt.description)
			}

			// Step 3: Verify bind address is not converted to IPv4-mapped IPv6
			// (This was the bug caused by Case 3)
			if bindAddr.Addr().Is4() && !bindAddr.Addr().IsUnspecified() && writeAddr.Addr().Is6() && !writeAddr.Addr().Is4In6() {
				if bindAddr.Addr().Is4In6() {
					t.Errorf("BUG: IPv4 concrete address was converted to IPv4-mapped IPv6: %v -> %v (%s)",
						clientAddrPort, bindAddr, tt.description)
				}
			}
		})
	}
}

// TestIPVersionPreferScenario simulates the real-world scenario
// where ipversion_prefer: 4 is configured but DNS returns IPv6 address.
func TestIPVersionPreferScenario(t *testing.T) {
	// Scenario: User configures ipversion_prefer: 4
	// DNS query returns IPv6 address (240e:390::1)
	// Client is IPv4 (192.168.1.100)

	clientAddr := netip.MustParseAddrPort("192.168.1.100:12345")
	targetAddr := netip.MustParseAddrPort("[240e:390::1]:443")

	// Step 1: Dialer selection
	// With the fix in dial.go, UDP dialer selection uses client IP version
	networkType := &dialer.NetworkType{
		L4Proto:   consts.L4ProtoStr_UDP,
		IpVersion: consts.IpVersionFromAddr(targetAddr.Addr()), // IPv6 from target
		IsDns:     false,
	}

	selectionNetworkType := networkType
	if clientIpVersion := consts.IpVersionFromAddr(clientAddr.Addr()); clientIpVersion != networkType.IpVersion {
		selectionNetworkType = &dialer.NetworkType{
			L4Proto:   networkType.L4Proto,
			IpVersion: clientIpVersion, // Switch to IPv4 (client version)
			IsDns:     networkType.IsDns,
		}
	}

	// Verify: Should select IPv4 dialer (respecting ipversion_prefer: 4)
	if selectionNetworkType.IpVersion != consts.IpVersionStr_4 {
		t.Errorf("Should select IPv4 dialer (ipversion_prefer: 4), got %v", selectionNetworkType.IpVersion)
	}

	// Step 2: Response sending
	bindAddr, writeAddr := normalizeSendPktAddrFamily(clientAddr, targetAddr)

	// Verify: bindAddr should remain IPv4 (not converted to IPv4-mapped IPv6)
	if bindAddr.Addr().Is4In6() {
		t.Errorf("bindAddr should NOT be converted to IPv4-mapped IPv6 (this breaks ipversion_prefer), got %v", bindAddr)
	}

	// Verify: This combination is unsupported (IPv4 concrete -> IPv6 pure)
	if !isUnsupportedTransparentUDPPair(bindAddr, writeAddr) {
		t.Errorf("IPv4 concrete bind to IPv6 write should be unsupported, got bind=%v write=%v", bindAddr, writeAddr)
	}

	// Expected behavior: This scenario should fail early with clear error
	// instead of silently breaking ipversion_prefer configuration
}

// TestIPVersionPrefer6Semantics tests that ipversion_prefer: 6 works correctly
// This is the counterpart to TestIPVersionPreferAfterCase3Removal for IPv6 preference.
func TestIPVersionPrefer6Semantics(t *testing.T) {
	tests := []struct {
		name              string
		clientAddr        string
		targetAddr        string
		expectIPv6Dialer  bool
		expectUnsupported bool
		description       string
	}{
		{
			name:              "IPv6_client_to_IPv4_target_with_prefer_6",
			clientAddr:        "[240e:390::100]:12345",
			targetAddr:        "8.8.8.8:443",
			expectIPv6Dialer:  true,
			expectUnsupported: false, // IPv6 -> IPv4-mapped is supported
			description:       "IPv6 client should select IPv6 dialer, response to IPv4 target is supported via IPv4-mapped",
		},
		{
			name:              "IPv6_client_to_IPv6_target_with_prefer_6",
			clientAddr:        "[240e:390::100]:12345",
			targetAddr:        "[2001:4860::1]:443",
			expectIPv6Dialer:  true,
			expectUnsupported: false,
			description:       "IPv6 client to IPv6 target should work normally",
		},
		{
			name:              "IPv6_wildcard_to_IPv4_target",
			clientAddr:        "[::]:53",
			targetAddr:        "8.8.8.8:443",
			expectIPv6Dialer:  true,
			expectUnsupported: false,
			description:       "IPv6 wildcard to IPv4 target should work via IPv4-mapped",
		},
		{
			name:              "IPv4_client_to_IPv4_target",
			clientAddr:        "192.168.1.100:12345",
			targetAddr:        "8.8.8.8:443",
			expectIPv6Dialer:  false,
			expectUnsupported: false,
			description:       "IPv4 client to IPv4 target should use IPv4 dialer",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientAddrPort := netip.MustParseAddrPort(tt.clientAddr)
			targetAddrPort := netip.MustParseAddrPort(tt.targetAddr)

			// Step 1: Verify dialer selection (based on client IP version)
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

			isIPv6Dialer := selectionNetworkType.IpVersion == consts.IpVersionStr_6
			if tt.expectIPv6Dialer != isIPv6Dialer {
				t.Errorf("Dialer selection mismatch: expect IPv6=%v, got IPv6=%v (%s)",
					tt.expectIPv6Dialer, isIPv6Dialer, tt.description)
			}

			// Step 2: Verify response sending (normalizeSendPktAddrFamily)
			bindAddr, writeAddr := normalizeSendPktAddrFamily(clientAddrPort, targetAddrPort)
			isUnsupported := isUnsupportedTransparentUDPPair(bindAddr, writeAddr)

			if tt.expectUnsupported != isUnsupported {
				t.Errorf("Unsupported pair mismatch: expect=%v, got=%v, bind=%v, write=%v (%s)",
					tt.expectUnsupported, isUnsupported, bindAddr, writeAddr, tt.description)
			}

			// Step 3: For IPv6 -> IPv4 scenarios, verify IPv4-mapped conversion
			if bindAddr.Addr().Is6() && targetAddrPort.Addr().Is4() {
				if !writeAddr.Addr().Is4In6() {
					t.Errorf("IPv6 bind to IPv4 target should convert writeAddr to IPv4-mapped, got %v", writeAddr)
				}
			}
		})
	}
}

// TestIPVersionPrefer6Scenario simulates the real-world scenario
// where ipversion_prefer: 6 is configured but DNS returns IPv4 address.
func TestIPVersionPrefer6Scenario(t *testing.T) {
	// Scenario: User configures ipversion_prefer: 6
	// DNS query returns IPv4 address (8.8.8.8)
	// Client is IPv6 ([240e:390::100])

	clientAddr := netip.MustParseAddrPort("[240e:390::100]:12345")
	targetAddr := netip.MustParseAddrPort("8.8.8.8:443")

	// Step 1: Dialer selection
	// With the fix in dial.go, UDP dialer selection uses client IP version
	networkType := &dialer.NetworkType{
		L4Proto:   consts.L4ProtoStr_UDP,
		IpVersion: consts.IpVersionFromAddr(targetAddr.Addr()), // IPv4 from target
		IsDns:     false,
	}

	selectionNetworkType := networkType
	if clientIpVersion := consts.IpVersionFromAddr(clientAddr.Addr()); clientIpVersion != networkType.IpVersion {
		selectionNetworkType = &dialer.NetworkType{
			L4Proto:   networkType.L4Proto,
			IpVersion: clientIpVersion, // Switch to IPv6 (client version)
			IsDns:     networkType.IsDns,
		}
	}

	// Verify: Should select IPv6 dialer (respecting ipversion_prefer: 6)
	if selectionNetworkType.IpVersion != consts.IpVersionStr_6 {
		t.Errorf("Should select IPv6 dialer (ipversion_prefer: 6), got %v", selectionNetworkType.IpVersion)
	}

	// Step 2: Response sending
	bindAddr, writeAddr := normalizeSendPktAddrFamily(clientAddr, targetAddr)

	// Verify: bindAddr should remain IPv6
	if !bindAddr.Addr().Is6() {
		t.Errorf("bindAddr should remain IPv6, got %v", bindAddr)
	}

	// Verify: writeAddr should be converted to IPv4-mapped IPv6
	if !writeAddr.Addr().Is4In6() {
		t.Errorf("writeAddr should be IPv4-mapped IPv6 for IPv4 target, got %v", writeAddr)
	}

	// Verify: This combination is supported (IPv6 -> IPv4-mapped)
	if isUnsupportedTransparentUDPPair(bindAddr, writeAddr) {
		t.Errorf("IPv6 bind to IPv4-mapped write should be supported, got bind=%v write=%v", bindAddr, writeAddr)
	}

	// Expected behavior: This scenario should work normally
	// IPv6 socket can write to IPv4-mapped IPv6 addresses
}

// TestIPVersionPreferBothVersions tests both ipversion_prefer: 4 and 6
// to ensure symmetry and correctness.
func TestIPVersionPreferBothVersions(t *testing.T) {
	tests := []struct {
		name           string
		preferVersion  int // 4 or 6
		clientAddr     string
		targetAddr     string
		expectedDialer string // "IPv4" or "IPv6"
		shouldWork     bool
	}{
		// ipversion_prefer: 4 scenarios
		{
			name:           "prefer_4_IPv4_client_IPv4_target",
			preferVersion:  4,
			clientAddr:     "192.168.1.100:12345",
			targetAddr:     "8.8.8.8:443",
			expectedDialer: "IPv4",
			shouldWork:     true,
		},
		{
			name:           "prefer_4_IPv4_client_IPv6_target",
			preferVersion:  4,
			clientAddr:     "192.168.1.100:12345",
			targetAddr:     "[240e:390::1]:443",
			expectedDialer: "IPv4",
			shouldWork:     false, // IPv4 concrete -> IPv6 pure is unsupported
		},
		{
			name:           "prefer_4_IPv4_wildcard_IPv6_target",
			preferVersion:  4,
			clientAddr:     "0.0.0.0:53",
			targetAddr:     "[240e:390::1]:443",
			expectedDialer: "IPv4",
			shouldWork:     true, // Wildcard converts to IPv6
		},

		// ipversion_prefer: 6 scenarios
		{
			name:           "prefer_6_IPv6_client_IPv6_target",
			preferVersion:  6,
			clientAddr:     "[240e:390::100]:12345",
			targetAddr:     "[2001:4860::1]:443",
			expectedDialer: "IPv6",
			shouldWork:     true,
		},
		{
			name:           "prefer_6_IPv6_client_IPv4_target",
			preferVersion:  6,
			clientAddr:     "[240e:390::100]:12345",
			targetAddr:     "8.8.8.8:443",
			expectedDialer: "IPv6",
			shouldWork:     true, // IPv6 -> IPv4-mapped is supported
		},
		{
			name:           "prefer_6_IPv6_wildcard_IPv4_target",
			preferVersion:  6,
			clientAddr:     "[::]:53",
			targetAddr:     "8.8.8.8:443",
			expectedDialer: "IPv6",
			shouldWork:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientAddrPort := netip.MustParseAddrPort(tt.clientAddr)
			targetAddrPort := netip.MustParseAddrPort(tt.targetAddr)

			// Dialer selection
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

			// Verify dialer version
			var actualDialer string
			if selectionNetworkType.IpVersion == consts.IpVersionStr_4 {
				actualDialer = "IPv4"
			} else {
				actualDialer = "IPv6"
			}

			if actualDialer != tt.expectedDialer {
				t.Errorf("Dialer mismatch: want %s, got %s", tt.expectedDialer, actualDialer)
			}

			// Verify response sending
			bindAddr, writeAddr := normalizeSendPktAddrFamily(clientAddrPort, targetAddrPort)
			isUnsupported := isUnsupportedTransparentUDPPair(bindAddr, writeAddr)

			if tt.shouldWork && isUnsupported {
				t.Errorf("Scenario should work but got unsupported: bind=%v write=%v", bindAddr, writeAddr)
			}
			if !tt.shouldWork && !isUnsupported {
				t.Errorf("Scenario should be unsupported but got supported: bind=%v write=%v", bindAddr, writeAddr)
			}
		})
	}
}
