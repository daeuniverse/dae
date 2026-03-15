/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net/netip"
	"testing"
)

// TestIPv6ServerToIPv4ClientIssue tests the specific case where IPv6 SS server
// sends response to IPv4 client. This is a known edge case that may fail.
func TestIPv6ServerToIPv4ClientIssue(t *testing.T) {
	// Scenario: SS server uses IPv6, client uses IPv4
	// Response from SS server has source = IPv6 address, destination = client IPv4

	ssServer, _ := netip.ParseAddrPort("[2001:db8::1]:8388")
	clientAddr, _ := netip.ParseAddrPort("192.168.1.100:12345")

	t.Logf("SS Server (response source): %v", ssServer)
	t.Logf("Client (response destination): %v", clientAddr)

	// Current branch behavior
	bindAddr, writeAddr := normalizeSendPktAddrFamily(ssServer, clientAddr)

	t.Logf("bindAddr after normalize: %v", bindAddr)
	t.Logf("writeAddr after normalize: %v", writeAddr)

	// Check if unsupported
	unsupported := isUnsupportedTransparentUDPPair(bindAddr, writeAddr)
	t.Logf("isUnsupportedTransparentUDPPair: %v", unsupported)

	// Main branch would use:
	mainBranchKey := ssServer.String()
	t.Logf("Main branch pool key: %s", mainBranchKey)

	// The issue: writeAddr gets converted to IPv4-mapped IPv6
	// bindAddr: [2001:db8::1]:8388 (IPv6)
	// writeAddr: [::ffff:192.168.1.100]:12345 (IPv4-mapped IPv6)
	//
	// isUnsupportedTransparentUDPPair checks: bindAddr.Is4() && writeAddr.Is6()
	// = false && true = false (not considered unsupported)
	//
	// But this is problematic because we're trying to bind to IPv6 and write to IPv4

	if bindAddr.Addr().Is6() && writeAddr.Addr().Is4In6() {
		t.Log("WARNING: IPv6 bind with IPv4-mapped IPv6 write - may fail")
		t.Log("This case should unmap writeAddr to pure IPv4")
	}
}

// TestFullConeNATKeyDifference tests pool key differences between main and current branch.
func TestFullConeNATKeyDifference(t *testing.T) {
	tests := []struct {
		name             string
		from             string
		realTo           string
		mainBranchKey    string
		currentBranchKey string
		different        bool
	}{
		{
			name:             "Pure IPv4",
			from:             "10.0.0.1:8388",
			realTo:           "192.168.1.100:12345",
			mainBranchKey:    "10.0.0.1:8388",
			currentBranchKey: "10.0.0.1:8388",
			different:        false,
		},
		{
			name:             "IPv4-mapped from",
			from:             "[::ffff:10.0.0.1]:8388",
			realTo:           "192.168.1.100:12345",
			mainBranchKey:    "[::ffff:10.0.0.1]:8388",
			currentBranchKey: "10.0.0.1:8388",
			different:        true,
		},
		{
			name:             "IPv4-mapped to",
			from:             "10.0.0.1:8388",
			realTo:           "[::ffff:192.168.1.100]:12345",
			mainBranchKey:    "10.0.0.1:8388",
			currentBranchKey: "10.0.0.1:8388",
			different:        false,
		},
		{
			name:             "Both IPv4-mapped",
			from:             "[::ffff:10.0.0.1]:8388",
			realTo:           "[::ffff:192.168.1.100]:12345",
			mainBranchKey:    "[::ffff:10.0.0.1]:8388",
			currentBranchKey: "10.0.0.1:8388",
			different:        true,
		},
		{
			name:             "Pure IPv6",
			from:             "[2001:db8::1]:8388",
			realTo:           "[2001:db8::100]:12345",
			mainBranchKey:    "[2001:db8::1]:8388",
			currentBranchKey: "[2001:db8::1]:8388",
			different:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			from, _ := netip.ParseAddrPort(tt.from)
			realTo, _ := netip.ParseAddrPort(tt.realTo)

			// Current branch
			bindAddr, _ := normalizeSendPktAddrFamily(from, realTo)
			currentKey := bindAddr.String()

			// Main branch
			mainKey := from.String()

			if mainKey != currentKey {
				t.Logf("KEY MISMATCH!")
				t.Logf("  main:  %s", mainKey)
				t.Logf("  current: %s", currentKey)
			}

			if mainKey != tt.mainBranchKey {
				t.Errorf("mainBranchKey = %s, want %s", mainKey, tt.mainBranchKey)
			}
			if currentKey != tt.currentBranchKey {
				t.Errorf("currentBranchKey = %s, want %s", currentKey, tt.currentBranchKey)
			}
		})
	}
}

// TestStunLikeResponseFlow simulates STUN response flow in SS proxy mode.
func TestStunLikeResponseFlow(t *testing.T) {
	scenarios := []struct {
		name          string
		ssServerAddr  string // Address as seen by dae after SS decryption
		clientAddr    string // Original client address
		expectSuccess bool
		reason        string
	}{
		{
			name:          "IPv4 SS to IPv4 client",
			ssServerAddr:  "10.0.0.1:8388",
			clientAddr:    "192.168.1.100:54321",
			expectSuccess: true,
			reason:        "Both IPv4 - straightforward case",
		},
		{
			name:          "IPv4 SS to IPv4-mapped IPv6 client",
			ssServerAddr:  "10.0.0.1:8388",
			clientAddr:    "[::ffff:192.168.1.100]:54321",
			expectSuccess: true,
			reason:        "Client addr gets unmapped to IPv4",
		},
		{
			name:          "IPv4 SS to pure IPv6 client",
			ssServerAddr:  "10.0.0.1:8388",
			clientAddr:    "[2001:db8::100]:54321",
			expectSuccess: true, // PATCH: Now supported via IPv6 wildcard bind
			reason:        "IPv4 bind promoted to [::]:port for IPv6 write",
		},
		{
			name:          "IPv6 SS to IPv4 client",
			ssServerAddr:  "[2001:db8::1]:8388",
			clientAddr:    "192.168.1.100:54321",
			expectSuccess: true, // PATCH: Now supported via IPv4-mapped write
			reason:        "IPv4 write converted to IPv4-mapped IPv6",
		},
		{
			name:          "IPv6 SS to IPv6 client",
			ssServerAddr:  "[2001:db8::1]:8388",
			clientAddr:    "[2001:db8::100]:54321",
			expectSuccess: true,
			reason:        "Both IPv6 - should work",
		},
	}

	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			from, _ := netip.ParseAddrPort(sc.ssServerAddr)
			realTo, _ := netip.ParseAddrPort(sc.clientAddr)

			t.Logf("SS Server: %v", sc.ssServerAddr)
			t.Logf("Client: %v", sc.clientAddr)
			t.Logf("Reason: %s", sc.reason)

			bindAddr, writeAddr := normalizeSendPktAddrFamily(from, realTo)
			unsupported := isUnsupportedTransparentUDPPair(bindAddr, writeAddr)

			t.Logf("  bindAddr: %v", bindAddr)
			t.Logf("  writeAddr: %v", writeAddr)
			t.Logf("  unsupported: %v", unsupported)

			success := !unsupported
			if success != sc.expectSuccess {
				t.Errorf("success = %v, want %v (reason: %s)", success, sc.expectSuccess, sc.reason)
			}

			// Additional check for IPv6 + IPv4 case
			if from.Addr().Is6() && realTo.Addr().Is4() {
				if writeAddr.Addr().Is4() {
					t.Log("  Note: writeAddr was unmaped to IPv4")
				} else if writeAddr.Addr().Is4In6() {
					t.Log("  WARNING: writeAddr is still IPv4-mapped IPv6 - this may cause issues")
				}
			}
		})
	}
}
