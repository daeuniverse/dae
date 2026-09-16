/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net/netip"
	"testing"
)

// Audit regression: a dual-stack upstream that answers over an IPv4-mapped IPv6
// socket reports ::ffff:a.b.c.d, which denotes the same endpoint as a.b.c.d.
// The raw comparison flagged every such reply as a source mismatch.
func TestUDPResponseSourceMismatchNormalisesMappedAddresses(t *testing.T) {
	for _, tc := range []struct {
		name   string
		from   string
		target string
		want   bool
	}{
		{"exact ipv4", "127.0.0.1:5335", "127.0.0.1:5335", false},
		{"mapped ipv4", "[::ffff:127.0.0.1]:5335", "127.0.0.1:5335", false},
		{"mapped ipv4 reverse", "127.0.0.1:5335", "[::ffff:127.0.0.1]:5335", false},
		{"same address, different port", "127.0.0.1:5336", "127.0.0.1:5335", true},
		{"different address", "127.0.0.2:5335", "127.0.0.1:5335", true},
		{"mapped address, different port", "[::ffff:127.0.0.1]:1", "127.0.0.1:5335", true},
		{"genuine ipv6", "[2001:db8::1]:5335", "[2001:db8::1]:5335", false},
	} {
		from := netip.MustParseAddrPort(tc.from)
		target := netip.MustParseAddrPort(tc.target)
		if got := udpResponseSourceMismatch(from, target); got != tc.want {
			t.Errorf("%s: udpResponseSourceMismatch(%v, %v) = %v, want %v", tc.name, from, target, got, tc.want)
		}
	}

	// Invalid addresses stay "unknown", never a mismatch.
	if udpResponseSourceMismatch(netip.AddrPort{}, netip.MustParseAddrPort("127.0.0.1:53")) {
		t.Error("an invalid source address must not be reported as a mismatch")
	}
}
