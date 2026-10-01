//go:build linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

// TestBuildICMPv4PortUnreachable verifies the quoted header is rebuilt from the
// routing 4-tuple: the embedded IP source is the original destination (the
// rejected target) and the embedded IP destination is the client, so the
// client's QUIC stack can correlate the error with the connection it opened.
func TestBuildICMPv4PortUnreachable(t *testing.T) {
	client := netip.MustParseAddrPort("192.168.2.3:47305")
	originalDst := netip.MustParseAddrPort("1.1.1.1:443")

	msg, err := buildICMPv4PortUnreachable(client, originalDst)
	if err != nil {
		t.Fatalf("buildICMPv4PortUnreachable: %v", err)
	}
	if len(msg) != 8+28 {
		t.Fatalf("unexpected ICMP length: got %d, want %d", len(msg), 8+28)
	}
	if msg[0] != 3 || msg[1] != 3 {
		t.Fatalf("want type=3 code=3, got type=%d code=%d", msg[0], msg[1])
	}
	// RFC 792: unused field must be zero.
	if msg[4] != 0 || msg[5] != 0 || msg[6] != 0 || msg[7] != 0 {
		t.Fatalf("unused field must be zero, got %v", msg[4:8])
	}
	// Quoted IPv4 header mirrors the original datagram: src = client, dst = originalDst.
	if msg[12] != 192 || msg[13] != 168 || msg[14] != 2 || msg[15] != 3 {
		t.Fatalf("quoted IP source must be 192.168.2.3 (client), got %d.%d.%d.%d", msg[12], msg[13], msg[14], msg[15])
	}
	if msg[16] != 1 || msg[17] != 1 || msg[18] != 1 || msg[19] != 1 {
		t.Fatalf("quoted IP destination must be 1.1.1.1 (original destination), got %d.%d.%d.%d", msg[16], msg[17], msg[18], msg[19])
	}
	// Quoted UDP header: src port = client.Port(), dst port = originalDst.Port().
	if got := binary.BigEndian.Uint16(msg[28:30]); got != 47305 {
		t.Fatalf("quoted UDP source port must be 47305 (client), got %d", got)
	}
	if got := binary.BigEndian.Uint16(msg[30:32]); got != 443 {
		t.Fatalf("quoted UDP destination port must be 443 (original destination), got %d", got)
	}
	// ICMP checksum must be valid: a correctly checksummed message verifies to 0.
	if got := internetChecksum(msg); got != 0x0000 {
		t.Fatalf("invalid ICMP checksum: got 0x%04x, want 0x0000", got)
	}
}

// TestBuildICMPv6PortUnreachable mirrors the IPv4 test for the IPv6 path.
func TestBuildICMPv6PortUnreachable(t *testing.T) {
	client := netip.MustParseAddrPort("[fe80::3]:47305")
	originalDst := netip.MustParseAddrPort("[2606:4700::1111]:443")

	msg, err := buildICMPv6PortUnreachable(client, originalDst)
	if err != nil {
		t.Fatalf("buildICMPv6PortUnreachable: %v", err)
	}
	if len(msg) != 8+48 {
		t.Fatalf("unexpected ICMPv6 length: got %d, want %d", len(msg), 8+48)
	}
	if msg[0] != 1 || msg[1] != 4 {
		t.Fatalf("want type=1 code=4, got type=%d code=%d", msg[0], msg[1])
	}
	// Quoted IPv6 header (40 bytes) mirrors the original datagram: src = client, dst = originalDst.
	quoted := msg[8:48]
	if got := netip.AddrFrom16([16]byte(quoted[8:24])); got != client.Addr() {
		t.Fatalf("quoted IPv6 source must be %s (client), got %s", client.Addr(), got)
	}
	if got := netip.AddrFrom16([16]byte(quoted[24:40])); got != originalDst.Addr() {
		t.Fatalf("quoted IPv6 destination must be %s (original destination), got %s", originalDst.Addr(), got)
	}
	// Quoted UDP header: src port = client.Port(), dst port = originalDst.Port().
	if got := binary.BigEndian.Uint16(quoted[40:42]); got != 47305 {
		t.Fatalf("quoted UDP source port must be 47305 (client), got %d", got)
	}
	if got := binary.BigEndian.Uint16(quoted[42:44]); got != 443 {
		t.Fatalf("quoted UDP destination port must be 443 (original destination), got %d", got)
	}
}

// TestSendICMPPortUnreachableFamilyMismatch ensures a family mismatch between
// the client and the original destination is rejected rather than producing a
// malformed datagram.
func TestSendICMPPortUnreachableFamilyMismatch(t *testing.T) {
	client := netip.MustParseAddrPort("192.168.2.3:47305")          // IPv4
	originalDst := netip.MustParseAddrPort("[2606:4700::1111]:443") // IPv6
	if _, err := buildICMPv4PortUnreachable(client, originalDst); err == nil {
		t.Fatal("IPv4 build with IPv6 destination should error")
	}
}
