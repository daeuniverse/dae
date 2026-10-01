//go:build linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"encoding/binary"
	"testing"
)

// fakeV4UDPPacket builds a minimal IPv4/UDP datagram: 20-byte IP header + 8-byte
// UDP header + 4-byte payload.
func fakeV4UDPPacket(src, dst [4]byte, sport, dport uint16) []byte {
	udp := make([]byte, 8+4)
	binary.BigEndian.PutUint16(udp[0:], sport)
	binary.BigEndian.PutUint16(udp[2:], dport)
	binary.BigEndian.PutUint16(udp[4:], uint16(len(udp)))
	binary.BigEndian.PutUint16(udp[6:], 0) // checksum

	ip := make([]byte, 20+len(udp))
	ip[0] = 0x45 // version 4, IHL 5
	binary.BigEndian.PutUint16(ip[2:], uint16(len(ip)))
	ip[8] = 64 // TTL
	ip[9] = 17 // protocol: UDP
	copy(ip[12:16], src[:])
	copy(ip[16:20], dst[:])
	copy(ip[20:], udp)
	return ip
}

func TestBuildICMPv4PortUnreachable(t *testing.T) {
	src := [4]byte{192, 168, 2, 100}
	dst := [4]byte{142, 250, 190, 20}
	pkt := fakeV4UDPPacket(src, dst, 54321, 443)

	msg, err := buildICMPv4PortUnreachable(pkt)
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
	// The quoted datagram must be the original IP header (20) + UDP header (8).
	if string(msg[8:28]) != string(pkt[0:20]) {
		t.Fatalf("quoted IP header mismatch")
	}
	if string(msg[28:36]) != string(pkt[20:28]) {
		t.Fatalf("quoted UDP header mismatch")
	}
	// ICMP checksum must be valid: a correctly checksummed message verifies to 0.
	if got := internetChecksum(msg); got != 0x0000 {
		t.Fatalf("invalid ICMP checksum: got 0x%04x, want 0x0000", got)
	}
}

func TestBuildICMPv6PortUnreachable(t *testing.T) {
	src := [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
	dst := [16]byte{0x20, 0x01, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xbe, 0x14}
	// Minimal IPv6 header (40 bytes) + 8-byte UDP header.
	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:], 54321)
	binary.BigEndian.PutUint16(udp[2:], 443)
	ip := make([]byte, 40+len(udp))
	ip[0] = 0x60 // version 6
	binary.BigEndian.PutUint16(ip[4:], uint16(len(udp)))
	ip[6] = 17 // next header: UDP
	ip[7] = 64 // hop limit
	copy(ip[8:24], src[:])
	copy(ip[24:40], dst[:])
	copy(ip[40:], udp)

	msg, err := buildICMPv6PortUnreachable(ip)
	if err != nil {
		t.Fatalf("buildICMPv6PortUnreachable: %v", err)
	}
	if len(msg) != 8+48 {
		t.Fatalf("unexpected ICMPv6 length: got %d, want %d", len(msg), 8+48)
	}
	if msg[0] != 1 || msg[1] != 4 {
		t.Fatalf("want type=1 code=4, got type=%d code=%d", msg[0], msg[1])
	}
	if string(msg[8:48]) != string(ip[0:40]) {
		t.Fatalf("quoted IPv6 header mismatch")
	}
	if string(msg[48:56]) != string(ip[40:48]) {
		t.Fatalf("quoted UDP header mismatch")
	}
}

// TestSendICMPPortUnreachableRejectsGarbage ensures the builder fails gracefully
// on packets too short to carry the headers we need to quote.
func TestSendICMPPortUnreachableRejectsGarbage(t *testing.T) {
	if _, err := buildICMPv4PortUnreachable([]byte{0x45, 0, 0, 10}); err == nil {
		t.Fatal("short IPv4 packet should error")
	}
	if _, err := buildICMPv6PortUnreachable([]byte{0x60}); err == nil {
		t.Fatal("short IPv6 packet should error")
	}
}
