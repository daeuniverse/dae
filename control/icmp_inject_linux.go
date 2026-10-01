//go:build linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// rejectIcmpRateWindow / rejectIcmpRateMax bound the number of ICMP
// port-unreachable replies we emit per client within a sliding window. Past the
// budget we silently drop the original packet, mirroring the silent behaviour
// of the "block" action. This prevents an ICMP storm (and the associated
// control-plane cost) when a rejected destination is hammered, and matches the
// backpressure intent of sing-box's reject (method: default) action.
const (
	rejectIcmpRateWindow = 30 * time.Second
	rejectIcmpRateMax    = 50
)

type rejectRateBucket struct {
	count int
	start time.Time
}

var rejectRateBuckets sync.Map // netip.AddrPort.String() -> *rejectRateBucket

// rejectAllowed reports whether an ICMP port-unreachable may still be sent to
// client within the per-client budget. It is safe for concurrent use.
func rejectAllowed(client netip.AddrPort) bool {
	now := time.Now()
	key := client.String()
	if v, ok := rejectRateBuckets.Load(key); ok {
		b := v.(*rejectRateBucket)
		if now.Sub(b.start) <= rejectIcmpRateWindow {
			if b.count >= rejectIcmpRateMax {
				return false
			}
			b.count++
			return true
		}
	}
	rejectRateBuckets.Store(key, &rejectRateBucket{count: 1, start: now})
	return true
}

// sendICMPPortUnreachable injects an ICMP Destination Port Unreachable (IPv4,
// type 3 / code 3) or ICMPv6 Port Unreachable (IPv6, type 1 / code 4) back to
// the client, quoting the original packet's IP and UDP headers so the client's
// QUIC stack correlates the error and immediately falls back to TCP (RFC 9000
// §9.3 / RFC 792 / RFC 4443).
//
// The ICMP source is the dae host's own egress address, chosen by the kernel
// from the route to the client. This is sufficient: QUIC associates the ICMP
// error with a connection by the embedded original-datagram header (the quoted
// IP/UDP tuple), not by the ICMP message's own source address. Spoofing the
// original destination as the source would also be valid but requires
// IP_TRANSPARENT and reverse-path-filter care, so it is intentionally left as a
// follow-up.
func sendICMPPortUnreachable(data []byte, client netip.AddrPort) error {
	if len(data) < 1 {
		return errors.New("icmp_inject: empty packet")
	}
	// The control plane receives the full L2 frame from the eBPF handoff, so the
	// IP header does not necessarily start at offset 0. Skip the link-layer
	// header (14 bytes for plain Ethernet, or 18/22 with 802.1Q/802.1ad VLAN
	// tags) before reading the IP version. This matches dae's
	// controlPlaneCore.linkHdrLen, which returns consts.LinkHdrLen_Ethernet (14)
	// for "ether" interfaces.
	l2 := linkHeaderLen(data)
	if l2 > 0 {
		if l2 >= len(data) {
			return errors.New("icmp_inject: packet shorter than link header")
		}
		data = data[l2:]
	}
	version := data[0] >> 4
	switch version {
	case 4:
		return sendICMPv4PortUnreachable(data, client)
	case 6:
		return sendICMPv6PortUnreachable(data, client)
	default:
		return fmt.Errorf("icmp_inject: unsupported IP version %d (after skipping %d-byte link header)", version, l2)
	}
}

// linkHeaderLen returns the number of leading bytes that belong to the
// link-layer (Ethernet) header, so the caller can reach the IP header. It
// inspects the EtherType field: a plain Ethernet frame is 14 bytes, and VLAN
// tagging (802.1Q / 802.1ad) adds 4 bytes per tag. If the buffer already starts
// with a valid-looking IP header (no L2), it returns 0.
func linkHeaderLen(data []byte) int {
	if len(data) < 14 {
		return 0
	}
	// Already at the IP layer? (IPv4 with a sane IHL, or IPv6.)
	v := data[0] >> 4
	if (v == 4 && data[0]&0x0f >= 5) || v == 6 {
		return 0
	}
	ethType := binary.BigEndian.Uint16(data[12:14])
	switch ethType {
	case 0x0800, 0x86dd: // IPv4 / IPv6
		return 14
	case 0x8100, 0x88a8: // 802.1Q / 802.1ad VLAN
		if len(data) >= 18 {
			inner := binary.BigEndian.Uint16(data[16:18])
			if inner == 0x0800 || inner == 0x86dd {
				return 18
			}
			if len(data) >= 22 { // stacked (QinQ) tag
				inner2 := binary.BigEndian.Uint16(data[20:22])
				if inner2 == 0x0800 || inner2 == 0x86dd {
					return 22
				}
			}
		}
	}
	// Unknown/edge case: fall back to the Ethernet minimum, which is also what
	// dae's linkHdrLen returns for "ether".
	return 14
}

func sendICMPv4PortUnreachable(data []byte, client netip.AddrPort) error {
	msg, err := buildICMPv4PortUnreachable(data)
	if err != nil {
		return err
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_ICMP)
	if err != nil {
		return fmt.Errorf("icmp_inject: socket: %w", err)
	}
	defer unix.Close(fd)

	sa := &unix.SockaddrInet4{}
	sa.Addr = client.Addr().As4()
	if err := unix.Sendto(fd, msg, 0, sa); err != nil {
		return fmt.Errorf("icmp_inject: sendto: %w", err)
	}
	return nil
}

// buildICMPv4PortUnreachable constructs the ICMPv4 Destination Port
// Unreachable message (RFC 792) without sending it. The message quotes the
// original IP header and the first 8 bytes of the original payload (the UDP
// header) so the client can correlate the error with its sent packet.
func buildICMPv4PortUnreachable(data []byte) ([]byte, error) {
	if len(data) < 20 {
		return nil, fmt.Errorf("icmp_inject: packet too short for IPv4 header: %d", len(data))
	}
	ihl := int(data[0]&0x0f) * 4
	if ihl < 20 {
		ihl = 20
	}
	quoteLen := ihl + 8 // original IP header + first 8 bytes of original payload (UDP header)
	if quoteLen > len(data) {
		quoteLen = len(data)
	}
	quoted := data[:quoteLen]

	// ICMP message: type(1) code(1) checksum(2) unused(4) + quoted datagram.
	msg := make([]byte, 8+len(quoted))
	msg[0] = 3 // type: destination unreachable
	msg[1] = 3 // code: port unreachable
	// msg[2:4] checksum, msg[4:8] unused (zero) are already zero.
	copy(msg[8:], quoted)
	cs := internetChecksum(msg)
	msg[2] = byte(cs >> 8)
	msg[3] = byte(cs & 0xff)
	return msg, nil
}

func sendICMPv6PortUnreachable(data []byte, client netip.AddrPort) error {
	msg, err := buildICMPv6PortUnreachable(data)
	if err != nil {
		return err
	}
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_RAW, unix.IPPROTO_ICMPV6)
	if err != nil {
		return fmt.Errorf("icmp_inject: socket: %w", err)
	}
	defer unix.Close(fd)

	sa := &unix.SockaddrInet6{}
	sa.Addr = client.Addr().As16()
	if err := unix.Sendto(fd, msg, 0, sa); err != nil {
		return fmt.Errorf("icmp_inject: sendto: %w", err)
	}
	return nil
}

// buildICMPv6PortUnreachable constructs the ICMPv6 Port Unreachable message
// (RFC 4443) without sending it. The kernel fills the ICMPv6 checksum for raw
// sockets, so it is left zero here.
func buildICMPv6PortUnreachable(data []byte) ([]byte, error) {
	if len(data) < 40 {
		return nil, fmt.Errorf("icmp_inject: packet too short for IPv6 header: %d", len(data))
	}
	quoteLen := 40 + 8 // original IPv6 header + first 8 bytes of original payload (UDP header)
	if quoteLen > len(data) {
		quoteLen = len(data)
	}
	quoted := data[:quoteLen]

	// ICMPv6 message: type(1) code(1) checksum(2) unused(4) + quoted datagram.
	msg := make([]byte, 8+len(quoted))
	msg[0] = 1 // type: destination unreachable
	msg[1] = 4 // code: port unreachable
	copy(msg[8:], quoted)
	return msg, nil
}
