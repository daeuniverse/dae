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
	"sync/atomic"
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

// rejectRateBucket is the per-client ICMP budget. count is accessed
// concurrently and must only be mutated through atomic operations.
type rejectRateBucket struct {
	count atomic.Int64
	start time.Time
}

// rejectRateBuckets maps a client endpoint (netip.AddrPort.String()) to its
// ICMP budget. Entries are evicted by rejectSweeper once they fall outside the
// rate window, so the map no longer grows without bound (each QUIC client uses
// a fresh source port, which previously left a permanent entry per connection).
var rejectRateBuckets sync.Map // netip.AddrPort.String() -> *rejectRateBucket

// icmpV4Fd / icmpV6Fd are the process-lifetime raw sockets used to emit ICMP
// port-unreachable messages. They are created once on first use instead of
// per packet (see rejectIcmpSockets).
var (
	icmpV4Fd   int = -1
	icmpV6Fd   int = -1
	icmpFdOnce sync.Once
)

func rejectIcmpSockets() (v4, v6 int) {
	icmpFdOnce.Do(func() {
		if fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_ICMP); err == nil {
			icmpV4Fd = fd
		}
		if fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_RAW, unix.IPPROTO_ICMPV6); err == nil {
			icmpV6Fd = fd
		}
	})
	return icmpV4Fd, icmpV6Fd
}

// rejectAllowed reports whether an ICMP port-unreachable may still be sent to
// client within the per-client budget. It is safe for concurrent use.
func rejectAllowed(client netip.AddrPort) bool {
	now := time.Now()
	key := client.String()
	if v, ok := rejectRateBuckets.Load(key); ok {
		b := v.(*rejectRateBucket)
		if now.Sub(b.start) <= rejectIcmpRateWindow {
			if b.count.Load() >= rejectIcmpRateMax {
				return false
			}
			b.count.Add(1)
			return true
		}
		// Expired: drop the stale bucket so it does not leak.
		rejectRateBuckets.Delete(key)
	}
	b := &rejectRateBucket{start: now}
	b.count.Store(1)
	rejectRateBuckets.Store(key, b)
	return true
}

// rejectSweeper periodically evicts stale entries from rejectRateBuckets so the
// map does not grow without bound under sustained rejection pressure.
func rejectSweeper() {
	ticker := time.NewTicker(rejectIcmpRateWindow)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		rejectRateBuckets.Range(func(k, v any) bool {
			if now.Sub(v.(*rejectRateBucket).start) > rejectIcmpRateWindow {
				rejectRateBuckets.Delete(k)
			}
			return true
		})
	}
}

func init() {
	go rejectSweeper()
}

// sendICMPPortUnreachable injects an ICMP Destination Port Unreachable (IPv4,
// type 3 / code 3) or ICMPv6 Port Unreachable (IPv6, type 1 / code 4) back to
// the client, quoting the original packet's IP and UDP headers so the client's
// QUIC stack correlates the error and immediately falls back to TCP (RFC 9000
// §9.3 / RFC 792 / RFC 4443).
//
// Unlike TCP RST, the ICMP error is not delivered to the socket that sent the
// datagram by the kernel; instead the client matches it by the embedded
// original-datagram header (the quoted IP/UDP 4-tuple). The tproxy data plane
// hands the control plane the UDP *payload* only, so the quoted IP/UDP headers
// cannot be recovered from the packet buffer — we reconstruct them from the
// routing 4-tuple we already resolved: client is the datagram's source, and
// originalDst is the datagram's original destination (the rejected target).
//
// The ICMP message itself is sent from the dae host's own egress address
// (chosen by the kernel from the route to the client); that outer source is
// irrelevant to correlation. Spoofing the original destination as the source
// would also be valid but requires IP_TRANSPARENT and reverse-path-filter care,
// so it is intentionally left as a follow-up.
func sendICMPPortUnreachable(client, originalDst netip.AddrPort) error {
	if !client.Addr().IsValid() || !originalDst.Addr().IsValid() {
		return errors.New("icmp_inject: missing client or original destination address")
	}
	if client.Addr().Is4() {
		if !originalDst.Addr().Is4() {
			return fmt.Errorf("icmp_inject: address family mismatch: client %s vs dst %s", client, originalDst)
		}
		return sendICMPv4PortUnreachable(client, originalDst)
	}
	if !originalDst.Addr().Is6() {
		return fmt.Errorf("icmp_inject: address family mismatch: client %s vs dst %s", client, originalDst)
	}
	return sendICMPv6PortUnreachable(client, originalDst)
}

// buildICMPv4PortUnreachable constructs the ICMPv4 Destination Port
// Unreachable message (RFC 792) without sending it. The quoted "original
// datagram" is the IPv4 + UDP headers of the rejected packet, rebuilt from the
// routing 4-tuple: the embedded IP source is the client (the datagram's source)
// and the embedded IP destination is the original destination (the rejected
// target), exactly mirroring the original datagram; the embedded UDP ports are
// the client port (source) and the original destination port respectively. This
// is what lets the client's QUIC stack associate the error with the connection
// it opened to originalDst.
func buildICMPv4PortUnreachable(client, originalDst netip.AddrPort) ([]byte, error) {
	if !client.Addr().Is4() || !originalDst.Addr().Is4() {
		return nil, fmt.Errorf("icmp_inject: IPv4 ICMP requires IPv4 addresses, got client %s dst %s", client, originalDst)
	}
	// Quoted original IPv4 header (20 bytes, no options).
	ip := make([]byte, 20)
	ip[0] = 0x45 // version 4, IHL 5
	// ip[1] TOS = 0
	binary.BigEndian.PutUint16(ip[2:4], 28) // total length = IP(20) + UDP(8)
	// ip[4:6] identification = 0
	// ip[6:8] flags/fragment offset = 0
	ip[8] = 64 // TTL
	ip[9] = uint8(unix.IPPROTO_UDP)
	// ip[10:12] header checksum (filled below)
	c4 := client.Addr().As4()
	copy(ip[12:16], c4[:]) // source = client (datagram source)
	o4 := originalDst.Addr().As4()
	copy(ip[16:20], o4[:]) // destination = original destination
	binary.BigEndian.PutUint16(ip[10:12], internetChecksum(ip))

	// Quoted original UDP header (8 bytes).
	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:2], client.Port())      // source port = client
	binary.BigEndian.PutUint16(udp[2:4], originalDst.Port()) // destination port = original destination
	binary.BigEndian.PutUint16(udp[4:6], 8)                  // length = just the header
	// udp[6:8] checksum = 0

	quoted := make([]byte, 0, 28)
	quoted = append(quoted, ip...)
	quoted = append(quoted, udp...)

	// ICMPv4 message: type(1) code(1) checksum(2) unused(4) + quoted datagram.
	msg := make([]byte, 8+len(quoted))
	msg[0] = 3 // type: destination unreachable
	msg[1] = 3 // code: port unreachable
	// msg[2:4] checksum and msg[4:8] unused are already zero.
	copy(msg[8:], quoted)
	cs := internetChecksum(msg)
	msg[2] = byte(cs >> 8)
	msg[3] = byte(cs & 0xff)
	return msg, nil
}

func sendICMPv4PortUnreachable(client, originalDst netip.AddrPort) error {
	msg, err := buildICMPv4PortUnreachable(client, originalDst)
	if err != nil {
		return err
	}
	v4, _ := rejectIcmpSockets()
	if v4 < 0 {
		return errors.New("icmp_inject: raw ICMPv4 socket unavailable")
	}
	sa := &unix.SockaddrInet4{}
	sa.Addr = client.Addr().As4()
	if err := unix.Sendto(v4, msg, 0, sa); err != nil {
		return fmt.Errorf("icmp_inject: sendto: %w", err)
	}
	return nil
}

// buildICMPv6PortUnreachable constructs the ICMPv6 Port Unreachable message
// (RFC 4443) without sending it. The kernel fills the ICMPv6 checksum for raw
// sockets, so it is left zero here. The quoted header is rebuilt from the
// routing 4-tuple exactly as for IPv4 (see buildICMPv4PortUnreachable).
func buildICMPv6PortUnreachable(client, originalDst netip.AddrPort) ([]byte, error) {
	if !client.Addr().Is6() || !originalDst.Addr().Is6() {
		return nil, fmt.Errorf("icmp_inject: IPv6 ICMP requires IPv6 addresses, got client %s dst %s", client, originalDst)
	}
	// Quoted original IPv6 header (40 bytes).
	ip := make([]byte, 40)
	ip[0] = 0x60 // version 6
	// ip[1:4] traffic class / flow label = 0
	binary.BigEndian.PutUint16(ip[4:6], 8) // payload length = quoted UDP header (8)
	ip[6] = uint8(unix.IPPROTO_UDP)        // next header = UDP
	ip[7] = 64                             // hop limit
	c6 := client.Addr().As16()
	copy(ip[8:24], c6[:]) // source = client (datagram source)
	o6 := originalDst.Addr().As16()
	copy(ip[24:40], o6[:]) // destination = original destination

	// Quoted original UDP header (8 bytes).
	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:2], client.Port())      // source port = client
	binary.BigEndian.PutUint16(udp[2:4], originalDst.Port()) // destination port = original destination
	binary.BigEndian.PutUint16(udp[4:6], 8)                  // length = just the header
	// udp[6:8] checksum = 0

	quoted := make([]byte, 0, 48)
	quoted = append(quoted, ip...)
	quoted = append(quoted, udp...)

	// ICMPv6 message: type(1) code(1) checksum(2) unused(4) + quoted datagram.
	msg := make([]byte, 8+len(quoted))
	msg[0] = 1 // type: destination unreachable
	msg[1] = 4 // code: port unreachable
	// msg[2:4] checksum is filled by the kernel for raw ICMPv6 sockets.
	copy(msg[8:], quoted)
	return msg, nil
}

func sendICMPv6PortUnreachable(client, originalDst netip.AddrPort) error {
	msg, err := buildICMPv6PortUnreachable(client, originalDst)
	if err != nil {
		return err
	}
	_, v6 := rejectIcmpSockets()
	if v6 < 0 {
		return errors.New("icmp_inject: raw ICMPv6 socket unavailable")
	}
	sa := &unix.SockaddrInet6{}
	sa.Addr = client.Addr().As16()
	if err := unix.Sendto(v6, msg, 0, sa); err != nil {
		return fmt.Errorf("icmp_inject: sendto: %w", err)
	}
	return nil
}
