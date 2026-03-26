//go:build linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"encoding/binary"
	"fmt"
	"net/netip"

	"golang.org/x/sys/unix"
)

func sendUDPv6RawDirect(data []byte, from, realTo netip.AddrPort) error {
	if !from.IsValid() || !realTo.IsValid() {
		return fmt.Errorf("invalid addr: from=%v to=%v", from, realTo)
	}
	if !from.Addr().Is6() || from.Addr().Is4In6() || !realTo.Addr().Is6() || realTo.Addr().Is4In6() {
		return fmt.Errorf("raw UDPv6 fallback requires pure IPv6 endpoints: from=%v to=%v", from, realTo)
	}

	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_UDP)
	if err != nil {
		return fmt.Errorf("create raw IPv6 UDP socket: %w", err)
	}
	defer func() { _ = unix.Close(fd) }()

	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_TRANSPARENT, 1); err != nil {
		return fmt.Errorf("enable IPV6_TRANSPARENT on raw socket: %w", err)
	}
	if soMarkFromDae != 0 {
		if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, int(soMarkFromDae)); err != nil {
			return fmt.Errorf("set SO_MARK on raw socket: %w", err)
		}
	}

	var bindAddr unix.SockaddrInet6
	fromIP := from.Addr().As16()
	copy(bindAddr.Addr[:], fromIP[:])
	if err := unix.Bind(fd, &bindAddr); err != nil {
		return fmt.Errorf("bind raw IPv6 UDP socket to %v: %w", from.Addr(), err)
	}

	udp := make([]byte, 8+len(data))
	binary.BigEndian.PutUint16(udp[0:2], from.Port())
	binary.BigEndian.PutUint16(udp[2:4], realTo.Port())
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	copy(udp[8:], data)
	binary.BigEndian.PutUint16(udp[6:8], udp6Checksum(from.Addr(), realTo.Addr(), udp))

	var dstAddr unix.SockaddrInet6
	toIP := realTo.Addr().As16()
	copy(dstAddr.Addr[:], toIP[:])
	if err := unix.Sendto(fd, udp, 0, &dstAddr); err != nil {
		return fmt.Errorf("send raw IPv6 UDP packet from %v to %v: %w", from, realTo, err)
	}
	return nil
}

func sendUDPv6RawInDaeNetns(data []byte, from, realTo netip.AddrPort) error {
	// This path is called from the dataplane hot path where caller is already
	// in dae netns (see run loop in cmd/run.go). Avoid nested netns switching:
	// re-entering WithRequired here can temporarily flip thread netns and break
	// packet handling continuity under concurrent traffic.
	return sendUDPv6RawDirect(data, from, realTo)
}

func udp6Checksum(src, dst netip.Addr, udp []byte) uint16 {
	pseudo := make([]byte, 40+len(udp))
	srcIP := src.As16()
	dstIP := dst.As16()
	copy(pseudo[0:16], srcIP[:])
	copy(pseudo[16:32], dstIP[:])
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(udp)))
	pseudo[39] = unix.IPPROTO_UDP
	copy(pseudo[40:], udp)
	return internetChecksum(pseudo)
}

func internetChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i:]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
