/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package netutils

import (
	"net/netip"

	"github.com/daeuniverse/outbound/netproxy"
)

// WriteUDPConn writes a UDP payload to conn and prefers packet semantics when available.
// Some UDP protocol adapters, such as Shadowsocks 2022, require WriteTo with the
// explicit target address instead of the stream-style Write method.
func WriteUDPConn(conn netproxy.Conn, addr string, payload []byte) (int, error) {
	if pc, ok := conn.(netproxy.PacketConn); ok {
		return pc.WriteTo(payload, addr)
	}
	return conn.Write(payload)
}

// ReadUDPConnFrom reads a UDP payload from conn, reporting the datagram source
// when the transport exposes packet semantics. A transport that only exposes
// stream semantics reports an invalid address, which callers must treat as
// "unknown" rather than as a mismatch: stream transports cannot attribute a
// datagram to a sender at all.
func ReadUDPConnFrom(conn netproxy.Conn, payload []byte) (n int, from netip.AddrPort, err error) {
	if pc, ok := conn.(netproxy.PacketConn); ok {
		return pc.ReadFrom(payload)
	}
	n, err = conn.Read(payload)
	return n, netip.AddrPort{}, err
}

// ReadUDPConn reads a UDP payload from conn and prefers packet semantics when available.
// Callers that must validate which upstream produced the datagram should use
// ReadUDPConnFrom; this wrapper exists for the paths that only need the bytes.
func ReadUDPConn(conn netproxy.Conn, payload []byte) (int, error) {
	n, _, err := ReadUDPConnFrom(conn, payload)
	return n, err
}
