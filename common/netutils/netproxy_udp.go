/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package netutils

import "github.com/daeuniverse/outbound/netproxy"

// WriteUDPConn writes a UDP payload to conn and prefers packet semantics when available.
// Some UDP protocol adapters, such as Shadowsocks 2022, require WriteTo with the
// explicit target address instead of the stream-style Write method.
func WriteUDPConn(conn netproxy.Conn, addr string, payload []byte) (int, error) {
	if pc, ok := conn.(netproxy.PacketConn); ok {
		return pc.WriteTo(payload, addr)
	}
	return conn.Write(payload)
}

// ReadUDPConn reads a UDP payload from conn and prefers packet semantics when available.
// The source address is intentionally discarded because callers already know the
// upstream endpoint they dialed and only need the payload bytes.
func ReadUDPConn(conn netproxy.Conn, payload []byte) (int, error) {
	if pc, ok := conn.(netproxy.PacketConn); ok {
		n, _, err := pc.ReadFrom(payload)
		return n, err
	}
	return conn.Read(payload)
}
