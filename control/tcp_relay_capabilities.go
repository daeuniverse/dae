/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import "net"

type relayUnderlyingConn interface {
	UnderlyingConn() net.Conn
}

type relayPrefixSource interface {
	TakeRelayPrefix() []byte
}

const relayUnderlyingConnMaxDepth = 8

// unwrapRelayTCPConn resolves transparent wrappers down to a concrete TCP
// socket. This is intentionally capability-based so outbound wrappers can opt
// in by exposing UnderlyingConn without hard-coding protocol types here.
func unwrapRelayTCPConn(conn any) (*net.TCPConn, bool) {
	return unwrapRelayTCPConnDepth(conn, 0)
}

func unwrapRelayTCPConnDepth(conn any, depth int) (*net.TCPConn, bool) {
	if conn == nil || depth >= relayUnderlyingConnMaxDepth {
		return nil, false
	}

	switch c := conn.(type) {
	case *net.TCPConn:
		return c, true
	case *prefixedConn:
		return unwrapRelayTCPConnDepth(c.Conn, depth+1)
	case relayUnderlyingConn:
		return unwrapRelayTCPConnDepth(c.UnderlyingConn(), depth+1)
	default:
		return nil, false
	}
}
