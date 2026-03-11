/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"fmt"
	"io"
	"net"

	"github.com/daeuniverse/outbound/netproxy"
)

type relaySegmentSource interface {
	TakeRelaySegments() [][]byte
}

type relayContinuationSource interface {
	CopyRelayRemainder(dst io.Writer, buf []byte) (int64, error)
}

type relayPrefixSource interface {
	TakeRelayPrefix() []byte
}

const relayConnChainMaxDepth = 8

// unwrapRelayTCPConn resolves transparent wrappers down to a concrete TCP
// socket. Generic wrapper traversal is delegated to outbound/netproxy's
// UnwrapTCPConn so dae stays aligned with wrapper capabilities added there,
// while prefixedConn remains a dae-local relay wrapper that must be peeled
// explicitly.
func unwrapRelayTCPConn(conn any) (*net.TCPConn, bool) {
	return unwrapRelayTCPConnDepth(conn, 0)
}

func relayConnChain(conn any) string {
	return relayConnChainDepth(conn, 0)
}

func unwrapRelayTCPConnDepth(conn any, depth int) (*net.TCPConn, bool) {
	if conn == nil || depth >= relayConnChainMaxDepth {
		return nil, false
	}

	switch c := conn.(type) {
	case *prefixedConn:
		return unwrapRelayTCPConnDepth(c.Conn, depth+1)
	case netproxy.UnderlyingConnProvider:
		if tcpConn, ok := netproxy.UnwrapTCPConn(c); ok {
			return tcpConn, true
		}
		return unwrapRelayTCPConnDepth(c.UnderlyingConn(), depth+1)
	default:
		return netproxy.UnwrapTCPConn(conn)
	}
}

func relayConnChainDepth(conn any, depth int) string {
	if conn == nil {
		return "<nil>"
	}
	if depth >= relayConnChainMaxDepth {
		return fmt.Sprintf("%T -> <max-depth>", conn)
	}

	switch c := conn.(type) {
	case *net.TCPConn:
		return fmt.Sprintf("%T", c)
	case *prefixedConn:
		return fmt.Sprintf("%T -> %s", c, relayConnChainDepth(c.Conn, depth+1))
	case netproxy.UnderlyingConnProvider:
		return fmt.Sprintf("%T -> %s", c, relayConnChainDepth(c.UnderlyingConn(), depth+1))
	default:
		return fmt.Sprintf("%T", c)
	}
}
