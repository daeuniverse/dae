/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/daeuniverse/dae/component/sniffing"
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
//
// Iterative implementation reduces function call overhead and improves CPU
// branch prediction compared to the previous recursive approach.
func unwrapRelayTCPConn(conn any) (*net.TCPConn, bool) {
	for depth := 0; depth < relayConnChainMaxDepth; depth++ {
		if conn == nil {
			return nil, false
		}

		switch c := conn.(type) {
		case *net.TCPConn:
			return c, true
		case *prefixedConn:
			conn = c.Conn
		case *sniffing.ConnSniffer:
			// ConnSniffer now supports UnwrapTCPConn for splice after sniffing.
			if tcpConn, ok := c.UnwrapTCPConn(); ok {
				return tcpConn, true
			}
			conn = c.Conn
		case netproxy.UnderlyingConnProvider:
			if tcpConn, ok := netproxy.UnwrapTCPConn(c); ok {
				return tcpConn, true
			}
			conn = c.UnderlyingConn()
		default:
			return netproxy.UnwrapTCPConn(conn)
		}
	}
	return nil, false
}

func relayConnChain(conn any) string {
	// Build the chain string by unwrapping and collecting types.
	// Iterative approach avoids function call overhead while building the full chain.
	var chain []string
	for depth := 0; depth < relayConnChainMaxDepth; depth++ {
		if conn == nil {
			return "<nil>"
		}

		switch c := conn.(type) {
		case *net.TCPConn:
			chain = append(chain, fmt.Sprintf("%T", c))
			return strings.Join(chain, " -> ")
		case *prefixedConn:
			chain = append(chain, fmt.Sprintf("%T", c))
			conn = c.Conn
		case *sniffing.ConnSniffer:
			chain = append(chain, fmt.Sprintf("%T", c))
			conn = c.Conn
		case netproxy.UnderlyingConnProvider:
			chain = append(chain, fmt.Sprintf("%T", c))
			conn = c.UnderlyingConn()
		default:
			// Unknown type - add it and stop
			chain = append(chain, fmt.Sprintf("%T", c))
			return strings.Join(chain, " -> ")
		}
	}
	// Max depth reached
	return fmt.Sprintf("%T -> <max-depth>", conn)
}
