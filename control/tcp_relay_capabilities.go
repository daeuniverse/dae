/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"io"
	"net"

	"github.com/daeuniverse/dae/component/sniffing"
	"github.com/daeuniverse/outbound/netproxy"
)

type relaySegmentSource interface {
	TakeRelaySegments() [][]byte
}

type relayContinuationSource interface {
	// CopyRelayRemainder receives the owning relay's ctx so long-running
	// fast paths inside implementers observe cancellation instead of
	// outliving the flow.
	CopyRelayRemainder(ctx context.Context, dst io.Writer, buf []byte, record func(int64), onActive func(int64)) (int64, error)
}

type relayPrefixSource interface {
	TakeRelayPrefix() []byte
}

// The relay capability interfaces are satisfied structurally, so a signature
// drift in an implementer is not a compile error on its own — it just makes
// the type assertion fail and silently changes which relay path runs. These
// assertions pin the intended set of implementers.
//
// sniffing.ConnSniffer is intentionally absent from relayContinuationSource:
// its remainder must be read through Sniffer.Read, so it stays on
// relayCopyLoop. See ConnSniffer.CopyRelayRemainder.
var (
	_ relaySegmentSource      = (*sniffing.ConnSniffer)(nil)
	_ relayPrefixSource       = (*sniffing.ConnSniffer)(nil)
	_ relaySegmentSource      = (*bufioConn)(nil)
	_ relayContinuationSource = (*bufioConn)(nil)
	_ relayPrefixSource       = (*bufioConn)(nil)
	_ relaySegmentSource      = (*prefixedConn)(nil)
	_ relayContinuationSource = (*prefixedConn)(nil)
	_ relayPrefixSource       = (*prefixedConn)(nil)
)

const relayConnChainMaxDepth = 8

// unwrapRelayTCPConn resolves known byte-transparent wrappers down to a
// concrete TCP socket safe for kernel splice(2), gather writev, eBPF sockmap
// offload, and raw TCP CloseWrite. It deliberately does not walk generic
// netproxy.UnderlyingConnProvider chains: outbound protocol and TLS layers
// (vmess, trojan, vless, UnderlyingConnForwarder) implement UnderlyingConn
// for socket-queue inspection, and peeling past them would bypass framing
// and encryption.
func unwrapRelayTCPConn(conn any) (*net.TCPConn, bool) {
	for range relayConnChainMaxDepth {
		if conn == nil {
			return nil, false
		}

		switch c := conn.(type) {
		case *net.TCPConn:
			return c, true
		case *prefixedConn:
			conn = c.Conn
		case *bufioConn:
			conn = c.Conn
		case *sniffing.ConnSniffer:
			// ConnSniffer now supports UnwrapTCPConn for splice after sniffing.
			if tcpConn, ok := c.UnwrapTCPConn(); ok {
				return tcpConn, true
			}
			conn = c.Conn
		case *netproxy.FakeNetConn:
			conn = c.Conn
		default:
			return nil, false
		}
	}
	return nil, false
}
