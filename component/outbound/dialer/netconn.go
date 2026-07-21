/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"context"
	"net"

	"github.com/daeuniverse/outbound/netproxy"
)

type netConnDialer struct {
	netproxy.Dialer
}

func (d *netConnDialer) DialContext(ctx context.Context, network, addr string) (netproxy.Conn, error) {
	conn, err := d.Dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	if _, ok := conn.(net.Conn); ok {
		return conn, nil
	}
	if packetConn, ok := conn.(netproxy.PacketConn); ok {
		return &netPacketConn{PacketConn: packetConn}, nil
	}
	return &netproxy.FakeNetConn{Conn: conn}, nil
}

type netPacketConn struct {
	netproxy.PacketConn
}

func (*netPacketConn) LocalAddr() net.Addr  { return nil }
func (*netPacketConn) RemoteAddr() net.Addr { return nil }

// EnsureNetConn adapts connections returned by a chain entry for exit
// protocols that require the standard library's net.Conn interface.
func EnsureNetConn(d netproxy.Dialer) netproxy.Dialer {
	return &netConnDialer{Dialer: d}
}
