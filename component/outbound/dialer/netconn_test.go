/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
)

type netConnTestDialer struct {
	conn netproxy.Conn
}

func (d netConnTestDialer) DialContext(context.Context, string, string) (netproxy.Conn, error) {
	return d.conn, nil
}

type netConnTestConn struct{}

func (*netConnTestConn) Read([]byte) (int, error)         { return 0, nil }
func (*netConnTestConn) Write(p []byte) (int, error)      { return len(p), nil }
func (*netConnTestConn) Close() error                     { return nil }
func (*netConnTestConn) SetDeadline(time.Time) error      { return nil }
func (*netConnTestConn) SetReadDeadline(time.Time) error  { return nil }
func (*netConnTestConn) SetWriteDeadline(time.Time) error { return nil }

type netConnTestPacketConn struct {
	netConnTestConn
}

func (*netConnTestPacketConn) ReadFrom([]byte) (int, netip.AddrPort, error) {
	return 0, netip.AddrPort{}, nil
}
func (*netConnTestPacketConn) WriteTo(p []byte, _ string) (int, error) { return len(p), nil }

func TestEnsureNetConn(t *testing.T) {
	raw := &netConnTestConn{}
	conn, err := EnsureNetConn(netConnTestDialer{conn: raw}).DialContext(context.Background(), "tcp", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := conn.(net.Conn); !ok {
		t.Fatalf("adapted connection = %T, want net.Conn", conn)
	}
	if got := conn.(*netproxy.FakeNetConn).Conn; got != raw {
		t.Fatalf("wrapped connection = %T, want original %T", got, raw)
	}
}

func TestEnsureNetConnKeepsStandardConn(t *testing.T) {
	raw, peer := net.Pipe()
	defer func() { _ = raw.Close() }()
	defer func() { _ = peer.Close() }()
	conn, err := EnsureNetConn(netConnTestDialer{conn: raw}).DialContext(context.Background(), "tcp", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	if conn != raw {
		t.Fatalf("adapted connection = %T, want original %T", conn, raw)
	}
}

func TestEnsureNetConnPreservesPacketConn(t *testing.T) {
	raw := &netConnTestPacketConn{}
	conn, err := EnsureNetConn(netConnTestDialer{conn: raw}).DialContext(context.Background(), "udp", "1.1.1.1:53")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := conn.(net.Conn); !ok {
		t.Fatalf("adapted packet connection = %T, want net.Conn", conn)
	}
	if _, ok := conn.(netproxy.PacketConn); !ok {
		t.Fatalf("adapted packet connection = %T, want netproxy.PacketConn", conn)
	}
}
