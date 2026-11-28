//go:build linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"bufio"
	"net"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/sniffing"
	"github.com/daeuniverse/outbound/netproxy"
)

func newLoopbackTCPConnPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()

	ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	accepted := make(chan *net.TCPConn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := ln.AcceptTCP()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn
	}()

	client, err := net.DialTCP("tcp4", nil, ln.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatalf("DialTCP: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	select {
	case err := <-acceptErr:
		t.Fatalf("AcceptTCP: %v", err)
	case server := <-accepted:
		t.Cleanup(func() { _ = server.Close() })
		return client, server
	case <-time.After(3 * time.Second):
		t.Fatal("AcceptTCP timed out")
	}
	return nil, nil
}

// opaqueProtocolConn models an encrypting or framing outbound conn (such as
// vmess, trojan, vless, or ws) that exposes UnderlyingConn for socket-queue
// inspection without being byte-transparent.
type opaqueProtocolConn struct {
	netproxy.Conn
	underlying net.Conn
}

func (c *opaqueProtocolConn) UnderlyingConn() net.Conn {
	return c.underlying
}

func TestUnwrapRelayTCPConnTransparentWrappers(t *testing.T) {
	client, _ := newLoopbackTCPConnPair(t)

	sniffer := sniffing.NewConnSniffer(client, time.Second)
	t.Cleanup(func() { _ = sniffer.Close() })

	cases := []struct {
		name string
		conn any
	}{
		{name: "raw TCPConn", conn: client},
		{name: "prefixedConn", conn: &prefixedConn{Conn: client}},
		{name: "bufioConn", conn: &bufioConn{Conn: client, reader: bufio.NewReader(client)}},
		{name: "ConnSniffer", conn: sniffer},
		{name: "FakeNetConn", conn: &netproxy.FakeNetConn{Conn: client}},
		{
			name: "nested transparent wrappers",
			conn: &prefixedConn{
				Conn: &bufioConn{
					Conn:   &netproxy.FakeNetConn{Conn: sniffer},
					reader: bufio.NewReader(client),
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := unwrapRelayTCPConn(tc.conn)
			if !ok || got != client {
				t.Fatalf("unwrapRelayTCPConn(%T) = (%v, %v), want (%p, true)", tc.conn, got, ok, client)
			}
		})
	}
}

func TestUnwrapRelayTCPConnRejectsNonTransparentUnderlyingConnProvider(t *testing.T) {
	client, _ := newLoopbackTCPConnPair(t)
	peerClient, _ := newLoopbackTCPConnPair(t)

	cases := []struct {
		name string
		conn netproxy.Conn
	}{
		{
			name: "UnderlyingConnProvider protocol wrapper",
			conn: &opaqueProtocolConn{Conn: client, underlying: client},
		},
		{
			name: "UnderlyingConnForwarder TLS wrapper",
			conn: netproxy.NewUnderlyingConnForwarder(client, func() net.Conn { return client }),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got, ok := unwrapRelayTCPConn(tc.conn); ok || got != nil {
				t.Fatalf("unwrapRelayTCPConn(%T) = (%v, %v), want (nil, false)", tc.conn, got, ok)
			}
			if shouldUseRelayFastPath(tc.conn, peerClient) || shouldUseRelayFastPath(peerClient, tc.conn) {
				t.Fatalf("shouldUseRelayFastPath accepted non-transparent %T", tc.conn)
			}
			if got, ok := relayGatherWriteTCPConn(tc.conn); ok || got != nil {
				t.Fatalf("relayGatherWriteTCPConn(%T) = (%v, %v), want (nil, false)", tc.conn, got, ok)
			}
		})
	}
}
