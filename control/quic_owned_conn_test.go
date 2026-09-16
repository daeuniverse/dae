/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"

	"github.com/daeuniverse/dae/component/dnstransport"
	"github.com/olicesx/quic-go"
	"github.com/olicesx/quic-go/congestion"
)

type ownedPacketCloser struct {
	closed atomic.Int32
}

func (c *ownedPacketCloser) Close() error {
	c.closed.Add(1)
	return nil
}

type stubEarlyConn struct {
	closed atomic.Int32
}

func (c *stubEarlyConn) AcceptStream(context.Context) (quic.Stream, error) {
	return nil, net.ErrClosed
}
func (c *stubEarlyConn) AcceptUniStream(context.Context) (quic.ReceiveStream, error) {
	return nil, net.ErrClosed
}
func (c *stubEarlyConn) OpenStream() (quic.Stream, error) { return nil, net.ErrClosed }
func (c *stubEarlyConn) OpenStreamSync(context.Context) (quic.Stream, error) {
	return nil, net.ErrClosed
}
func (c *stubEarlyConn) OpenUniStream() (quic.SendStream, error) { return nil, net.ErrClosed }
func (c *stubEarlyConn) OpenUniStreamSync(context.Context) (quic.SendStream, error) {
	return nil, net.ErrClosed
}
func (c *stubEarlyConn) LocalAddr() net.Addr  { return &net.UDPAddr{} }
func (c *stubEarlyConn) RemoteAddr() net.Addr { return &net.UDPAddr{} }
func (c *stubEarlyConn) CloseWithError(quic.ApplicationErrorCode, string) error {
	c.closed.Add(1)
	return nil
}
func (c *stubEarlyConn) Context() context.Context { return context.Background() }
func (c *stubEarlyConn) ConnectionState() quic.ConnectionState {
	return quic.ConnectionState{}
}
func (c *stubEarlyConn) SendDatagram([]byte) error { return nil }
func (c *stubEarlyConn) ReceiveDatagram(context.Context) ([]byte, error) {
	return nil, net.ErrClosed
}
func (c *stubEarlyConn) ReleaseDatagram([]byte)                            {}
func (c *stubEarlyConn) SetCongestionControl(congestion.CongestionControl) {}
func (c *stubEarlyConn) HandshakeComplete() <-chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}
func (c *stubEarlyConn) NextConnection(context.Context) (quic.Connection, error) {
	return nil, net.ErrClosed
}

func TestDoQReplaceAndCloseClosesUnderlyingPacketConn(t *testing.T) {
	t.Parallel()

	firstPacket := &ownedPacketCloser{}
	secondPacket := &ownedPacketCloser{}
	first := dnstransport.OwnEarlyConnection(&stubEarlyConn{}, firstPacket)
	second := dnstransport.OwnEarlyConnection(&stubEarlyConn{}, secondPacket)

	calls := 0
	d := &DoQ{
		connectionFactory: func(context.Context) (quic.EarlyConnection, error) {
			calls++
			if calls == 1 {
				return first, nil
			}
			return second, nil
		},
	}

	got, err := d.getOrCreateConnection(context.Background())
	if err != nil {
		t.Fatalf("getOrCreateConnection: %v", err)
	}
	if got != first {
		t.Fatal("expected first owned connection")
	}

	got, err = d.replaceConnection(context.Background(), first)
	if err != nil {
		t.Fatalf("replaceConnection: %v", err)
	}
	if got != second {
		t.Fatal("expected second owned connection")
	}
	if got := firstPacket.closed.Load(); got != 1 {
		t.Fatalf("replaced packet Close count = %d, want 1", got)
	}
	if got := secondPacket.closed.Load(); got != 0 {
		t.Fatalf("active packet Close count = %d, want 0", got)
	}

	if err := d.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := secondPacket.closed.Load(); got != 1 {
		t.Fatalf("closed packet Close count = %d, want 1", got)
	}
}

func TestDoQInstallRaceClosesLosingConnection(t *testing.T) {
	t.Parallel()

	winnerPacket := &ownedPacketCloser{}
	loserPacket := &ownedPacketCloser{}
	winner := dnstransport.OwnEarlyConnection(&stubEarlyConn{}, winnerPacket)
	loser := dnstransport.OwnEarlyConnection(&stubEarlyConn{}, loserPacket)

	d := &DoQ{connection: winner}
	got, err := d.installConnection(loser)
	if err != nil {
		t.Fatalf("installConnection: %v", err)
	}
	if got != winner {
		t.Fatal("install race must keep the already-installed connection")
	}
	if got := loserPacket.closed.Load(); got != 1 {
		t.Fatalf("losing packet Close count = %d, want 1", got)
	}
	if got := winnerPacket.closed.Load(); got != 0 {
		t.Fatalf("winning packet Close count = %d, want 0", got)
	}
}

var (
	_ io.Closer            = (*ownedPacketCloser)(nil)
	_ quic.EarlyConnection = (*stubEarlyConn)(nil)
)
