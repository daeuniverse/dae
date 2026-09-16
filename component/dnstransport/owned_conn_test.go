/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package dnstransport

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/olicesx/quic-go"
	"github.com/olicesx/quic-go/congestion"
)

type ownedPacketCloser struct {
	closed atomic.Int32
	done   chan struct{}
}

func (c *ownedPacketCloser) Close() error {
	if c.closed.Add(1) == 1 && c.done != nil {
		close(c.done)
	}
	return nil
}

type stubEarlyConn struct {
	closed atomic.Int32
	ctx    context.Context
	cancel context.CancelFunc
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
	if c.cancel != nil {
		c.cancel()
	}
	return nil
}

func (c *stubEarlyConn) Context() context.Context {
	if c.ctx != nil {
		return c.ctx
	}
	return context.Background()
}

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

func TestOwnedEarlyConnCloseClosesPacketConnOnce(t *testing.T) {
	t.Parallel()

	packet := &ownedPacketCloser{}
	qc := &stubEarlyConn{}
	owned := OwnEarlyConnection(qc, packet)
	if err := owned.CloseWithError(0, ""); err != nil {
		t.Fatalf("CloseWithError: %v", err)
	}
	if err := owned.CloseWithError(0, "again"); err != nil {
		t.Fatalf("second CloseWithError: %v", err)
	}
	if got := packet.closed.Load(); got != 1 {
		t.Fatalf("packet Close count = %d, want 1", got)
	}
	if got := qc.closed.Load(); got != 1 {
		t.Fatalf("quic CloseWithError count = %d, want 1", got)
	}
}

func TestOwnedEarlyConnClosesWhenConnectionEnds(t *testing.T) {
	for _, alreadyClosed := range []bool{false, true} {
		name := "after_registration"
		if alreadyClosed {
			name = "before_registration"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if alreadyClosed {
				cancel()
			}
			packet := &ownedPacketCloser{done: make(chan struct{})}
			qc := &stubEarlyConn{ctx: ctx, cancel: cancel}
			owned := OwnEarlyConnection(qc, packet)
			t.Cleanup(func() { _ = owned.CloseWithError(0, "") })
			cancel()
			select {
			case <-packet.done:
			case <-time.After(time.Second):
				t.Fatal("connection ended without closing its owned packet conn")
			}
			if err := owned.CloseWithError(0, "again"); err != nil {
				t.Fatal(err)
			}
			if got := packet.closed.Load(); got != 1 {
				t.Fatalf("packet Close count = %d, want 1", got)
			}
		})
	}
}

func TestOwnedEarlyConnNaturalAndExplicitCloseRace(t *testing.T) {
	for range 32 {
		ctx, cancel := context.WithCancel(context.Background())
		packet := &ownedPacketCloser{done: make(chan struct{})}
		qc := &stubEarlyConn{ctx: ctx, cancel: cancel}
		owned := OwnEarlyConnection(qc, packet)
		var wg sync.WaitGroup
		wg.Go(cancel)
		for range 4 {
			wg.Go(func() { _ = owned.CloseWithError(0, "") })
		}
		wg.Wait()
		if got := packet.closed.Load(); got != 1 {
			t.Fatalf("packet Close count = %d, want 1", got)
		}
		if got := qc.closed.Load(); got != 1 {
			t.Fatalf("quic CloseWithError count = %d, want 1", got)
		}
	}
}

var (
	_ io.Closer            = (*ownedPacketCloser)(nil)
	_ quic.EarlyConnection = (*stubEarlyConn)(nil)
)
