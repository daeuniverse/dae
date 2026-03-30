/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@daeuniverse.org>
 */

package control

import (
	"io"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
)

type scriptedPacketRead struct {
	data []byte
	from netip.AddrPort
	err  error
}

type scriptedPacketConn struct {
	reads       chan scriptedPacketRead
	writeErr    error
	writeN      int
	forceWriteN bool
	closeCh     chan struct{}
	closeCalls  atomic.Int32
}

func (c *scriptedPacketConn) Read(_ []byte) (int, error) {
	return 0, io.EOF
}

func (c *scriptedPacketConn) Write(b []byte) (int, error) {
	return len(b), nil
}

func (c *scriptedPacketConn) ReadFrom(p []byte) (int, netip.AddrPort, error) {
	read := <-c.reads
	if read.err != nil {
		return 0, netip.AddrPort{}, read.err
	}
	copy(p, read.data)
	return len(read.data), read.from, nil
}

func (c *scriptedPacketConn) WriteTo(b []byte, _ string) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	if c.forceWriteN {
		return c.writeN, nil
	}
	return len(b), nil
}

func (c *scriptedPacketConn) Close() error {
	if c.closeCalls.Add(1) == 1 && c.closeCh != nil {
		close(c.closeCh)
	}
	return nil
}

func (c *scriptedPacketConn) SetDeadline(_ time.Time) error {
	return nil
}

func (c *scriptedPacketConn) SetReadDeadline(_ time.Time) error {
	return nil
}

func (c *scriptedPacketConn) SetWriteDeadline(_ time.Time) error {
	return nil
}

func waitForCloseSignal(t *testing.T, ch <-chan struct{}, context string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for close signal: %s", context)
	}
}

func TestUdpEndpointRefreshTtlWithTime_BoundsInitialLifetimeByDialTimeout(t *testing.T) {
	now := time.Unix(123, 0)
	ue := &UdpEndpoint{
		NatTimeout: QuicNatTimeout,
	}

	ue.RefreshTtlWithTime(now.UnixNano())

	got := time.Duration(ue.expiresAtNano.Load() - now.UnixNano())
	want := 2 * consts.DefaultDialTimeout
	if got != want {
		t.Fatalf("expires delta = %v, want %v", got, want)
	}
}

func TestUdpEndpointRefreshTtlWithTime_DoesNotExtendUnrepliedDeadline(t *testing.T) {
	now := time.Unix(456, 0)
	ue := &UdpEndpoint{
		NatTimeout: QuicNatTimeout,
	}

	ue.RefreshTtlWithTime(now.UnixNano())
	firstDeadline := ue.expiresAtNano.Load()
	ue.RefreshTtlWithTime(now.Add(5 * time.Second).UnixNano())

	if got := ue.expiresAtNano.Load(); got != firstDeadline {
		t.Fatalf("expiresAt = %v, want %v", got, firstDeadline)
	}
}

func TestUdpEndpointPromoteAfterReply_UsesFullLifetimeImmediately(t *testing.T) {
	now := time.Unix(789, 0)
	ue := &UdpEndpoint{
		NatTimeout: QuicNatTimeout,
	}

	ue.RefreshTtlWithTime(now.UnixNano())
	ue.markReplied(now.Add(50 * time.Millisecond).UnixNano())

	got := time.Duration(ue.expiresAtNano.Load() - ue.lastRefreshNano.Load())
	if got != QuicNatTimeout {
		t.Fatalf("expires delta = %v, want %v", got, QuicNatTimeout)
	}
}

func TestUdpEndpointAcceptsInitialReplyFrom_SymmetricRequiresExactPeer(t *testing.T) {
	ue := &UdpEndpoint{
		poolKey: UdpEndpointKey{
			Dst: netip.MustParseAddrPort("198.51.100.10:443"),
		},
	}
	ue.rememberPendingReplyPeer("198.51.100.10:443")

	if !ue.acceptsInitialReplyFrom(netip.MustParseAddrPort("198.51.100.10:443")) {
		t.Fatal("expected exact symmetric peer to be accepted")
	}
	if ue.acceptsInitialReplyFrom(netip.MustParseAddrPort("198.51.100.10:8443")) {
		t.Fatal("expected different symmetric peer port to be rejected")
	}
}

func TestUdpEndpointAcceptsInitialReplyFrom_FullConeAllowsSameIpFallback(t *testing.T) {
	ue := &UdpEndpoint{
		poolKey: UdpEndpointKey{},
	}
	ue.rememberPendingReplyPeer("203.0.113.10:3478")

	if !ue.acceptsInitialReplyFrom(netip.MustParseAddrPort("203.0.113.10:50000")) {
		t.Fatal("expected same-IP full-cone reply to be accepted")
	}
	if ue.acceptsInitialReplyFrom(netip.MustParseAddrPort("203.0.113.11:3478")) {
		t.Fatal("expected different-IP full-cone reply to be rejected")
	}
}

func TestUdpEndpointStart_DropsUnexpectedInitialReplyUntilPeerMatches(t *testing.T) {
	conn := &scriptedPacketConn{
		reads: make(chan scriptedPacketRead, 3),
	}
	handled := make(chan netip.AddrPort, 1)
	ue := &UdpEndpoint{
		conn:       conn,
		NatTimeout: QuicNatTimeout,
		handler: func(_ *UdpEndpoint, _ []byte, from netip.AddrPort) error {
			handled <- from
			return nil
		},
	}
	ue.rememberPendingReplyPeer("203.0.113.10:3478")

	done := make(chan struct{})
	go func() {
		defer close(done)
		ue.start()
	}()

	conn.reads <- scriptedPacketRead{
		data: []byte("unexpected"),
		from: netip.MustParseAddrPort("198.51.100.1:1111"),
	}
	conn.reads <- scriptedPacketRead{
		data: []byte("expected"),
		from: netip.MustParseAddrPort("203.0.113.10:50000"),
	}
	conn.reads <- scriptedPacketRead{err: io.EOF}

	select {
	case from := <-handled:
		if from != netip.MustParseAddrPort("203.0.113.10:50000") {
			t.Fatalf("handler saw from = %v, want matched peer", from)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for matched initial reply to be handled")
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for read loop to exit")
	}

	if !ue.hasReply.Load() {
		t.Fatal("expected endpoint to be promoted after matched initial reply")
	}
}

func TestUdpEndpointStart_HandlerErrorClosesConn(t *testing.T) {
	conn := &scriptedPacketConn{
		reads:   make(chan scriptedPacketRead, 1),
		closeCh: make(chan struct{}),
	}
	wantErr := io.ErrUnexpectedEOF
	ue := &UdpEndpoint{
		conn:       conn,
		NatTimeout: QuicNatTimeout,
		handler: func(_ *UdpEndpoint, _ []byte, _ netip.AddrPort) error {
			return wantErr
		},
	}
	ue.hasReply.Store(true)

	done := make(chan struct{})
	go func() {
		defer close(done)
		ue.start()
	}()

	conn.reads <- scriptedPacketRead{
		data: []byte("payload"),
		from: netip.MustParseAddrPort("203.0.113.10:3478"),
	}

	waitForCloseSignal(t, conn.closeCh, "handler error should retire the endpoint")

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for read loop to exit after handler error")
	}

	if !ue.IsDead() {
		t.Fatal("expected endpoint to be marked dead after handler error")
	}
}

func TestUdpEndpointWriteTo_ErrorClosesConn(t *testing.T) {
	conn := &scriptedPacketConn{
		writeErr: io.ErrClosedPipe,
		closeCh:  make(chan struct{}),
	}
	ue := &UdpEndpoint{
		conn:       conn,
		NatTimeout: QuicNatTimeout,
	}

	_, err := ue.WriteTo([]byte("payload"), "203.0.113.10:3478")
	if err == nil {
		t.Fatal("expected write error")
	}

	waitForCloseSignal(t, conn.closeCh, "write error should close the socket")

	if !ue.IsDead() {
		t.Fatal("expected endpoint to be marked dead after write error")
	}

	if err := ue.Close(); err != nil {
		t.Fatalf("unexpected close error: %v", err)
	}
	if got := conn.closeCalls.Load(); got != 1 {
		t.Fatalf("close calls = %d, want 1", got)
	}
}

func TestUdpEndpointWriteTo_ShortWriteClosesConn(t *testing.T) {
	conn := &scriptedPacketConn{
		writeN:      3,
		forceWriteN: true,
		closeCh:     make(chan struct{}),
	}
	ue := &UdpEndpoint{
		conn:       conn,
		NatTimeout: QuicNatTimeout,
	}

	_, err := ue.WriteTo([]byte("payload"), "203.0.113.10:3478")
	if err == nil {
		t.Fatal("expected short write error")
	}

	waitForCloseSignal(t, conn.closeCh, "short write should close the socket")

	if !ue.IsDead() {
		t.Fatal("expected endpoint to be marked dead after short write")
	}
}

func TestUdpEndpointUpdateNatTimeout_DoesNotExtendUnrepliedDeadline(t *testing.T) {
	now := time.Unix(1000, 0)
	ue := &UdpEndpoint{
		NatTimeout: DefaultNatTimeout,
	}

	ue.RefreshTtlWithTime(now.UnixNano())
	firstDeadline := ue.expiresAtNano.Load()
	ue.UpdateNatTimeout(QuicNatTimeout)

	if got := ue.expiresAtNano.Load(); got != firstDeadline {
		t.Fatalf("expiresAt = %v, want %v", got, firstDeadline)
	}
}

func TestUdpEndpointRefreshTtlWithTime_DoesNotStretchShortTimeout(t *testing.T) {
	now := time.Unix(1200, 0)
	timeout := 3 * time.Second
	ue := &UdpEndpoint{
		NatTimeout: timeout,
	}

	ue.RefreshTtlWithTime(now.UnixNano())

	got := time.Duration(ue.expiresAtNano.Load() - now.UnixNano())
	if got != timeout {
		t.Fatalf("expires delta = %v, want %v", got, timeout)
	}
}
