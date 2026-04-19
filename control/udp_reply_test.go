/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

func readUdpReplyPacket(t *testing.T, conn *net.UDPConn) ([]byte, netip.AddrPort) {
	t.Helper()

	buf := make([]byte, 2048)
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline() error = %v", err)
	}
	n, from, err := conn.ReadFromUDPAddrPort(buf)
	if err != nil {
		t.Fatalf("ReadFromUDPAddrPort() error = %v", err)
	}
	return append([]byte(nil), buf[:n]...), from
}

func TestForwardUdpEndpointReplyToClient_IgnoresLocalSendErrors(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	var calls int
	err := forwardUdpEndpointReplyToClient(
		logger,
		&UdpEndpoint{},
		[]byte("payload"),
		netip.MustParseAddrPort("203.0.113.10:3478"),
		netip.MustParseAddrPort("192.0.2.10:40000"),
		func(_ *logrus.Logger, _ []byte, _ netip.AddrPort, _ netip.AddrPort, _ udpEndpointResponseConnSlot) error {
			calls++
			return io.ErrClosedPipe
		},
	)
	if err != nil {
		t.Fatalf("forwardUdpEndpointReplyToClient() err = %v, want nil", err)
	}
	if calls != 1 {
		t.Fatalf("send calls = %d, want 1", calls)
	}
}

func TestUdpEndpointStart_LocalReplySendErrorDoesNotRetireConn(t *testing.T) {
	conn := &scriptedPacketConn{
		reads:   make(chan scriptedPacketRead, 1),
		closeCh: make(chan struct{}),
	}
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	handled := make(chan struct{}, 1)
	ue := &UdpEndpoint{
		conn:       conn,
		NatTimeout: QuicNatTimeout,
		handler: func(ue *UdpEndpoint, data []byte, from netip.AddrPort) error {
			err := forwardUdpEndpointReplyToClient(
				logger,
				ue,
				data,
				from,
				netip.MustParseAddrPort("192.0.2.10:40000"),
				func(_ *logrus.Logger, _ []byte, _ netip.AddrPort, _ netip.AddrPort, _ udpEndpointResponseConnSlot) error {
					return io.ErrClosedPipe
				},
			)
			handled <- struct{}{}
			return err
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

	select {
	case <-handled:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for handler to process reply packet")
	}

	time.Sleep(50 * time.Millisecond)

	select {
	case <-conn.closeCh:
		t.Fatal("expected endpoint to remain open after local reply send error")
	default:
	}

	if ue.IsDead() {
		t.Fatal("expected endpoint to remain alive after local reply send error")
	}

	if err := ue.Close(); err != nil {
		t.Fatalf("unexpected close error: %v", err)
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for read loop to exit after close")
	}
}

func TestUdpEndpointStart_BackpressurePreservesAllReplies(t *testing.T) {
	const totalReplies = udpEndpointReplyQueueSize + 64

	conn := &scriptedPacketConn{
		reads:   make(chan scriptedPacketRead, totalReplies+1),
		closeCh: make(chan struct{}),
	}

	var (
		mu       sync.Mutex
		handled  = make([]int, 0, totalReplies)
		seen     atomic.Int64
		replySrc = netip.MustParseAddrPort("203.0.113.10:3478")
	)

	ue := &UdpEndpoint{
		conn:       conn,
		NatTimeout: QuicNatTimeout,
		handler: func(_ *UdpEndpoint, data []byte, from netip.AddrPort) error {
			if from != replySrc {
				t.Fatalf("handler from = %v, want %v", from, replySrc)
			}
			if len(data) < 2 {
				t.Fatalf("handler data length = %d, want at least 2", len(data))
			}
			seq := int(data[0])<<8 | int(data[1])
			mu.Lock()
			handled = append(handled, seq)
			mu.Unlock()
			seen.Add(1)
			// Slow the sender enough to force the read loop into its burst path.
			time.Sleep(2 * time.Millisecond)
			return nil
		},
	}
	ue.hasReply.Store(true)

	done := make(chan struct{})
	go func() {
		defer close(done)
		ue.start()
	}()

	for i := 0; i < totalReplies; i++ {
		conn.reads <- scriptedPacketRead{
			data: []byte{byte(i >> 8), byte(i)},
			from: replySrc,
		}
	}
	conn.reads <- scriptedPacketRead{err: io.EOF}

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for read loop to drain reply backlog")
	}

	if got := int(seen.Load()); got != totalReplies {
		t.Fatalf("handled replies = %d, want %d", got, totalReplies)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(handled) != totalReplies {
		t.Fatalf("handled sequence count = %d, want %d", len(handled), totalReplies)
	}
	for i, seq := range handled {
		if seq != i {
			t.Fatalf("handled[%d] = %d, want %d", i, seq, i)
		}
	}
}

func TestForwardUdpEndpointReplyToClient_FullConeCacheTracksReplySourceAddr(t *testing.T) {
	oldAnyfromPool := DefaultAnyfromPool
	DefaultAnyfromPool = newTestAnyfromPoolWithoutJanitor()
	defer func() {
		DefaultAnyfromPool.Reset()
		DefaultAnyfromPool = oldAnyfromPool
	}()

	clientConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP(client) error = %v", err)
	}
	defer func() {
		_ = clientConn.Close()
	}()
	clientAddr := clientConn.LocalAddr().(*net.UDPAddr).AddrPort()

	replyConnA, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP(reply A) error = %v", err)
	}
	replyConnB, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		_ = replyConnA.Close()
		t.Fatalf("ListenUDP(reply B) error = %v", err)
	}

	replyAddrA := replyConnA.LocalAddr().(*net.UDPAddr).AddrPort()
	replyAddrB := replyConnB.LocalAddr().(*net.UDPAddr).AddrPort()
	afA := &Anyfrom{UDPConn: replyConnA, ttl: AnyfromTimeout}
	afA.RefreshTtl()
	afB := &Anyfrom{UDPConn: replyConnB, ttl: AnyfromTimeout}
	afB.RefreshTtl()

	shardA := DefaultAnyfromPool.shardFor(replyAddrA)
	shardA.mu.Lock()
	shardA.pool[replyAddrA] = afA
	shardA.mu.Unlock()

	shardB := DefaultAnyfromPool.shardFor(replyAddrB)
	shardB.mu.Lock()
	shardB.pool[replyAddrB] = afB
	shardB.mu.Unlock()

	ue := &UdpEndpoint{
		lAddr:   clientAddr,
		poolKey: UdpEndpointKey{Src: clientAddr},
	}
	ue.prewarmResponseConn(replyAddrA.String())
	if got := ue.CachedResponseConn(replyAddrA); got != afA {
		t.Fatalf("CachedResponseConn(replyAddrA) = %p, want %p", got, afA)
	}

	payloadA1 := []byte("reply-a-1")
	if err := forwardUdpEndpointReplyToClient(nil, ue, payloadA1, replyAddrA, clientAddr, nil); err != nil {
		t.Fatalf("forward first reply from A: %v", err)
	}
	gotData, gotFrom := readUdpReplyPacket(t, clientConn)
	if gotFrom != replyAddrA {
		t.Fatalf("first reply source = %v, want %v", gotFrom, replyAddrA)
	}
	if string(gotData) != string(payloadA1) {
		t.Fatalf("first reply payload = %q, want %q", gotData, payloadA1)
	}

	payloadB := []byte("reply-b")
	if err := forwardUdpEndpointReplyToClient(nil, ue, payloadB, replyAddrB, clientAddr, nil); err != nil {
		t.Fatalf("forward reply from B: %v", err)
	}
	gotData, gotFrom = readUdpReplyPacket(t, clientConn)
	if gotFrom != replyAddrB {
		t.Fatalf("second reply source = %v, want %v", gotFrom, replyAddrB)
	}
	if string(gotData) != string(payloadB) {
		t.Fatalf("second reply payload = %q, want %q", gotData, payloadB)
	}
	if got := ue.CachedResponseConn(replyAddrB); got != afB {
		t.Fatalf("CachedResponseConn(replyAddrB) = %p, want %p", got, afB)
	}

	payloadA2 := []byte("reply-a-2")
	if err := forwardUdpEndpointReplyToClient(nil, ue, payloadA2, replyAddrA, clientAddr, nil); err != nil {
		t.Fatalf("forward second reply from A: %v", err)
	}
	gotData, gotFrom = readUdpReplyPacket(t, clientConn)
	if gotFrom != replyAddrA {
		t.Fatalf("third reply source = %v, want %v", gotFrom, replyAddrA)
	}
	if string(gotData) != string(payloadA2) {
		t.Fatalf("third reply payload = %q, want %q", gotData, payloadA2)
	}

	if got := afA.pins.Load(); got != 1 {
		t.Fatalf("reply source A pins = %d, want 1", got)
	}
	if got := afB.pins.Load(); got != 1 {
		t.Fatalf("reply source B pins = %d, want 1", got)
	}

	if err := ue.Close(); err != nil {
		t.Fatalf("UdpEndpoint.Close() error = %v", err)
	}
	if got := afA.pins.Load(); got != 0 {
		t.Fatalf("reply source A pins after close = %d, want 0", got)
	}
	if got := afB.pins.Load(); got != 0 {
		t.Fatalf("reply source B pins after close = %d, want 0", got)
	}
}
