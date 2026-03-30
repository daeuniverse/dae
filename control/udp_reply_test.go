/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"io"
	"net/netip"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

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
		func(_ *logrus.Logger, _ []byte, _ netip.AddrPort, _ netip.AddrPort, _ **Anyfrom) error {
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
				func(_ *logrus.Logger, _ []byte, _ netip.AddrPort, _ netip.AddrPort, _ **Anyfrom) error {
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
