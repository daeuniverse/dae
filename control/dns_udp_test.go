/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	dnsmessage "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

type mockUdpDatagramConn struct {
	mu         sync.Mutex
	responses  [][]byte
	closed     bool
	closeCalls int
	deadline   time.Time
}

func (m *mockUdpDatagramConn) Read(b []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return 0, net.ErrClosed
	}
	if len(m.responses) == 0 {
		return 0, &net.DNSError{IsTimeout: true}
	}

	pkt := m.responses[0]
	m.responses = m.responses[1:]
	return copy(b, pkt), nil
}

func (m *mockUdpDatagramConn) Write(b []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return 0, net.ErrClosed
	}
	return len(b), nil
}

func (m *mockUdpDatagramConn) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	m.closeCalls++
	return nil
}

func (m *mockUdpDatagramConn) SetDeadline(t time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deadline = t
	return nil
}

func (m *mockUdpDatagramConn) SetReadDeadline(t time.Time) error {
	return m.SetDeadline(t)
}

func (m *mockUdpDatagramConn) SetWriteDeadline(t time.Time) error {
	return m.SetDeadline(t)
}

func buildDNSResponsePacket(t *testing.T, id uint16, qname string) []byte {
	t.Helper()

	req := new(dnsmessage.Msg)
	req.SetQuestion(qname, dnsmessage.TypeA)
	req.Id = id

	resp := new(dnsmessage.Msg)
	resp.SetReply(req)
	resp.Answer = []dnsmessage.RR{
		&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{
				Name:   dnsmessage.Fqdn(qname),
				Rrtype: dnsmessage.TypeA,
				Class:  dnsmessage.ClassINET,
				Ttl:    60,
			},
			A: net.IPv4(1, 1, 1, 1),
		},
	}

	b, err := resp.Pack()
	require.NoError(t, err)
	return b
}

func TestDoUDP_ForwardDNS_DiscardStaleResponseThenSucceed(t *testing.T) {
	const (
		reqID = 0x1234
		qname = "one.one.one.one."
	)

	req := new(dnsmessage.Msg)
	req.SetQuestion(qname, dnsmessage.TypeA)
	req.Id = reqID
	data, err := req.Pack()
	require.NoError(t, err)

	stale := buildDNSResponsePacket(t, 0x4321, qname)
	valid := buildDNSResponsePacket(t, reqID, qname)

	mockConn := &mockUdpDatagramConn{
		responses: [][]byte{stale, valid},
	}

	forwarder := &DoUDP{
		pool: newUdpConnPool(1, func(context.Context) (netproxy.Conn, error) {
			return mockConn, nil
		}),
	}
	defer func() { _ = forwarder.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	respMsg, err := forwarder.ForwardDNS(ctx, data)
	require.NoError(t, err)
	require.NotNil(t, respMsg)
	require.Equal(t, uint16(reqID), respMsg.Id)

	mockConn.mu.Lock()
	defer mockConn.mu.Unlock()
	require.Equal(t, 0, mockConn.closeCalls)
}

func TestDoUDP_ForwardDNS_TooManyStaleResponsesClosesConn(t *testing.T) {
	const (
		reqID = 0x5678
		qname = "one.one.one.one."
	)

	req := new(dnsmessage.Msg)
	req.SetQuestion(qname, dnsmessage.TypeA)
	req.Id = reqID
	data, err := req.Pack()
	require.NoError(t, err)

	responses := make([][]byte, 9)
	for i := range responses {
		responses[i] = buildDNSResponsePacket(t, uint16(i+1), qname)
	}

	mockConn := &mockUdpDatagramConn{responses: responses}

	forwarder := &DoUDP{
		pool: newUdpConnPool(1, func(context.Context) (netproxy.Conn, error) {
			return mockConn, nil
		}),
	}
	defer func() { _ = forwarder.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	respMsg, err := forwarder.ForwardDNS(ctx, data)
	require.Nil(t, respMsg)
	require.Error(t, err)
	require.ErrorContains(t, err, "too many stale UDP DNS responses")

	mockConn.mu.Lock()
	defer mockConn.mu.Unlock()
	require.GreaterOrEqual(t, mockConn.closeCalls, 1)
	require.True(t, mockConn.closed)
}
