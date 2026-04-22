/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package netutils

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/direct"
	dnsmessage "github.com/miekg/dns"
)

func TestResolveIp46(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	direct.InitDirectDialers("223.5.5.5:53")
	ip46, err4, err6 := ResolveIp46(ctx, direct.SymmetricDirect, netip.MustParseAddrPort("223.5.5.5:53"), "ipv6.google.com", "udp", false)
	// Skip test if network is unavailable or DNS resolution fails completely
	if err4 != nil || err6 != nil {
		t.Skipf("network unavailable or DNS blocked in test environment: err4=%v err6=%v", err4, err6)
	}
	if !ip46.Ip4.IsValid() && !ip46.Ip6.IsValid() {
		t.Skip("DNS resolution returned no valid records (likely network restriction)")
	}
	t.Log(ip46)
}

func TestResolveIp46RaceWaitsForFirstSuccessfulAnswer(t *testing.T) {
	serverAddr := netip.MustParseAddrPort("203.0.113.53:53")
	dialer := scriptedDNSDialer{serverAddr: serverAddr}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	ip46, err4, err6 := ResolveIp46(ctx, dialer, serverAddr, "example.com", "udp", true)
	if err4 != nil {
		t.Fatalf("unexpected IPv4 error: %v", err4)
	}
	if err6 != nil {
		t.Fatalf("unexpected IPv6 error: %v", err6)
	}
	if ip46.Ip4.IsValid() {
		t.Fatalf("expected no IPv4 result, got %v", ip46.Ip4)
	}
	if got := ip46.Ip6.String(); got != "2001:db8::1" {
		t.Fatalf("unexpected IPv6 result: got %s want 2001:db8::1", got)
	}
}

type scriptedDNSDialer struct {
	serverAddr netip.AddrPort
}

func (d scriptedDNSDialer) DialContext(_ context.Context, _, _ string) (netproxy.Conn, error) {
	return &scriptedDNSConn{serverAddr: d.serverAddr}, nil
}

type scriptedDNSConn struct {
	serverAddr netip.AddrPort

	mu       sync.Mutex
	delay    time.Duration
	response []byte
}

func (c *scriptedDNSConn) Write(_ []byte) (int, error) {
	return 0, errors.New("Write should not be used for UDP PacketConn")
}

func (c *scriptedDNSConn) Read(_ []byte) (int, error) {
	return 0, errors.New("Read should not be used for UDP PacketConn")
}

func (c *scriptedDNSConn) WriteTo(p []byte, addr string) (int, error) {
	if addr != c.serverAddr.String() {
		return 0, errors.New("unexpected upstream address")
	}

	var req dnsmessage.Msg
	if err := req.Unpack(p); err != nil {
		return 0, err
	}
	if len(req.Question) == 0 {
		return 0, errors.New("missing DNS question")
	}

	resp := dnsmessage.Msg{
		MsgHdr: dnsmessage.MsgHdr{
			Id:       req.Id,
			Response: true,
		},
		Question: req.Question,
	}

	c.mu.Lock()
	switch req.Question[0].Qtype {
	case dnsmessage.TypeA:
		c.delay = 10 * time.Millisecond
	case dnsmessage.TypeAAAA:
		c.delay = 80 * time.Millisecond
		resp.Answer = append(resp.Answer, &dnsmessage.AAAA{
			Hdr: dnsmessage.RR_Header{
				Name:   req.Question[0].Name,
				Rrtype: dnsmessage.TypeAAAA,
				Class:  dnsmessage.ClassINET,
				Ttl:    60,
			},
			AAAA: netip.MustParseAddr("2001:db8::1").AsSlice(),
		})
	default:
		c.mu.Unlock()
		return 0, errors.New("unexpected DNS qtype")
	}

	packed, err := resp.Pack()
	if err != nil {
		c.mu.Unlock()
		return 0, err
	}
	c.response = packed
	c.mu.Unlock()

	return len(p), nil
}

func (c *scriptedDNSConn) ReadFrom(p []byte) (int, netip.AddrPort, error) {
	c.mu.Lock()
	delay := c.delay
	response := append([]byte(nil), c.response...)
	c.mu.Unlock()

	time.Sleep(delay)
	if len(response) == 0 {
		return 0, netip.AddrPort{}, io.EOF
	}
	n := copy(p, response)
	return n, c.serverAddr, nil
}

func (c *scriptedDNSConn) Close() error                       { return nil }
func (c *scriptedDNSConn) SetDeadline(_ time.Time) error      { return nil }
func (c *scriptedDNSConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *scriptedDNSConn) SetWriteDeadline(_ time.Time) error { return nil }
