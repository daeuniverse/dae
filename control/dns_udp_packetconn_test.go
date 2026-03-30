/*
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package control

import (
	"context"
	stderrors "errors"
	"io"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	dnsmessage "github.com/miekg/dns"
)

type packetOnlyUpstreamConn struct {
	serverAddr netip.AddrPort

	mu          sync.Mutex
	response    []byte
	writeCalls  int
	readCalls   int
	writeToHits int
	readFromHit int
}

func (c *packetOnlyUpstreamConn) Write(_ []byte) (int, error) {
	c.mu.Lock()
	c.writeCalls++
	c.mu.Unlock()
	return 0, stderrors.New("Write should not be used for UDP PacketConn")
}

func (c *packetOnlyUpstreamConn) Read(_ []byte) (int, error) {
	c.mu.Lock()
	c.readCalls++
	c.mu.Unlock()
	return 0, stderrors.New("Read should not be used for UDP PacketConn")
}

func (c *packetOnlyUpstreamConn) WriteTo(p []byte, addr string) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.writeToHits++
	if addr != c.serverAddr.String() {
		return 0, stderrors.New("unexpected upstream address")
	}

	var req dnsmessage.Msg
	if err := req.Unpack(p); err != nil {
		return 0, err
	}
	if len(req.Question) == 0 {
		return 0, stderrors.New("missing DNS question")
	}

	resp := dnsmessage.Msg{
		MsgHdr: dnsmessage.MsgHdr{
			Id:       req.Id,
			Response: true,
		},
		Question: req.Question,
		Answer: []dnsmessage.RR{
			&dnsmessage.A{
				Hdr: dnsmessage.RR_Header{
					Name:   req.Question[0].Name,
					Rrtype: dnsmessage.TypeA,
					Class:  dnsmessage.ClassINET,
					Ttl:    60,
				},
				A: []byte{198, 51, 100, 9},
			},
		},
	}
	packed, err := resp.Pack()
	if err != nil {
		return 0, err
	}
	c.response = packed
	return len(p), nil
}

func (c *packetOnlyUpstreamConn) ReadFrom(p []byte) (int, netip.AddrPort, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.readFromHit++
	if len(c.response) == 0 {
		return 0, netip.AddrPort{}, io.EOF
	}
	n := copy(p, c.response)
	c.response = nil
	return n, c.serverAddr, nil
}

func (c *packetOnlyUpstreamConn) Close() error                       { return nil }
func (c *packetOnlyUpstreamConn) SetDeadline(_ time.Time) error      { return nil }
func (c *packetOnlyUpstreamConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *packetOnlyUpstreamConn) SetWriteDeadline(_ time.Time) error { return nil }

func TestDoUDPForwardDNSUsesPacketConnForUDP(t *testing.T) {
	serverAddr := netip.MustParseAddrPort("198.51.100.53:53")
	conn := &packetOnlyUpstreamConn{serverAddr: serverAddr}

	doUDP := &DoUDP{
		dialArgument: dialArgument{
			bestTarget: serverAddr,
		},
		pool: newUdpConnPool(1, func(context.Context) (netproxy.Conn, error) {
			return conn, nil
		}),
	}

	req := dnsmessage.Msg{}
	req.SetQuestion("example.org.", dnsmessage.TypeA)
	packed, err := req.Pack()
	if err != nil {
		t.Fatalf("Pack failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := doUDP.ForwardDNS(ctx, packed)
	if err != nil {
		t.Fatalf("ForwardDNS failed: %v", err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("unexpected answer count: got %d want 1", len(resp.Answer))
	}

	a, ok := resp.Answer[0].(*dnsmessage.A)
	if !ok {
		t.Fatalf("unexpected answer type: %T", resp.Answer[0])
	}
	ip, ok := netip.AddrFromSlice(a.A)
	if !ok {
		t.Fatalf("failed to parse answer IP: %v", a.A)
	}
	if got := ip.String(); got != "198.51.100.9" {
		t.Fatalf("unexpected answer IP: got %s want 198.51.100.9", got)
	}

	conn.mu.Lock()
	defer conn.mu.Unlock()
	if conn.writeCalls != 0 {
		t.Fatalf("unexpected stream Write usage: %d", conn.writeCalls)
	}
	if conn.readCalls != 0 {
		t.Fatalf("unexpected stream Read usage: %d", conn.readCalls)
	}
	if conn.writeToHits == 0 {
		t.Fatal("expected WriteTo to be used")
	}
	if conn.readFromHit == 0 {
		t.Fatal("expected ReadFrom to be used")
	}
}
