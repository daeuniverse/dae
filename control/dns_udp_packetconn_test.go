/*
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package control

import (
	"context"
	stderrors "errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
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

type timeoutNetError struct{}

func (timeoutNetError) Error() string   { return "i/o timeout" }
func (timeoutNetError) Timeout() bool   { return true }
func (timeoutNetError) Temporary() bool { return true }

type deadlineTimeoutUpstreamConn struct {
	serverAddr   netip.AddrPort
	deadlineNano atomic.Int64
	writeStarted chan struct{}
	writeOnce    sync.Once
	closed       atomic.Bool
	closeCalls   atomic.Int32
}

func (c *deadlineTimeoutUpstreamConn) Write(_ []byte) (int, error) {
	return 0, stderrors.New("Write should not be used for UDP PacketConn")
}

func (c *deadlineTimeoutUpstreamConn) Read(_ []byte) (int, error) {
	return 0, stderrors.New("Read should not be used for UDP PacketConn")
}

func (c *deadlineTimeoutUpstreamConn) WriteTo(p []byte, addr string) (int, error) {
	if addr != c.serverAddr.String() {
		return 0, stderrors.New("unexpected upstream address")
	}
	c.writeOnce.Do(func() {
		if c.writeStarted != nil {
			close(c.writeStarted)
		}
	})
	return len(p), nil
}

func (c *deadlineTimeoutUpstreamConn) ReadFrom(_ []byte) (int, netip.AddrPort, error) {
	deadlineNano := c.deadlineNano.Load()
	if deadlineNano > 0 {
		wait := time.Until(time.Unix(0, deadlineNano))
		if wait > 0 {
			timer := time.NewTimer(wait)
			defer timer.Stop()
			<-timer.C
		}
	}
	if c.closed.Load() {
		return 0, netip.AddrPort{}, io.EOF
	}
	return 0, netip.AddrPort{}, timeoutNetError{}
}

func (c *deadlineTimeoutUpstreamConn) Close() error {
	c.closeCalls.Add(1)
	c.closed.Store(true)
	return nil
}

func (c *deadlineTimeoutUpstreamConn) SetDeadline(t time.Time) error {
	c.deadlineNano.Store(t.UnixNano())
	return nil
}

func (c *deadlineTimeoutUpstreamConn) SetReadDeadline(t time.Time) error {
	return c.SetDeadline(t)
}

func (c *deadlineTimeoutUpstreamConn) SetWriteDeadline(_ time.Time) error {
	return nil
}

func TestDoUDPForwardDNSUsesPacketConnForUDP(t *testing.T) {
	serverAddr := netip.MustParseAddrPort("198.51.100.53:53")
	conn := &packetOnlyUpstreamConn{serverAddr: serverAddr}

	doUDP := &DoUDP{
		dialArgument: dialArgument{
			bestTarget: serverAddr,
		},
		pool: newUdpConnPool(1, 1, func(context.Context) (netproxy.Conn, error) {
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

func TestDoUDPForwardDNSPoolSaturationFailsFast(t *testing.T) {
	serverAddr := netip.MustParseAddrPort("198.51.100.53:53")
	writeStarted := make(chan struct{})
	timeoutConn := &deadlineTimeoutUpstreamConn{
		serverAddr:   serverAddr,
		writeStarted: writeStarted,
	}

	var dialCalls atomic.Int32
	doUDP := &DoUDP{
		dialArgument: dialArgument{
			bestTarget: serverAddr,
		},
		pool: newUdpConnPool(1, 1, func(context.Context) (netproxy.Conn, error) {
			dialCalls.Add(1)
			return timeoutConn, nil
		}),
	}
	defer func() {
		_ = doUDP.Close()
	}()

	req := dnsmessage.Msg{}
	req.SetQuestion("example.org.", dnsmessage.TypeA)
	packed, err := req.Pack()
	if err != nil {
		t.Fatalf("Pack failed: %v", err)
	}

	firstCtx, firstCancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer firstCancel()

	firstErrCh := make(chan error, 1)
	go func() {
		_, err := doUDP.ForwardDNS(firstCtx, packed)
		firstErrCh <- err
	}()

	select {
	case <-writeStarted:
	case <-time.After(time.Second):
		t.Fatal("first request did not reach upstream write")
	}

	secondCtx, secondCancel := context.WithTimeout(context.Background(), time.Second)
	defer secondCancel()

	start := time.Now()
	_, err = doUDP.ForwardDNS(secondCtx, packed)
	elapsed := time.Since(start)
	if !stderrors.Is(err, ErrDNSUDPConnPoolExhausted) {
		t.Fatalf("second ForwardDNS error = %v, want pool exhaustion", err)
	}
	if elapsed > 50*time.Millisecond {
		t.Fatalf("second ForwardDNS took %v, want fast local rejection", elapsed)
	}
	if got := dialCalls.Load(); got != 1 {
		t.Fatalf("dial calls after saturated request = %d, want 1", got)
	}

	err = <-firstErrCh
	var netErr net.Error
	if !stderrors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("first ForwardDNS error = %v, want timeout", err)
	}

	thirdCtx, thirdCancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer thirdCancel()

	_, err = doUDP.ForwardDNS(thirdCtx, packed)
	if !stderrors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("third ForwardDNS error = %v, want timeout", err)
	}
	if got := dialCalls.Load(); got != 1 {
		t.Fatalf("dial calls after timed-out reuse = %d, want 1", got)
	}
}

func TestDoUDPForwardDNSProxyTimeoutDiscardsConnAndRedials(t *testing.T) {
	serverAddr := netip.MustParseAddrPort("198.51.100.53:53")
	var (
		mu        sync.Mutex
		conns     []*deadlineTimeoutUpstreamConn
		dialCalls atomic.Int32
	)

	proxyDialer := newTestProxyEndpointDialer("hysteria2", "proxy.example:443")
	doUDP := &DoUDP{
		dialArgument: dialArgument{
			bestDialer: proxyDialer,
			bestTarget: serverAddr,
		},
		pool: newUdpConnPool(1, 1, func(context.Context) (netproxy.Conn, error) {
			dialCalls.Add(1)
			conn := &deadlineTimeoutUpstreamConn{serverAddr: serverAddr}
			mu.Lock()
			conns = append(conns, conn)
			mu.Unlock()
			return conn, nil
		}),
	}
	defer func() {
		_ = doUDP.Close()
	}()

	req := dnsmessage.Msg{}
	req.SetQuestion("example.org.", dnsmessage.TypeA)
	packed, err := req.Pack()
	if err != nil {
		t.Fatalf("Pack failed: %v", err)
	}

	ctx1, cancel1 := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel1()
	_, err = doUDP.ForwardDNS(ctx1, packed)
	var netErr net.Error
	if !stderrors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("first ForwardDNS error = %v, want timeout", err)
	}

	ctx2, cancel2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel2()
	_, err = doUDP.ForwardDNS(ctx2, packed)
	if !stderrors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("second ForwardDNS error = %v, want timeout", err)
	}

	if got := dialCalls.Load(); got != 2 {
		t.Fatalf("dial calls after proxy timeouts = %d, want 2", got)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(conns) != 2 {
		t.Fatalf("created conns = %d, want 2", len(conns))
	}
	if got := conns[0].closeCalls.Load(); got != 1 {
		t.Fatalf("first conn close calls = %d, want 1", got)
	}
	if got := conns[1].closeCalls.Load(); got != 1 {
		t.Fatalf("second conn close calls = %d, want 1", got)
	}
}
