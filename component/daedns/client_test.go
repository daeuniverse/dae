/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@daeuniverse.org>
 */

package daedns

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/netutils"
	componentdns "github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/direct"
	dnsmessage "github.com/miekg/dns"
)

type testTrackingTransport struct {
	closed bool
}

func (t *testTrackingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, nil
}

func (t *testTrackingTransport) CloseIdleConnections() {
	t.closed = true
}

func TestQueryHTTPSClosesIdleConnections(t *testing.T) {
	originalTransportFunc := newHTTPTransportFunc
	originalSendHTTPDNSFunc := sendHTTPDNSFunc
	t.Cleanup(func() {
		newHTTPTransportFunc = originalTransportFunc
		sendHTTPDNSFunc = originalSendHTTPDNSFunc
	})

	upstream := &componentdns.Upstream{
		Hostname: "dns.example.com",
		Path:     "/dns-query",
	}
	target := netip.MustParseAddrPort("1.1.1.1:443")

	for _, tt := range []struct {
		name      string
		http3Mode bool
	}{
		{name: "http", http3Mode: false},
		{name: "http3", http3Mode: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			transport := &testTrackingTransport{}
			newHTTPTransportFunc = func(_ *Router, _ *componentdns.Upstream, _ netip.AddrPort, http3Mode bool) http.RoundTripper {
				if http3Mode != tt.http3Mode {
					t.Fatalf("unexpected http3Mode = %v, want %v", http3Mode, tt.http3Mode)
				}
				return transport
			}
			sendHTTPDNSFunc = func(_ context.Context, client *http.Client, _ string, _ *componentdns.Upstream, _ []byte) (*dnsmessage.Msg, error) {
				if client.Transport != transport {
					t.Fatal("expected queryHTTPS to use injected transport")
				}
				return &dnsmessage.Msg{}, nil
			}

			router := &Router{}
			if _, err := router.queryHTTPS(context.Background(), upstream, target, []byte{0, 0}, tt.http3Mode); err != nil {
				t.Fatalf("queryHTTPS() error = %v", err)
			}
			if !transport.closed {
				t.Fatal("expected idle connections to be closed")
			}
		})
	}
}

func TestLookupTypeDedupCancelsSharedLookupWhenLastWaiterLeaves(t *testing.T) {
	originalTransportFunc := newHTTPTransportFunc
	originalSendHTTPDNSFunc := sendHTTPDNSFunc
	t.Cleanup(func() {
		newHTTPTransportFunc = originalTransportFunc
		sendHTTPDNSFunc = originalSendHTTPDNSFunc
	})

	lookupStarted := make(chan struct{})
	lookupCanceled := make(chan struct{})
	var invocations atomic.Int32

	newHTTPTransportFunc = func(_ *Router, _ *componentdns.Upstream, _ netip.AddrPort, _ bool) http.RoundTripper {
		return &testTrackingTransport{}
	}
	sendHTTPDNSFunc = func(ctx context.Context, _ *http.Client, _ string, _ *componentdns.Upstream, _ []byte) (*dnsmessage.Msg, error) {
		invocations.Add(1)
		select {
		case <-lookupStarted:
		default:
			close(lookupStarted)
		}
		<-ctx.Done()
		select {
		case <-lookupCanceled:
		default:
			close(lookupCanceled)
		}
		return nil, ctx.Err()
	}

	router := &Router{lookupCalls: make(map[string]*lookupCall)}
	upstream := &componentdns.Upstream{
		Scheme:   componentdns.UpstreamScheme_HTTPS,
		Hostname: "dns.example.com",
		Path:     "/dns-query",
		Port:     443,
		Ip46: &netutils.Ip46{
			Ip4: netip.MustParseAddr("203.0.113.53"),
		},
	}

	firstCtx, firstCancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer firstCancel()
	secondCtx, secondCancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer secondCancel()

	errCh := make(chan error, 2)
	go func() {
		_, err := router.lookupTypeDedup(firstCtx, upstream, "example.com", dnsmessage.TypeA)
		errCh <- err
	}()

	select {
	case <-lookupStarted:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for shared lookup to start")
	}

	go func() {
		_, err := router.lookupTypeDedup(secondCtx, upstream, "example.com", dnsmessage.TypeA)
		errCh <- err
	}()

	for range 2 {
		select {
		case err := <-errCh:
			if err == nil || !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("lookupTypeDedup() error = %v, want context deadline exceeded", err)
			}
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for callers to return")
		}
	}

	if invocations.Load() != 1 {
		t.Fatalf("shared lookup invocations = %d, want 1", invocations.Load())
	}

	select {
	case <-lookupCanceled:
	case <-time.After(300 * time.Millisecond):
		t.Fatal("shared lookup did not stop after the last waiter canceled")
	}
}

type stubDirectDialer struct {
	conn netproxy.Conn
}

func (d stubDirectDialer) DialContext(_ context.Context, _, _ string) (netproxy.Conn, error) {
	return d.conn, nil
}

type largeUDPResponseConn struct {
	serverAddr  netip.AddrPort
	response    []byte
	responseLen int
}

func (c *largeUDPResponseConn) Write(_ []byte) (int, error) {
	return 0, fmt.Errorf("Write should not be used for UDP PacketConn")
}

func (c *largeUDPResponseConn) Read(_ []byte) (int, error) {
	return 0, fmt.Errorf("Read should not be used for UDP PacketConn")
}

func (c *largeUDPResponseConn) WriteTo(p []byte, addr string) (int, error) {
	if addr != c.serverAddr.String() {
		return 0, fmt.Errorf("unexpected upstream address %q", addr)
	}

	var req dnsmessage.Msg
	if err := req.Unpack(p); err != nil {
		return 0, err
	}
	if len(req.Question) == 0 {
		return 0, fmt.Errorf("missing DNS question")
	}

	resp := dnsmessage.Msg{
		MsgHdr: dnsmessage.MsgHdr{
			Id:       req.Id,
			Response: true,
		},
		Question: req.Question,
	}
	for i := 0; i < 400; i++ {
		resp.Answer = append(resp.Answer, &dnsmessage.A{
			Hdr: dnsmessage.RR_Header{
				Name:   req.Question[0].Name,
				Rrtype: dnsmessage.TypeA,
				Class:  dnsmessage.ClassINET,
				Ttl:    60,
			},
			A: []byte{203, 0, 113, byte(i%250 + 1)},
		})
	}
	packed, err := resp.Pack()
	if err != nil {
		return 0, err
	}
	c.response = packed
	c.responseLen = len(packed)
	return len(p), nil
}

func (c *largeUDPResponseConn) ReadFrom(p []byte) (int, netip.AddrPort, error) {
	if len(c.response) == 0 {
		return 0, netip.AddrPort{}, io.EOF
	}
	n := copy(p, c.response)
	c.response = nil
	return n, c.serverAddr, nil
}

func (c *largeUDPResponseConn) Close() error                       { return nil }
func (c *largeUDPResponseConn) SetDeadline(_ time.Time) error      { return nil }
func (c *largeUDPResponseConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *largeUDPResponseConn) SetWriteDeadline(_ time.Time) error { return nil }

func TestLookupTypeHandlesLargeUDPResponse(t *testing.T) {
	originalDirectDialer := direct.SymmetricDirect
	t.Cleanup(func() {
		direct.SymmetricDirect = originalDirectDialer
	})

	serverAddr := netip.MustParseAddrPort("203.0.113.53:53")
	conn := &largeUDPResponseConn{serverAddr: serverAddr}
	direct.SymmetricDirect = stubDirectDialer{conn: conn}

	router := &Router{}
	upstream := &componentdns.Upstream{
		Scheme: componentdns.UpstreamScheme_UDP,
		Port:   serverAddr.Port(),
		Ip46: &netutils.Ip46{
			Ip4: serverAddr.Addr(),
		},
	}

	ips, err := router.lookupType(context.Background(), upstream, "large.example.com", dnsmessage.TypeA)
	if err != nil {
		t.Fatalf("lookupType() error = %v", err)
	}
	if conn.responseLen <= 4096 {
		t.Fatalf("udp response length = %d, want > 4096", conn.responseLen)
	}
	if len(ips) != 400 {
		t.Fatalf("lookupType() returned %d addresses, want 400", len(ips))
	}
}
