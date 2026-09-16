/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package daedns

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	componentdns "github.com/daeuniverse/dae/component/dns"
	dnsmessage "github.com/miekg/dns"
	"github.com/olicesx/quic-go"
	"github.com/olicesx/quic-go/congestion"
)

type countingCloser struct {
	closed atomic.Int32
}

func (c *countingCloser) Close() error {
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

type countingRoundTripper struct {
	closed atomic.Int32
}

func (t *countingRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("unused")
}

func (t *countingRoundTripper) Close() error {
	t.closed.Add(1)
	return nil
}

type blockingCloseRoundTripper struct {
	closed  atomic.Int32
	started chan struct{}
	release chan struct{}
}

func (t *blockingCloseRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("unused")
}

func (t *blockingCloseRoundTripper) Close() error {
	t.started <- struct{}{}
	<-t.release
	t.closed.Add(1)
	return nil
}

func TestQueryHTTPSReusesHTTP3Client(t *testing.T) {
	t.Parallel()

	transports := 0
	seen := make([]*http.Client, 0, 2)
	r := &Router{
		httpTransportFactory: func(*Router, *componentdns.Upstream, netip.AddrPort, bool) http.RoundTripper {
			transports++
			return &countingRoundTripper{}
		},
		httpSendFunc: func(_ context.Context, client *http.Client, _ string, _ *componentdns.Upstream, _ []byte) (*dnsmessage.Msg, error) {
			seen = append(seen, client)
			return &dnsmessage.Msg{MsgHdr: dnsmessage.MsgHdr{Id: 7}}, nil
		},
	}
	defer func() { _ = r.Close() }()
	upstream := &componentdns.Upstream{Scheme: componentdns.UpstreamScheme_H3, Hostname: "dns.example", Port: 443, Path: "/dns-query"}
	target := netip.MustParseAddrPort("1.1.1.1:443")

	if _, err := r.queryHTTPS(context.Background(), upstream, target, []byte("q1"), true); err != nil {
		t.Fatalf("first queryHTTPS: %v", err)
	}
	if _, err := r.queryHTTPS(context.Background(), upstream, target, []byte("q2"), true); err != nil {
		t.Fatalf("second queryHTTPS: %v", err)
	}
	if transports != 1 {
		t.Fatalf("transports created = %d, want 1", transports)
	}
	if len(seen) != 2 || seen[0] != seen[1] {
		t.Fatal("consecutive H3 queries must reuse the same HTTP client")
	}
	if seen[0].CheckRedirect == nil {
		t.Fatal("redirect policy must be configured when the shared client is created")
	}
}

func TestQueryHTTPSReplacesClientOnFailureAndCloseReleasesIt(t *testing.T) {
	t.Parallel()

	first := &countingRoundTripper{}
	second := &countingRoundTripper{}
	created := 0
	attempts := 0
	r := &Router{
		httpTransportFactory: func(*Router, *componentdns.Upstream, netip.AddrPort, bool) http.RoundTripper {
			created++
			if created == 1 {
				return first
			}
			return second
		},
		httpSendFunc: func(_ context.Context, _ *http.Client, _ string, _ *componentdns.Upstream, _ []byte) (*dnsmessage.Msg, error) {
			attempts++
			if attempts == 1 {
				return nil, net.ErrClosed
			}
			return &dnsmessage.Msg{MsgHdr: dnsmessage.MsgHdr{Id: 9}}, nil
		},
	}
	upstream := &componentdns.Upstream{Scheme: componentdns.UpstreamScheme_H3, Hostname: "dns.example", Port: 443, Path: "/dns-query"}
	target := netip.MustParseAddrPort("1.1.1.1:443")

	if _, err := r.queryHTTPS(context.Background(), upstream, target, []byte("q"), true); err != nil {
		t.Fatalf("queryHTTPS: %v", err)
	}
	if created != 2 {
		t.Fatalf("transports created = %d, want 2", created)
	}
	if got := first.closed.Load(); got != 1 {
		t.Fatalf("failed transport Close count = %d, want 1", got)
	}

	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if got := second.closed.Load(); got != 1 {
		t.Fatalf("cached transport Close count = %d, want 1", got)
	}
	if _, err := r.queryHTTPS(context.Background(), upstream, target, []byte("q"), true); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("queryHTTPS after Close err = %v, want net.ErrClosed", err)
	}
}

func TestQueryHTTPSReplacementWaitsForInflightGeneration(t *testing.T) {
	t.Parallel()

	first := &countingRoundTripper{}
	second := &countingRoundTripper{}
	var created atomic.Int32
	var failedAttempts atomic.Int32
	slowStarted := make(chan struct{}, 1)
	releaseSlow := make(chan struct{})
	r := &Router{
		httpTransportFactory: func(*Router, *componentdns.Upstream, netip.AddrPort, bool) http.RoundTripper {
			if created.Add(1) == 1 {
				return first
			}
			return second
		},
		httpSendFunc: func(_ context.Context, _ *http.Client, _ string, _ *componentdns.Upstream, data []byte) (*dnsmessage.Msg, error) {
			switch string(data) {
			case "slow":
				select {
				case slowStarted <- struct{}{}:
				default:
				}
				<-releaseSlow
				return &dnsmessage.Msg{}, nil
			case "fail":
				if failedAttempts.Add(1) == 1 {
					return nil, net.ErrClosed
				}
				return &dnsmessage.Msg{}, nil
			default:
				return nil, errors.New("unexpected query")
			}
		},
	}
	upstream := &componentdns.Upstream{Scheme: componentdns.UpstreamScheme_H3, Hostname: "dns.example", Port: 443, Path: "/dns-query"}
	target := netip.MustParseAddrPort("1.1.1.1:443")

	slowErr := make(chan error, 1)
	go func() {
		_, err := r.queryHTTPS(context.Background(), upstream, target, []byte("slow"), true)
		slowErr <- err
	}()
	select {
	case <-slowStarted:
	case <-time.After(time.Second):
		t.Fatal("slow query did not acquire the first generation")
	}

	if _, err := r.queryHTTPS(context.Background(), upstream, target, []byte("fail"), true); err != nil {
		t.Fatalf("replacement query: %v", err)
	}
	if got := first.closed.Load(); got != 0 {
		t.Fatalf("in-flight generation closed early: %d", got)
	}
	close(releaseSlow)
	select {
	case err := <-slowErr:
		if err != nil {
			t.Fatalf("slow query: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("slow query did not finish")
	}
	if got := first.closed.Load(); got != 1 {
		t.Fatalf("retired generation Close count = %d, want 1", got)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := second.closed.Load(); got != 1 {
		t.Fatalf("current generation Close count = %d, want 1", got)
	}
}

func TestRouterCloseWaitsForRetiredGenerationClose(t *testing.T) {
	t.Parallel()

	first := &blockingCloseRoundTripper{
		started: make(chan struct{}, 1),
		release: make(chan struct{}),
	}
	second := &countingRoundTripper{}
	var created atomic.Int32
	var failedAttempts atomic.Int32
	slowStarted := make(chan struct{}, 1)
	releaseSlow := make(chan struct{})
	r := &Router{
		httpTransportFactory: func(*Router, *componentdns.Upstream, netip.AddrPort, bool) http.RoundTripper {
			if created.Add(1) == 1 {
				return first
			}
			return second
		},
		httpSendFunc: func(_ context.Context, _ *http.Client, _ string, _ *componentdns.Upstream, data []byte) (*dnsmessage.Msg, error) {
			if string(data) == "slow" {
				slowStarted <- struct{}{}
				<-releaseSlow
				return &dnsmessage.Msg{}, nil
			}
			if failedAttempts.Add(1) == 1 {
				return nil, net.ErrClosed
			}
			return &dnsmessage.Msg{}, nil
		},
	}
	upstream := &componentdns.Upstream{Scheme: componentdns.UpstreamScheme_H3, Hostname: "dns.example", Port: 443, Path: "/dns-query"}
	target := netip.MustParseAddrPort("1.1.1.1:443")
	slowErr := make(chan error, 1)
	go func() {
		_, err := r.queryHTTPS(context.Background(), upstream, target, []byte("slow"), true)
		slowErr <- err
	}()
	select {
	case <-slowStarted:
	case <-time.After(time.Second):
		t.Fatal("slow query did not acquire generation")
	}
	if _, err := r.queryHTTPS(context.Background(), upstream, target, []byte("fail"), true); err != nil {
		t.Fatalf("replacement query: %v", err)
	}
	close(releaseSlow)
	select {
	case <-first.started:
	case <-time.After(time.Second):
		t.Fatal("retired generation did not start closing")
	}
	closeErr := make(chan error, 1)
	go func() { closeErr <- r.Close() }()
	select {
	case err := <-closeErr:
		t.Fatalf("Router.Close returned before retired close completed: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	close(first.release)
	select {
	case err := <-closeErr:
		if err != nil {
			t.Fatalf("Router.Close: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Router.Close did not wait for retired close")
	}
	select {
	case err := <-slowErr:
		if err != nil {
			t.Fatalf("slow query: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("slow query did not finish")
	}
	if got := first.closed.Load(); got != 1 {
		t.Fatalf("retired generation Close count = %d, want 1", got)
	}
	if got := second.closed.Load(); got != 1 {
		t.Fatalf("current generation Close count = %d, want 1", got)
	}
}

func TestRouterCloseForceClosesInflightHTTPGeneration(t *testing.T) {
	t.Parallel()

	transport := &countingRoundTripper{}
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	r := &Router{
		httpTransportFactory: func(*Router, *componentdns.Upstream, netip.AddrPort, bool) http.RoundTripper {
			return transport
		},
		httpSendFunc: func(context.Context, *http.Client, string, *componentdns.Upstream, []byte) (*dnsmessage.Msg, error) {
			started <- struct{}{}
			<-release
			return &dnsmessage.Msg{}, nil
		},
	}
	upstream := &componentdns.Upstream{Scheme: componentdns.UpstreamScheme_H3, Hostname: "dns.example", Port: 443, Path: "/dns-query"}
	target := netip.MustParseAddrPort("1.1.1.1:443")
	errCh := make(chan error, 1)
	go func() {
		_, err := r.queryHTTPS(context.Background(), upstream, target, []byte("q"), true)
		errCh <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("query did not acquire generation")
	}
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := transport.closed.Load(); got != 1 {
		t.Fatalf("active generation Close count = %d, want 1", got)
	}
	close(release)
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("query: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("query did not finish")
	}
	if err := r.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if got := transport.closed.Load(); got != 1 {
		t.Fatalf("active generation Close count after second Close = %d, want 1", got)
	}
}

func TestQueryHTTPSResponseErrorDoesNotReplaceClient(t *testing.T) {
	t.Parallel()

	transport := &countingRoundTripper{}
	var created atomic.Int32
	responseErr := errors.New("unexpected content-type")
	r := &Router{
		httpTransportFactory: func(*Router, *componentdns.Upstream, netip.AddrPort, bool) http.RoundTripper {
			created.Add(1)
			return transport
		},
		httpSendFunc: func(context.Context, *http.Client, string, *componentdns.Upstream, []byte) (*dnsmessage.Msg, error) {
			return nil, responseErr
		},
	}
	upstream := &componentdns.Upstream{Scheme: componentdns.UpstreamScheme_H3, Hostname: "dns.example", Port: 443, Path: "/dns-query"}
	target := netip.MustParseAddrPort("1.1.1.1:443")

	if _, err := r.queryHTTPS(context.Background(), upstream, target, []byte("q"), true); !errors.Is(err, responseErr) {
		t.Fatalf("queryHTTPS error = %v, want response error", err)
	}
	if got := created.Load(); got != 1 {
		t.Fatalf("transports created = %d, want 1", got)
	}
	if got := transport.closed.Load(); got != 0 {
		t.Fatalf("response error closed transport: %d", got)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := transport.closed.Load(); got != 1 {
		t.Fatalf("transport Close count = %d, want 1", got)
	}
}

var (
	_ io.Closer            = (*countingCloser)(nil)
	_ quic.EarlyConnection = (*stubEarlyConn)(nil)
)
