/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/dns"
	dnsmessage "github.com/miekg/dns"
)

func TestDoH_ForwardDNS_RetriesOnClosedConnection(t *testing.T) {
	attempts := 0
	d := &DoH{
		Upstream: dns.Upstream{
			Scheme:   dns.UpstreamScheme_HTTPS,
			Hostname: "223.5.5.5",
			Port:     443,
			Path:     "/dns-query",
		},
		dialArgument: dialArgument{bestTarget: netip.MustParseAddrPort("223.5.5.5:443")},
	}
	d.clientFactory = func() *http.Client { return &http.Client{} }
	d.sendFunc = func(_ context.Context, _ *http.Client, _ string, _ *dns.Upstream, _ []byte) (*dnsmessage.Msg, error) {
		attempts++
		if attempts == 1 {
			return nil, net.ErrClosed
		}
		return &dnsmessage.Msg{MsgHdr: dnsmessage.MsgHdr{Id: 42}}, nil
	}

	msg, err := d.ForwardDNS(context.Background(), []byte("query"))
	if err != nil {
		t.Fatalf("ForwardDNS: %v", err)
	}
	if attempts != 2 {
		t.Fatalf("attempts = %d, want 2 (one retry after net.ErrClosed)", attempts)
	}
	if msg.Id != 42 {
		t.Fatalf("msg.Id = %d, want 42", msg.Id)
	}
}

func TestDoH_ForwardDNS_ClosedForwarderReturnsErrClosed(t *testing.T) {
	d := &DoH{Upstream: dns.Upstream{Scheme: dns.UpstreamScheme_HTTPS}}
	d.clientFactory = func() *http.Client { return &http.Client{} }
	if err := d.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := d.ForwardDNS(context.Background(), []byte("query")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("ForwardDNS err = %v, want net.ErrClosed", err)
	}
}

func TestDoH_CloseForceClosesInflightGeneration(t *testing.T) {
	transport := &dohCountingRoundTripper{}
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	d := &DoH{
		Upstream:     dns.Upstream{Scheme: dns.UpstreamScheme_H3},
		dialArgument: dialArgument{bestTarget: netip.MustParseAddrPort("1.1.1.1:443")},
	}
	d.clientFactory = func() *http.Client {
		return &http.Client{Transport: transport}
	}
	d.sendFunc = func(context.Context, *http.Client, string, *dns.Upstream, []byte) (*dnsmessage.Msg, error) {
		started <- struct{}{}
		<-release
		return &dnsmessage.Msg{}, nil
	}
	errCh := make(chan error, 1)
	go func() {
		_, err := d.ForwardDNS(context.Background(), []byte("query"))
		errCh <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("query did not acquire generation")
	}
	if err := d.Close(); err != nil {
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
	if err := d.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if got := transport.closed.Load(); got != 1 {
		t.Fatalf("active generation Close count after second Close = %d, want 1", got)
	}
}

func TestDoH_ResponseErrorDoesNotReplaceClient(t *testing.T) {
	responseErr := errors.New("unexpected content-type")
	var created atomic.Int32
	d := &DoH{
		Upstream:     dns.Upstream{Scheme: dns.UpstreamScheme_H3},
		dialArgument: dialArgument{bestTarget: netip.MustParseAddrPort("1.1.1.1:443")},
	}
	d.clientFactory = func() *http.Client {
		created.Add(1)
		return &http.Client{}
	}
	d.sendFunc = func(context.Context, *http.Client, string, *dns.Upstream, []byte) (*dnsmessage.Msg, error) {
		return nil, responseErr
	}

	if _, err := d.ForwardDNS(context.Background(), []byte("query")); !errors.Is(err, responseErr) {
		t.Fatalf("ForwardDNS error = %v, want response error", err)
	}
	if got := created.Load(); got != 1 {
		t.Fatalf("clients created = %d, want 1", got)
	}
	if err := d.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

type dohCountingRoundTripper struct {
	closed atomic.Int32
}

func (t *dohCountingRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("unused")
}

func (t *dohCountingRoundTripper) Close() error {
	t.closed.Add(1)
	return nil
}

type dohBlockingCloseRoundTripper struct {
	closed  atomic.Int32
	started chan struct{}
	release chan struct{}
}

func (t *dohBlockingCloseRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("unused")
}

func (t *dohBlockingCloseRoundTripper) Close() error {
	t.started <- struct{}{}
	<-t.release
	t.closed.Add(1)
	return nil
}

func TestDoH_CloseWaitsForRetiredGeneration(t *testing.T) {
	first := &dohBlockingCloseRoundTripper{
		started: make(chan struct{}, 1),
		release: make(chan struct{}),
	}
	second := &dohCountingRoundTripper{}
	var created atomic.Int32
	var failedAttempts atomic.Int32
	slowStarted := make(chan struct{}, 1)
	releaseSlow := make(chan struct{})
	d := &DoH{
		Upstream:     dns.Upstream{Scheme: dns.UpstreamScheme_H3},
		dialArgument: dialArgument{bestTarget: netip.MustParseAddrPort("1.1.1.1:443")},
	}
	d.clientFactory = func() *http.Client {
		if created.Add(1) == 1 {
			return &http.Client{Transport: first}
		}
		return &http.Client{Transport: second}
	}
	d.sendFunc = func(_ context.Context, _ *http.Client, _ string, _ *dns.Upstream, data []byte) (*dnsmessage.Msg, error) {
		if string(data) == "slow" {
			slowStarted <- struct{}{}
			<-releaseSlow
			return &dnsmessage.Msg{}, nil
		}
		if failedAttempts.Add(1) == 1 {
			return nil, net.ErrClosed
		}
		return &dnsmessage.Msg{}, nil
	}
	slowErr := make(chan error, 1)
	go func() {
		_, err := d.ForwardDNS(context.Background(), []byte("slow"))
		slowErr <- err
	}()
	select {
	case <-slowStarted:
	case <-time.After(time.Second):
		t.Fatal("slow query did not acquire generation")
	}
	if _, err := d.ForwardDNS(context.Background(), []byte("fail")); err != nil {
		t.Fatalf("replacement query: %v", err)
	}
	close(releaseSlow)
	select {
	case <-first.started:
	case <-time.After(time.Second):
		t.Fatal("retired generation did not start closing")
	}
	closeErr := make(chan error, 1)
	go func() { closeErr <- d.Close() }()
	select {
	case err := <-closeErr:
		t.Fatalf("DoH.Close returned before retired close completed: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	close(first.release)
	select {
	case err := <-closeErr:
		if err != nil {
			t.Fatalf("DoH.Close: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("DoH.Close did not wait for retired close")
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

func TestDoH_ReplacementWaitsForInflightGeneration(t *testing.T) {
	first := &dohCountingRoundTripper{}
	second := &dohCountingRoundTripper{}
	var created atomic.Int32
	var failedAttempts atomic.Int32
	slowStarted := make(chan struct{}, 1)
	releaseSlow := make(chan struct{})
	d := &DoH{
		Upstream: dns.Upstream{
			Scheme:   dns.UpstreamScheme_H3,
			Hostname: "dns.example",
			Port:     443,
			Path:     "/dns-query",
		},
		dialArgument: dialArgument{bestTarget: netip.MustParseAddrPort("1.1.1.1:443")},
	}
	d.clientFactory = func() *http.Client {
		if created.Add(1) == 1 {
			return &http.Client{Transport: first}
		}
		return &http.Client{Transport: second}
	}
	d.sendFunc = func(_ context.Context, _ *http.Client, _ string, _ *dns.Upstream, data []byte) (*dnsmessage.Msg, error) {
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
	}

	slowErr := make(chan error, 1)
	go func() {
		_, err := d.ForwardDNS(context.Background(), []byte("slow"))
		slowErr <- err
	}()
	select {
	case <-slowStarted:
	case <-time.After(time.Second):
		t.Fatal("slow query did not acquire the first generation")
	}

	if _, err := d.ForwardDNS(context.Background(), []byte("fail")); err != nil {
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
	if err := d.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := second.closed.Load(); got != 1 {
		t.Fatalf("current generation Close count = %d, want 1", got)
	}
}
