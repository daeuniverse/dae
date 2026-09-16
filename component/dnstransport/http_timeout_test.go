/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package dnstransport

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/dns"
)

func TestNewHTTPTransportSetsResponseHeaderTimeout(t *testing.T) {
	tr := NewHTTPTransport("dns.example", func(context.Context, string, string) (net.Conn, error) {
		return nil, net.ErrClosed
	})
	if tr.ResponseHeaderTimeout != httpTLSHandshakeTimeout {
		t.Fatalf("ResponseHeaderTimeout = %v, want %v", tr.ResponseHeaderTimeout, httpTLSHandshakeTimeout)
	}
	if tr.TLSHandshakeTimeout != httpTLSHandshakeTimeout {
		t.Fatalf("TLSHandshakeTimeout = %v, want %v", tr.TLSHandshakeTimeout, httpTLSHandshakeTimeout)
	}
	client := &http.Client{Transport: tr}
	if client.Timeout != 0 {
		t.Fatalf("http.Client.Timeout = %v, want 0 (request ctx is the deadline)", client.Timeout)
	}
}

type ctxRoundTripper struct {
	started chan struct{}
	sawCtx  atomic.Bool
}

func (t *ctxRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	close(t.started)
	select {
	case <-req.Context().Done():
		t.sawCtx.Store(true)
		return nil, req.Context().Err()
	case <-time.After(2 * time.Second):
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(http.NoBody),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	}
}

func TestSendHTTPDNSObservesRequestContext(t *testing.T) {
	rt := &ctxRoundTripper{started: make(chan struct{})}
	client := &http.Client{Transport: rt, Timeout: 0}
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		_, sendErr := SendHTTPDNS(ctx, client, "127.0.0.1:443", &dns.Upstream{
			Hostname: "dns.example",
			Path:     "/dns-query",
		}, []byte{0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0})
		errCh <- sendErr
	}()
	select {
	case <-rt.started:
	case <-time.After(time.Second):
		t.Fatal("RoundTrip did not observe the request")
	}
	cancel()
	select {
	case sendErr := <-errCh:
		if sendErr == nil {
			t.Fatal("SendHTTPDNS succeeded against a hanging transport")
		}
		if !errors.Is(sendErr, context.Canceled) {
			t.Fatalf("SendHTTPDNS error = %v, want context.Canceled", sendErr)
		}
	case <-time.After(time.Second):
		t.Fatal("SendHTTPDNS did not return after ctx cancel")
	}
	if !rt.sawCtx.Load() {
		t.Fatal("request context did not reach RoundTrip")
	}
}
