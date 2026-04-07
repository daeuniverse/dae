/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@daeuniverse.org>
 */

package daedns

import (
	"context"
	"net/http"
	"net/netip"
	"testing"

	componentdns "github.com/daeuniverse/dae/component/dns"
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
