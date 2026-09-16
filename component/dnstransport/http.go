/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package dnstransport

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/netip"

	"github.com/daeuniverse/outbound/netproxy"
	tc "github.com/daeuniverse/outbound/protocol/tuic/common"
	"github.com/olicesx/quic-go"
	"github.com/olicesx/quic-go/http3"
)

// DialEarlyOwned dials a QUIC early connection through dialConn (a dialer
// returning a netproxy connection whose UDP form backs the session) and wraps
// it so closing the connection also closes the caller-owned socket.
func DialEarlyOwned(
	ctx context.Context,
	dialConn func(ctx context.Context) (netproxy.Conn, error),
	target netip.AddrPort,
	tlsCfg *tls.Config,
	cfg *quic.Config,
) (quic.EarlyConnection, error) {
	conn, err := dialConn(ctx)
	if err != nil {
		return nil, err
	}
	udpAddr := net.UDPAddrFromAddrPort(target)
	fakePkt := netproxy.NewFakeNetPacketConn(conn.(netproxy.PacketConn), net.UDPAddrFromAddrPort(tc.GetUniqueFakeAddrPort()), udpAddr)
	qc, dialErr := quic.DialEarly(ctx, fakePkt, udpAddr, tlsCfg, cfg)
	if dialErr != nil {
		_ = conn.Close()
		return nil, dialErr
	}
	return OwnEarlyConnection(qc, conn), nil
}

// NewHTTPTransport builds the shared HTTP/1.1 (+TLS) transport parameters:
// bounded idle pools and handshake timeouts around the injected dialer.
func NewHTTPTransport(hostname string, dialContext func(ctx context.Context, network, addr string) (net.Conn, error)) *http.Transport {
	return &http.Transport{
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   20,
		IdleConnTimeout:       httpIdleConnTimeout,
		TLSHandshakeTimeout:   httpTLSHandshakeTimeout,
		ResponseHeaderTimeout: httpTLSHandshakeTimeout,
		ExpectContinueTimeout: httpExpectContinueTimeout,
		TLSClientConfig: &tls.Config{
			ServerName:         hostname,
			InsecureSkipVerify: false,
		},
		DialContext: dialContext,
	}
}

// NewHTTP3Transport builds the shared H3 transport: h3 ALPN plus the injected
// QUIC dialer that owns its socket via DialEarlyOwned.
func NewHTTP3Transport(hostname string, dial func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error)) *http3.Transport {
	return &http3.Transport{
		TLSClientConfig: &tls.Config{
			ServerName:         hostname,
			NextProtos:         []string{"h3"},
			InsecureSkipVerify: false,
		},
		QUICConfig: &quic.Config{},
		Dial:       dial,
	}
}
