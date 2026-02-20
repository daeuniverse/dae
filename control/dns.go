/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
	tc "github.com/daeuniverse/outbound/protocol/tuic/common"
	"github.com/daeuniverse/quic-go"
	"github.com/daeuniverse/quic-go/http3"
	dnsmessage "github.com/miekg/dns"
)

type DnsForwarder interface {
	ForwardDNS(ctx context.Context, data []byte) (*dnsmessage.Msg, error)
	Close() error
}

func newDnsForwarder(upstream *dns.Upstream, dialArgument dialArgument) (DnsForwarder, error) {
	forwarder, err := func() (DnsForwarder, error) {
		switch dialArgument.l4proto {
		case consts.L4ProtoStr_TCP:
			switch upstream.Scheme {
			case dns.UpstreamScheme_TCP, dns.UpstreamScheme_TCP_UDP:
				return &DoTCP{Upstream: *upstream, Dialer: dialArgument.bestDialer, dialArgument: dialArgument}, nil
			case dns.UpstreamScheme_TLS:
				return &DoTLS{Upstream: *upstream, Dialer: dialArgument.bestDialer, dialArgument: dialArgument}, nil
			case dns.UpstreamScheme_HTTPS:
				return &DoH{Upstream: *upstream, Dialer: dialArgument.bestDialer, dialArgument: dialArgument, http3: false}, nil
			default:
				return nil, fmt.Errorf("unexpected scheme: %v", upstream.Scheme)
			}
		case consts.L4ProtoStr_UDP:
			switch upstream.Scheme {
			case dns.UpstreamScheme_UDP, dns.UpstreamScheme_TCP_UDP:
				return &DoUDP{Upstream: *upstream, Dialer: dialArgument.bestDialer, dialArgument: dialArgument}, nil
			case dns.UpstreamScheme_QUIC:
				return &DoQ{Upstream: *upstream, Dialer: dialArgument.bestDialer, dialArgument: dialArgument}, nil
			case dns.UpstreamScheme_H3:
				return &DoH{Upstream: *upstream, Dialer: dialArgument.bestDialer, dialArgument: dialArgument, http3: true}, nil
			default:
				return nil, fmt.Errorf("unexpected scheme: %v", upstream.Scheme)
			}
		default:
			return nil, fmt.Errorf("unexpected l4proto: %v", dialArgument.l4proto)
		}
	}()
	if err != nil {
		return nil, err
	}
	return forwarder, nil
}

type DoH struct {
	dns.Upstream
	netproxy.Dialer
	dialArgument dialArgument
	http3        bool
	client       *http.Client
}

func closeDoHClient(client *http.Client) error {
	if client == nil || client.Transport == nil {
		return nil
	}
	// HTTP/1.1 and HTTP/2 transport.
	if t, ok := client.Transport.(interface{ CloseIdleConnections() }); ok {
		t.CloseIdleConnections()
	}
	// HTTP/3 transport.
	if closer, ok := client.Transport.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

func (d *DoH) ForwardDNS(ctx context.Context, data []byte) (*dnsmessage.Msg, error) {
	if d.client == nil {
		d.client = d.getClient()
	}
	msg, err := sendHttpDNS(ctx, d.client, d.dialArgument.bestTarget.String(), &d.Upstream, data)
	if err != nil {
		// If failed to send DNS request, we should try to create a new client.
		_ = closeDoHClient(d.client)
		d.client = d.getClient()
		msg, err = sendHttpDNS(ctx, d.client, d.dialArgument.bestTarget.String(), &d.Upstream, data)
		if err != nil {
			return nil, err
		}
		return msg, nil
	}
	return msg, nil
}

func (d *DoH) getClient() *http.Client {
	var roundTripper http.RoundTripper
	if d.http3 {
		roundTripper = d.getHttp3RoundTripper()
	} else {
		roundTripper = d.getHttpRoundTripper()
	}

	return &http.Client{
		Transport: roundTripper,
	}
}

func (d *DoH) getHttpRoundTripper() *http.Transport {
	httpTransport := http.Transport{
		TLSClientConfig: &tls.Config{
			ServerName:         d.Upstream.Hostname,
			InsecureSkipVerify: false,
		},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := d.dialArgument.bestDialer.DialContext(
				ctx,
				common.MagicNetwork("tcp", d.dialArgument.mark, d.dialArgument.mptcp),
				d.dialArgument.bestTarget.String(),
			)
			if err != nil {
				return nil, err
			}
			return &netproxy.FakeNetConn{Conn: conn}, nil
		},
	}

	return &httpTransport
}

func (d *DoH) getHttp3RoundTripper() *http3.RoundTripper {
	roundTripper := &http3.RoundTripper{
		TLSClientConfig: &tls.Config{
			ServerName:         d.Upstream.Hostname,
			NextProtos:         []string{"h3"},
			InsecureSkipVerify: false,
		},
		QUICConfig: &quic.Config{},
		Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
			udpAddr := net.UDPAddrFromAddrPort(d.dialArgument.bestTarget)
			conn, err := d.dialArgument.bestDialer.DialContext(
				ctx,
				common.MagicNetwork("udp", d.dialArgument.mark, d.dialArgument.mptcp),
				d.dialArgument.bestTarget.String(),
			)
			if err != nil {
				return nil, err
			}
			fakePkt := netproxy.NewFakeNetPacketConn(conn.(netproxy.PacketConn), net.UDPAddrFromAddrPort(tc.GetUniqueFakeAddrPort()), udpAddr)
			c, e := quic.DialEarly(ctx, fakePkt, udpAddr, tlsCfg, cfg)
			return c, e
		},
	}
	return roundTripper
}

func (d *DoH) Close() error {
	err := closeDoHClient(d.client)
	d.client = nil
	return err
}

type DoQ struct {
	dns.Upstream
	netproxy.Dialer
	dialArgument dialArgument
	connection   quic.EarlyConnection
}

func closeDoQConnection(conn quic.EarlyConnection) error {
	if conn == nil {
		return nil
	}
	return conn.CloseWithError(0, "")
}

func (d *DoQ) ForwardDNS(ctx context.Context, data []byte) (*dnsmessage.Msg, error) {
	if d.connection == nil {
		qc, err := d.createConnection(ctx)
		if err != nil {
			return nil, err
		}
		d.connection = qc
	}

	stream, err := d.connection.OpenStreamSync(ctx)
	if err != nil {
		// If failed to open stream, close old connection and try to create a new one.
		_ = closeDoQConnection(d.connection)
		d.connection = nil
		qc, err := d.createConnection(ctx)
		if err != nil {
			return nil, err
		}
		d.connection = qc
		stream, err = d.connection.OpenStreamSync(ctx)
		if err != nil {
			return nil, err
		}
	}
	defer func() {
		_ = stream.Close()
	}()

	// According https://datatracker.ietf.org/doc/html/rfc9250#section-4.2.1
	// msg id should set to 0 when transport over QUIC.
	// thanks https://github.com/natesales/q/blob/1cb2639caf69bd0a9b46494a3c689130df8fb24a/transport/quic.go#L97
	binary.BigEndian.PutUint16(data[0:2], 0)

	msg, err := sendStreamDNS(ctx, stream, data)
	if err != nil {
		return nil, err
	}
	return msg, nil
}
func (d *DoQ) createConnection(ctx context.Context) (quic.EarlyConnection, error) {

	udpAddr := net.UDPAddrFromAddrPort(d.dialArgument.bestTarget)
	conn, err := d.dialArgument.bestDialer.DialContext(
		ctx,
		common.MagicNetwork("udp", d.dialArgument.mark, d.dialArgument.mptcp),
		d.dialArgument.bestTarget.String(),
	)
	if err != nil {
		return nil, err
	}

	fakePkt := netproxy.NewFakeNetPacketConn(conn.(netproxy.PacketConn), net.UDPAddrFromAddrPort(tc.GetUniqueFakeAddrPort()), udpAddr)
	tlsCfg := &tls.Config{
		NextProtos:         []string{"doq"},
		InsecureSkipVerify: false,
		ServerName:         d.Upstream.Hostname,
	}
	addr := net.UDPAddrFromAddrPort(d.dialArgument.bestTarget)
	qc, err := quic.DialEarly(ctx, fakePkt, addr, tlsCfg, nil)
	if err != nil {
		return nil, err
	}
	return qc, nil

}

func (d *DoQ) Close() error {
	err := closeDoQConnection(d.connection)
	d.connection = nil
	return err
}

type DoTLS struct {
	dns.Upstream
	netproxy.Dialer
	dialArgument dialArgument
	conn         netproxy.Conn
}

func (d *DoTLS) ForwardDNS(ctx context.Context, data []byte) (*dnsmessage.Msg, error) {
	conn, err := d.dialArgument.bestDialer.DialContext(
		ctx,
		common.MagicNetwork("tcp", d.dialArgument.mark, d.dialArgument.mptcp),
		d.dialArgument.bestTarget.String(),
	)
	if err != nil {
		return nil, err
	}

	tlsConn := tls.Client(&netproxy.FakeNetConn{Conn: conn}, &tls.Config{
		InsecureSkipVerify: false,
		ServerName:         d.Upstream.Hostname,
	})
	if err = tlsConn.Handshake(); err != nil {
		return nil, err
	}
	d.conn = tlsConn

	return sendStreamDNS(ctx, tlsConn, data)
}

func (d *DoTLS) Close() error {
	if d.conn != nil {
		return d.conn.Close()
	}
	return nil
}

type DoTCP struct {
	dns.Upstream
	netproxy.Dialer
	dialArgument dialArgument
	conn         netproxy.Conn
}

func (d *DoTCP) ForwardDNS(ctx context.Context, data []byte) (*dnsmessage.Msg, error) {
	conn, err := d.dialArgument.bestDialer.DialContext(
		ctx,
		common.MagicNetwork("tcp", d.dialArgument.mark, d.dialArgument.mptcp),
		d.dialArgument.bestTarget.String(),
	)
	if err != nil {
		return nil, err
	}

	d.conn = conn
	return sendStreamDNS(ctx, conn, data)
}

func (d *DoTCP) Close() error {
	if d.conn != nil {
		return d.conn.Close()
	}
	return nil
}

type DoUDP struct {
	dns.Upstream
	netproxy.Dialer
	dialArgument dialArgument
	conn         netproxy.Conn
}

func (d *DoUDP) ForwardDNS(ctx context.Context, data []byte) (*dnsmessage.Msg, error) {
	conn, err := d.dialArgument.bestDialer.DialContext(
		ctx,
		common.MagicNetwork("udp", d.dialArgument.mark, d.dialArgument.mptcp),
		d.dialArgument.bestTarget.String(),
	)
	if err != nil {
		return nil, err
	}
	d.conn = conn
	localConn := conn

	timeout := 5 * time.Second
	_ = localConn.SetDeadline(time.Now().Add(timeout))
	dnsReqCtx, cancelDnsReqCtx := context.WithTimeout(ctx, timeout)
	defer cancelDnsReqCtx()
	retryTicker := time.NewTicker(1 * time.Second)
	defer retryTicker.Stop()

	go func() {
		// Send DNS request every seconds.
		for {
			_, _ = localConn.Write(data)
			// if err != nil {
			// 	if c.log.IsLevelEnabled(logrus.DebugLevel) {
			// 		c.log.WithFields(logrus.Fields{
			// 			"to":      dialArgument.bestTarget.String(),
			// 			"pid":     req.routingResult.Pid,
			// 			"pname":   ProcessName2String(req.routingResult.Pname[:]),
			// 			"mac":     Mac2String(req.routingResult.Mac[:]),
			// 			"from":    req.realSrc.String(),
			// 			"network": networkType.String(),
			// 			"err":     err.Error(),
			// 		}).Debugln("Failed to write UDP(DNS) packet request.")
			// 	}
			// 	return
			// }
			select {
			case <-dnsReqCtx.Done():
				return
			case <-retryTicker.C:
			}
		}
	}()

	// We can block here because we are in a coroutine.
	respBuf := pool.GetFullCap(consts.EthernetMtu)
	defer pool.Put(respBuf)
	// Wait for response.
	n, err := localConn.Read(respBuf)
	if err != nil {
		return nil, err
	}
	var msg dnsmessage.Msg
	if err = msg.Unpack(respBuf[:n]); err != nil {
		return nil, err
	}
	return &msg, nil
}

func (d *DoUDP) Close() error {
	if d.conn != nil {
		err := d.conn.Close()
		d.conn = nil
		return err
	}
	return nil
}

func sendHttpDNS(ctx context.Context, client *http.Client, target string, upstream *dns.Upstream, data []byte) (respMsg *dnsmessage.Msg, err error) {
	// disable redirect https://github.com/daeuniverse/dae/pull/649#issuecomment-2379577896
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return fmt.Errorf("do not use a server that will redirect, upstream: %v", upstream.String())
	}
	serverURL := url.URL{
		Scheme: "https",
		Host:   target,
		Path:   upstream.Path,
	}
	q := serverURL.Query()
	// According https://datatracker.ietf.org/doc/html/rfc8484#section-4
	// msg id should set to 0 when transport over HTTPS for cache friendly.
	binary.BigEndian.PutUint16(data[0:2], 0)
	q.Set("dns", base64.RawURLEncoding.EncodeToString(data))
	serverURL.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, serverURL.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-message")
	req.Host = upstream.Hostname
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var msg dnsmessage.Msg
	if err = msg.Unpack(buf); err != nil {
		return nil, err
	}
	return &msg, nil
}

func sendStreamDNS(ctx context.Context, stream io.ReadWriter, data []byte) (respMsg *dnsmessage.Msg, err error) {
	type streamDeadliner interface {
		SetDeadline(t time.Time) error
	}
	if deadliner, ok := stream.(streamDeadliner); ok {
		if deadline, ok := ctx.Deadline(); ok {
			_ = deadliner.SetDeadline(deadline)
		}
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}

	// We should write two byte length in the front of stream DNS request.
	bReq := pool.Get(2 + len(data))
	defer pool.Put(bReq)
	binary.BigEndian.PutUint16(bReq, uint16(len(data)))
	copy(bReq[2:], data)
	_, err = stream.Write(bReq)
	if err != nil {
		return nil, fmt.Errorf("failed to write DNS req: %w", err)
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}

	// Read two byte length.
	if _, err = io.ReadFull(stream, bReq[:2]); err != nil {
		return nil, fmt.Errorf("failed to read DNS resp payload length: %w", err)
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	respLen := int(binary.BigEndian.Uint16(bReq))
	// Try to reuse the buf.
	var buf []byte
	if len(bReq) < respLen {
		buf = pool.Get(respLen)
		defer pool.Put(buf)
	} else {
		buf = bReq
	}
	var n int
	if n, err = io.ReadFull(stream, buf[:respLen]); err != nil {
		return nil, fmt.Errorf("failed to read DNS resp payload: %w", err)
	}
	var msg dnsmessage.Msg
	if err = msg.Unpack(buf[:n]); err != nil {
		return nil, err
	}
	return &msg, nil
}
