/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package daedns

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/netutils"
	componentdns "github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pkg/fastrand"
	"github.com/daeuniverse/outbound/protocol/direct"
	tc "github.com/daeuniverse/outbound/protocol/tuic/common"
	dnsmessage "github.com/miekg/dns"
	"github.com/olicesx/quic-go"
	"github.com/olicesx/quic-go/http3"
)

var errInternalDNSTruncated = fmt.Errorf("internal dns response truncated")
var errPassthroughToBaseResolver = errors.New("dns request routing selected passthrough resolver")

var udpDNSBufPool = sync.Pool{
	// Keep the full UDP DNS payload budget so oversized replies still unpack
	// correctly instead of failing before TCP fallback decisions are made.
	New: func() any { return make([]byte, 65535) },
}

const lookupSharedTimeout = 10 * time.Second

var (
	// Test seams for queryHTTPS path validation without live network dependencies.
	sendHTTPDNSFunc      = sendHTTPDNS
	newHTTPTransportFunc = func(r *Router, upstream *componentdns.Upstream, target netip.AddrPort, http3Mode bool) http.RoundTripper {
		return r.newHTTPTransport(upstream, target, http3Mode)
	}
)

func (r *Router) selectUpstream(ctx context.Context, upstreamName, host string, qtype uint16) (*componentdns.Upstream, error) {
	if upstreamName != "" {
		upstreamResolver, ok := r.upstreams[upstreamName]
		if !ok {
			return nil, fmt.Errorf("dns upstream %q not found", upstreamName)
		}
		return upstreamResolver.GetUpstream(ctx)
	}
	if r.requestMatcher == nil {
		return nil, fmt.Errorf("dns request routing is not configured for %q", host)
	}
	upstreamIndex, err := r.requestMatcher.Match(dnsmessage.CanonicalName(host), qtype)
	if err != nil {
		return nil, err
	}
	switch upstreamIndex {
	case consts.DnsRequestOutboundIndex_AsIs, consts.DnsRequestOutboundIndex_Reject:
		return nil, errPassthroughToBaseResolver
	}
	if int(upstreamIndex) < 0 || int(upstreamIndex) >= len(r.upstreamByIndex) {
		return nil, fmt.Errorf("dns request routing selected unsupported action %q for %q", upstreamIndex.String(), host)
	}
	return r.upstreamByIndex[upstreamIndex].GetUpstream(ctx)
}

func (r *Router) LookupIPAddr(ctx context.Context, upstreamName string, network string, host string) ([]net.IPAddr, error) {
	if addr, err := netip.ParseAddr(host); err == nil {
		ip := net.IP(addr.AsSlice())
		return []net.IPAddr{{IP: ip}}, nil
	}

	var qtypes []uint16
	switch requestedIPVersion(network) {
	case "4":
		qtypes = []uint16{dnsmessage.TypeA}
	case "6":
		qtypes = []uint16{dnsmessage.TypeAAAA}
	default:
		qtypes = []uint16{dnsmessage.TypeA, dnsmessage.TypeAAAA}
	}

	addrs := make([]net.IPAddr, 0, 2)
	var firstErr error
	sawPassthrough := false
	for _, qtype := range qtypes {
		upstream, lookupErr := r.selectUpstream(ctx, upstreamName, host, qtype)
		if lookupErr != nil {
			if errors.Is(lookupErr, errPassthroughToBaseResolver) {
				sawPassthrough = true
				continue
			}
			if firstErr == nil {
				firstErr = lookupErr
			}
			continue
		}
		ips, lookupErr := r.lookupTypeDedup(ctx, upstream, host, qtype)
		if lookupErr != nil {
			if firstErr == nil {
				firstErr = lookupErr
			}
			continue
		}
		addrs = append(addrs, ips...)
	}
	if len(addrs) == 0 {
		if sawPassthrough {
			return nil, errPassthroughToBaseResolver
		}
		if firstErr != nil {
			return nil, firstErr
		}
	}
	return addrs, nil
}

func lookupTypeDedupKey(upstream *componentdns.Upstream, host string, qtype uint16) string {
	return fmt.Sprintf("%s\x00%s\x00%d", upstream.String(), host, qtype)
}

func (r *Router) lookupTypeDedup(ctx context.Context, upstream *componentdns.Upstream, host string, qtype uint16) ([]net.IPAddr, error) {
	key := lookupTypeDedupKey(upstream, host, qtype)
	call := r.getOrCreateLookupCall(key, upstream, host, qtype)
	defer r.releaseLookupCall(key, call)

	select {
	case <-call.done:
		return call.res, call.err
	default:
	}

	select {
	case <-call.done:
		return call.res, call.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (r *Router) getOrCreateLookupCall(key string, upstream *componentdns.Upstream, host string, qtype uint16) *lookupCall {
	r.lookupMu.Lock()
	if call, ok := r.lookupCalls[key]; ok {
		call.waiters++
		r.lookupMu.Unlock()
		return call
	}

	lookupCtx, cancel := context.WithTimeout(context.Background(), lookupSharedTimeout)
	call := &lookupCall{
		waiters: 1,
		done:    make(chan struct{}),
		cancel:  cancel,
	}
	r.lookupCalls[key] = call
	r.lookupMu.Unlock()

	go func() {
		call.res, call.err = r.lookupType(lookupCtx, upstream, host, qtype)
		close(call.done)
		cancel()

		r.lookupMu.Lock()
		if current := r.lookupCalls[key]; current == call {
			delete(r.lookupCalls, key)
		}
		r.lookupMu.Unlock()
	}()

	return call
}

func (r *Router) releaseLookupCall(key string, call *lookupCall) {
	r.lookupMu.Lock()
	defer r.lookupMu.Unlock()

	if call.waiters == 0 {
		return
	}
	call.waiters--
	if call.waiters != 0 {
		return
	}

	select {
	case <-call.done:
		return
	default:
		if current := r.lookupCalls[key]; current == call {
			delete(r.lookupCalls, key)
		}
		call.cancel()
	}
}

type deadlineCloser interface {
	Close() error
	SetDeadline(time.Time) error
}

// interruptConnOnCancel installs a cancellation hook that forcefully
// interrupts blocking I/O on conn. Callers should defer the returned stop
// function immediately after a successful dial so the hook is unregistered on
// the normal completion path.
func interruptConnOnCancel(ctx context.Context, conn deadlineCloser) func() {
	stop := context.AfterFunc(ctx, func() {
		_ = conn.SetDeadline(time.Now())
		_ = conn.Close()
	})
	return func() {
		_ = stop()
	}
}

// interruptQUICConnOnCancel installs a cancellation hook that forcefully
// interrupts blocking QUIC operations. Callers should defer the returned stop
// function immediately after a successful dial so the hook is unregistered on
// the normal completion path.
func interruptQUICConnOnCancel(ctx context.Context, conn quic.EarlyConnection) func() {
	stop := context.AfterFunc(ctx, func() {
		_ = conn.CloseWithError(0, "")
	})
	return func() {
		_ = stop()
	}
}

func (r *Router) lookupType(ctx context.Context, upstream *componentdns.Upstream, host string, qtype uint16) ([]net.IPAddr, error) {
	msg := dnsmessage.Msg{
		MsgHdr: dnsmessage.MsgHdr{
			Id:               uint16(fastrand.Intn(1 << 16)),
			Response:         false,
			Opcode:           0,
			Truncated:        false,
			RecursionDesired: true,
			Authoritative:    false,
		},
	}
	msg.SetQuestion(dnsmessage.CanonicalName(host), qtype)
	data, err := msg.Pack()
	if err != nil {
		return nil, err
	}

	resp, err := r.exchange(ctx, upstream, data)
	if err != nil {
		return nil, err
	}
	addrs := make([]net.IPAddr, 0, 2)
	for _, ans := range resp.Answer {
		switch qtype {
		case dnsmessage.TypeA:
			a, ok := ans.(*dnsmessage.A)
			if !ok {
				continue
			}
			addrs = append(addrs, net.IPAddr{IP: a.A[:]})
		case dnsmessage.TypeAAAA:
			aaaa, ok := ans.(*dnsmessage.AAAA)
			if !ok {
				continue
			}
			addrs = append(addrs, net.IPAddr{IP: aaaa.AAAA[:]})
		}
	}
	return addrs, nil
}

func (r *Router) exchange(ctx context.Context, upstream *componentdns.Upstream, data []byte) (*dnsmessage.Msg, error) {
	targets := upstreamTargets(upstream)
	if len(targets) == 0 {
		return nil, fmt.Errorf("dns upstream %q has no usable address", upstream.String())
	}

	var firstErr error
	for _, target := range targets {
		msg, err := r.exchangeTarget(ctx, upstream, target, data)
		if err == nil {
			return msg, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	if firstErr == nil {
		firstErr = fmt.Errorf("failed to query upstream %q", upstream.String())
	}
	return nil, firstErr
}

func (r *Router) exchangeTarget(ctx context.Context, upstream *componentdns.Upstream, target netip.AddrPort, data []byte) (*dnsmessage.Msg, error) {
	switch upstream.Scheme {
	case componentdns.UpstreamScheme_UDP:
		return r.queryUDP(ctx, target, data)
	case componentdns.UpstreamScheme_TCP:
		return r.queryTCP(ctx, target, data)
	case componentdns.UpstreamScheme_TCP_UDP:
		msg, err := r.queryUDP(ctx, target, data)
		if err == nil {
			return msg, nil
		}
		if err != errInternalDNSTruncated {
			msg, tcpErr := r.queryTCP(ctx, target, data)
			if tcpErr == nil {
				return msg, nil
			}
			return nil, fmt.Errorf("udp query failed: %w; tcp fallback failed: %v", err, tcpErr)
		}
		return r.queryTCP(ctx, target, data)
	case componentdns.UpstreamScheme_TLS:
		return r.queryTLS(ctx, upstream, target, data)
	case componentdns.UpstreamScheme_HTTPS:
		return r.queryHTTPS(ctx, upstream, target, data, false)
	case componentdns.UpstreamScheme_H3:
		return r.queryHTTPS(ctx, upstream, target, data, true)
	case componentdns.UpstreamScheme_QUIC:
		return r.queryQUIC(ctx, upstream, target, data)
	default:
		return nil, fmt.Errorf("unsupported upstream scheme: %v", upstream.Scheme)
	}
}

func (r *Router) queryUDP(ctx context.Context, target netip.AddrPort, data []byte) (*dnsmessage.Msg, error) {
	conn, err := direct.SymmetricDirect.DialContext(ctx, common.MagicNetwork("udp", r.soMark, r.mptcp), target.String())
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	defer interruptConnOnCancel(ctx, conn)()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	originalID := binary.BigEndian.Uint16(data[:2])
	if _, err = netutils.WriteUDPConn(conn, target.String(), data); err != nil {
		return nil, err
	}
	buf := udpDNSBufPool.Get().([]byte)
	defer udpDNSBufPool.Put(buf) //nolint:staticcheck
	for range 8 {
		n, readErr := netutils.ReadUDPConn(conn, buf)
		if readErr != nil {
			return nil, readErr
		}
		if n < 2 || binary.BigEndian.Uint16(buf[:2]) != originalID {
			continue
		}
		var msg dnsmessage.Msg
		if err = msg.Unpack(buf[:n]); err != nil {
			return nil, err
		}
		if msg.Truncated {
			return nil, errInternalDNSTruncated
		}
		return &msg, nil
	}
	return nil, fmt.Errorf("too many stale UDP DNS responses")
}

func (r *Router) queryTCP(ctx context.Context, target netip.AddrPort, data []byte) (*dnsmessage.Msg, error) {
	conn, err := direct.SymmetricDirect.DialContext(ctx, common.MagicNetwork("tcp", r.soMark, r.mptcp), target.String())
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	defer interruptConnOnCancel(ctx, conn)()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	return sendStreamDNS(conn, data)
}

func (r *Router) queryTLS(ctx context.Context, upstream *componentdns.Upstream, target netip.AddrPort, data []byte) (*dnsmessage.Msg, error) {
	conn, err := direct.SymmetricDirect.DialContext(ctx, common.MagicNetwork("tcp", r.soMark, r.mptcp), target.String())
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	tlsConn := tls.Client(&netproxy.FakeNetConn{Conn: conn}, &tls.Config{
		ServerName:         upstream.Hostname,
		InsecureSkipVerify: false,
	})
	defer interruptConnOnCancel(ctx, tlsConn)()
	if deadline, ok := ctx.Deadline(); ok {
		_ = tlsConn.SetDeadline(deadline)
	}
	if err = tlsConn.Handshake(); err != nil {
		return nil, err
	}
	return sendStreamDNS(tlsConn, data)
}

func (r *Router) queryHTTPS(ctx context.Context, upstream *componentdns.Upstream, target netip.AddrPort, data []byte, http3Mode bool) (*dnsmessage.Msg, error) {
	transport := newHTTPTransportFunc(r, upstream, target, http3Mode)
	client := &http.Client{
		Transport: transport,
	}
	defer client.CloseIdleConnections()
	return sendHTTPDNSFunc(ctx, client, target.String(), upstream, data)
}

func (r *Router) newHTTPTransport(upstream *componentdns.Upstream, target netip.AddrPort, http3Mode bool) http.RoundTripper {
	if http3Mode {
		return &http3.Transport{
			TLSClientConfig: &tls.Config{
				ServerName:         upstream.Hostname,
				NextProtos:         []string{"h3"},
				InsecureSkipVerify: false,
			},
			QUICConfig: &quic.Config{},
			Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
				conn, err := direct.SymmetricDirect.DialContext(ctx, common.MagicNetwork("udp", r.soMark, r.mptcp), target.String())
				if err != nil {
					return nil, err
				}
				udpAddr := net.UDPAddrFromAddrPort(target)
				fakePkt := netproxy.NewFakeNetPacketConn(conn.(netproxy.PacketConn), net.UDPAddrFromAddrPort(tc.GetUniqueFakeAddrPort()), udpAddr)
				return quic.DialEarly(ctx, fakePkt, udpAddr, tlsCfg, cfg)
			},
		}
	}

	return &http.Transport{
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   20,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
		TLSClientConfig: &tls.Config{
			ServerName:         upstream.Hostname,
			InsecureSkipVerify: false,
		},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := direct.SymmetricDirect.DialContext(ctx, common.MagicNetwork("tcp", r.soMark, r.mptcp), target.String())
			if err != nil {
				return nil, err
			}
			return &netproxy.FakeNetConn{Conn: conn}, nil
		},
	}
}

func (r *Router) queryQUIC(ctx context.Context, upstream *componentdns.Upstream, target netip.AddrPort, data []byte) (*dnsmessage.Msg, error) {
	conn, err := direct.SymmetricDirect.DialContext(ctx, common.MagicNetwork("udp", r.soMark, r.mptcp), target.String())
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	udpAddr := net.UDPAddrFromAddrPort(target)
	fakePkt := netproxy.NewFakeNetPacketConn(conn.(netproxy.PacketConn), net.UDPAddrFromAddrPort(tc.GetUniqueFakeAddrPort()), udpAddr)
	tlsCfg := &tls.Config{
		NextProtos:         []string{"doq"},
		InsecureSkipVerify: false,
		ServerName:         upstream.Hostname,
	}
	qc, err := quic.DialEarly(ctx, fakePkt, udpAddr, tlsCfg, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = qc.CloseWithError(0, "") }()
	defer interruptQUICConnOnCancel(ctx, qc)()

	stream, err := qc.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = stream.Close() }()

	wire := append([]byte(nil), data...)
	binary.BigEndian.PutUint16(wire[:2], 0)
	return sendStreamDNS(stream, wire)
}

func upstreamTargets(upstream *componentdns.Upstream) []netip.AddrPort {
	targets := make([]netip.AddrPort, 0, 2)
	if upstream.Ip4.IsValid() {
		targets = append(targets, netip.AddrPortFrom(upstream.Ip4, upstream.Port))
	}
	if upstream.Ip6.IsValid() {
		targets = append(targets, netip.AddrPortFrom(upstream.Ip6, upstream.Port))
	}
	return targets
}

func requestedIPVersion(network string) string {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err == nil && magicNetwork.IPVersion != "" {
		return magicNetwork.IPVersion
	}
	switch network {
	case "tcp4", "udp4":
		return "4"
	case "tcp6", "udp6":
		return "6"
	default:
		return ""
	}
}

func sendHTTPDNS(ctx context.Context, client *http.Client, target string, upstream *componentdns.Upstream, data []byte) (*dnsmessage.Msg, error) {
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return fmt.Errorf("do not use a server that will redirect, upstream: %v", upstream.String())
	}
	serverURL := url.URL{
		Scheme: "https",
		Host:   target,
		Path:   upstream.Path,
	}
	wire := append([]byte(nil), data...)
	binary.BigEndian.PutUint16(wire[0:2], 0)
	q := serverURL.Query()
	q.Set("dns", base64.RawURLEncoding.EncodeToString(wire))
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
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http status code: %v", resp.StatusCode)
	}
	if contentType := resp.Header.Get("Content-Type"); contentType != "application/dns-message" {
		return nil, fmt.Errorf("unexpected content-type: %v", contentType)
	}
	buf, err := io.ReadAll(io.LimitReader(resp.Body, 65535))
	if err != nil {
		return nil, err
	}
	var msg dnsmessage.Msg
	if err = msg.Unpack(buf); err != nil {
		return nil, err
	}
	return &msg, nil
}

func sendStreamDNS(stream io.ReadWriter, data []byte) (*dnsmessage.Msg, error) {
	req := make([]byte, 2+len(data))
	binary.BigEndian.PutUint16(req[:2], uint16(len(data)))
	copy(req[2:], data)
	if _, err := stream.Write(req); err != nil {
		return nil, fmt.Errorf("failed to write DNS request: %w", err)
	}

	lengthBuf := make([]byte, 2)
	if _, err := io.ReadFull(stream, lengthBuf); err != nil {
		return nil, fmt.Errorf("failed to read DNS response length: %w", err)
	}
	respLen := int(binary.BigEndian.Uint16(lengthBuf))
	respBuf := make([]byte, respLen)
	if _, err := io.ReadFull(stream, respBuf); err != nil {
		return nil, fmt.Errorf("failed to read DNS response payload: %w", err)
	}
	var msg dnsmessage.Msg
	if err := msg.Unpack(respBuf); err != nil {
		return nil, err
	}
	return &msg, nil
}
