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
	"sync"
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
	"github.com/daeuniverse/outbound/pkg/fastrand"
)

// channelPool is a pool of channels for DNS response routing.
// This reduces allocations in the hot path.
var channelPool = sync.Pool{
	New: func() interface{} {
		return make(chan *dnsmessage.Msg, 1)
	},
}

func getResponseChannel() chan *dnsmessage.Msg {
	return channelPool.Get().(chan *dnsmessage.Msg)
}

func putResponseChannel(ch chan *dnsmessage.Msg) {
	// Drain the channel before returning to pool
	select {
	case <-ch:
	default:
	}
	channelPool.Put(ch)
}

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

func (d *DoH) ForwardDNS(ctx context.Context, data []byte) (*dnsmessage.Msg, error) {
	if d.client == nil {
		d.client = d.getClient()
	}
	msg, err := sendHttpDNS(d.client, d.dialArgument.bestTarget.String(), &d.Upstream, data)
	if err != nil {
		// If failed to send DNS request, we should try to create a new client.
		d.client = d.getClient()
		msg, err = sendHttpDNS(d.client, d.dialArgument.bestTarget.String(), &d.Upstream, data)
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
	if d.client != nil {
		d.client.CloseIdleConnections()
	}
	return nil
}

type DoQ struct {
	dns.Upstream
	netproxy.Dialer
	dialArgument dialArgument
	connection   quic.EarlyConnection
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
		// If failed to open stream, we should try to create a new connection.
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
		// Best effort cleanup; stream may already be closed by QUIC implementation.
		_ = stream.Close()
	}()

	// According https://datatracker.ietf.org/doc/html/rfc9250#section-4.2.1
	// msg id should set to 0 when transport over QUIC.
	// thanks https://github.com/natesales/q/blob/1cb2639caf69bd0a9b46494a3c689130df8fb24a/transport/quic.go#L97
	binary.BigEndian.PutUint16(data[0:2], 0)

	msg, err := sendStreamDNS(stream, data)
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
		conn.Close() // Ensure underlying connection is closed
		return nil, err
	}
	return qc, nil
}

func (d *DoQ) Close() error {
	if d.connection != nil {
		return d.connection.CloseWithError(0, "")
	}
	return nil
}

type DoTLS struct {
	dns.Upstream
	netproxy.Dialer
	dialArgument dialArgument
	
	pConn *pipelinedConn
	mu    sync.Mutex
}

func (d *DoTLS) getPConn(ctx context.Context) (*pipelinedConn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.pConn != nil {
		select {
		case <-d.pConn.closed:
		default:
			return d.pConn, nil
		}
	}

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
		conn.Close()
		return nil, err
	}
	d.pConn = newPipelinedConn(tlsConn)
	return d.pConn, nil
}

func (d *DoTLS) ForwardDNS(ctx context.Context, data []byte) (*dnsmessage.Msg, error) {
	for i := 0; i < 2; i++ {
		pc, err := d.getPConn(ctx)
		if err != nil {
			return nil, err
		}

		msg, err := pc.RoundTrip(ctx, data)
		if err == nil {
			return msg, nil
		}

		d.mu.Lock()
		if d.pConn == pc {
			pc.Close()
			d.pConn = nil
		}
		d.mu.Unlock()
	}
	return nil, fmt.Errorf("failed to forward DNS after retry")
}

func (d *DoTLS) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.pConn != nil {
		d.pConn.Close()
		d.pConn = nil
	}
	return nil
}

type DoTCP struct {
	dns.Upstream
	netproxy.Dialer
	dialArgument dialArgument
	
	pConn *pipelinedConn
	mu    sync.Mutex
}

func (d *DoTCP) getPConn(ctx context.Context) (*pipelinedConn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	// If conn exists and is healthy, return it
	if d.pConn != nil {
		select {
		case <-d.pConn.closed:
			// Closed, create new one
		default:
			return d.pConn, nil
		}
	}

	conn, err := d.dialArgument.bestDialer.DialContext(
		ctx,
		common.MagicNetwork("tcp", d.dialArgument.mark, d.dialArgument.mptcp),
		d.dialArgument.bestTarget.String(),
	)
	if err != nil {
		return nil, err
	}
	d.pConn = newPipelinedConn(conn)
	return d.pConn, nil
}

func (d *DoTCP) ForwardDNS(ctx context.Context, data []byte) (*dnsmessage.Msg, error) {
	// Simple retry logic used to consist of 2 attempts.
	// With pipelining, we just try to get a connection and send.
	// If the connection dies during our request, we fail (or we could retry).
	// Let's implement retry for robustness.
	for i := 0; i < 2; i++ {
		pc, err := d.getPConn(ctx)
		if err != nil {
			return nil, err
		}

		msg, err := pc.RoundTrip(ctx, data)
		if err == nil {
			return msg, nil
		}

		// If error occurred, connection might be broken.
		// If the error is not temporary, or we just want to be safe, we close it.
		// Actually pipelinedConn handles its own closing on IO error.
		// But we might need to invalidate d.pConn if it's the same one.
		
		d.mu.Lock()
		if d.pConn == pc {
			// pc.Close() is idempotent and might already be called by readLoop
			pc.Close() 
			d.pConn = nil
		}
		d.mu.Unlock()
	}
	return nil, fmt.Errorf("failed to forward DNS after retry")
}

func (d *DoTCP) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.pConn != nil {
		d.pConn.Close()
		d.pConn = nil
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
	defer conn.Close() // Ensure connection is closed

	timeout := 5 * time.Second
	// SetDeadline may fail on connection types that don't support deadlines;
	// the timeout is also handled by the context.
	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Send DNS request directly without creating goroutine
	if _, err = conn.Write(data); err != nil {
		return nil, err
	}

	// Wait for response
	respBuf := pool.GetFullCap(consts.EthernetMtu)
	defer pool.Put(respBuf)
	n, err := conn.Read(respBuf)
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
		return d.conn.Close()
	}
	return nil
}

func sendHttpDNS(client *http.Client, target string, upstream *dns.Upstream, data []byte) (respMsg *dnsmessage.Msg, err error) {
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

	req, err := http.NewRequest(http.MethodGet, serverURL.String(), nil)
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

func sendStreamDNS(stream io.ReadWriter, data []byte) (respMsg *dnsmessage.Msg, err error) {
	// We should write two byte length in the front of stream DNS request.
	bReq := pool.Get(2 + len(data))
	defer pool.Put(bReq)
	binary.BigEndian.PutUint16(bReq, uint16(len(data)))
	copy(bReq[2:], data)
	_, err = stream.Write(bReq)
	if err != nil {
		return nil, fmt.Errorf("failed to write DNS req: %w", err)
	}

	// Read two byte length.
	if _, err = io.ReadFull(stream, bReq[:2]); err != nil {
		return nil, fmt.Errorf("failed to read DNS resp payload length: %w", err)
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

type pipelinedConn struct {
conn    netproxy.Conn
writeMu sync.Mutex

// routing
pendingMu sync.Mutex
pending   map[uint16]chan *dnsmessage.Msg

// lifecycle
errMu  sync.Mutex
err    error
closed chan struct{}
}

func newPipelinedConn(conn netproxy.Conn) *pipelinedConn {
pc := &pipelinedConn{
conn:    conn,
pending: make(map[uint16]chan *dnsmessage.Msg),
closed:  make(chan struct{}),
}
go pc.readLoop()
return pc
}

func (pc *pipelinedConn) readLoop() {
defer func() {
_ = pc.conn.Close()
pc.errMu.Lock()
if pc.err == nil {
pc.err = io.ErrUnexpectedEOF
}
pc.errMu.Unlock()

close(pc.closed)

// Cleanup all pending
pc.pendingMu.Lock()
for _, ch := range pc.pending {
close(ch)
}
pc.pending = nil
pc.pendingMu.Unlock()
}()

for {
// Read 2-byte length
// We use a small buffer from pool or just stack alloc since it's 2 bytes?
// Pool is safer for GC if high throughput.
header := pool.Get(2)
if _, err := io.ReadFull(pc.conn, header); err != nil {
pc.errMu.Lock()
pc.err = err
pc.errMu.Unlock()
pool.Put(header)
return
}
l := binary.BigEndian.Uint16(header)
pool.Put(header)

// Read payload
buf := pool.Get(int(l))
if _, err := io.ReadFull(pc.conn, buf); err != nil {
pc.errMu.Lock()
pc.err = err
pc.errMu.Unlock()
pool.Put(buf)
return
}

var msg dnsmessage.Msg
if err := msg.Unpack(buf); err != nil {
// Protocol error, close connection
pc.errMu.Lock()
pc.err = fmt.Errorf("bad DNS packet: %w", err)
pc.errMu.Unlock()
pool.Put(buf)
return
	}
	pool.Put(buf)

	pc.pendingMu.Lock()
	if ch, ok := pc.pending[msg.Id]; ok {
		select {
		case ch <- &msg:
		default:
			// Receiver abandoned channel or timed out.
			// This is expected under high load when requests timeout before response arrives.
		}
		// One-shot channel, remove after use.
		delete(pc.pending, msg.Id)
	}
	pc.pendingMu.Unlock()
	}
}

func (pc *pipelinedConn) RoundTrip(ctx context.Context, data []byte) (*dnsmessage.Msg, error) {
	// Allocate ID using linear probe + random start
	var id uint16

	pc.pendingMu.Lock()
	if pc.pending == nil {
		pc.pendingMu.Unlock()
		return nil, io.ErrClosedPipe
	}

	// Get channel from pool instead of allocating new one
	ch := getResponseChannel()
	defer putResponseChannel(ch)

	// Allocate ID using linear probe + random start (Go best practice for hash collision resolution)
	// This is more efficient than pure random under high contention.
	// Reference: https://go.dev/src/net/http/transport.go
	allocSuccess := false
	start := uint16(fastrand.Uint32())
	for i := uint16(0); i < 1000; i++ {
		id = start + i
		if _, ok := pc.pending[id]; !ok {
			pc.pending[id] = ch
			allocSuccess = true
			break
		}
	}
	pc.pendingMu.Unlock()

	if !allocSuccess {
		return nil, fmt.Errorf("failed to allocate transaction ID: too many in-flight requests (pending: %d)", len(pc.pending))
	}

	defer func() {
		pc.pendingMu.Lock()
		if pc.pending != nil {
			delete(pc.pending, id)
		}
		pc.pendingMu.Unlock()
	}()

	// Write request
// We need to copy data because we are modifying ID in-place and adding length prefix
// data[0:2] is ID.
reqLen := len(data)
buf := pool.Get(2 + reqLen)
defer pool.Put(buf)

binary.BigEndian.PutUint16(buf[0:2], uint16(reqLen))
copy(buf[2:], data)
// Update ID in buffer
binary.BigEndian.PutUint16(buf[2:4], id)

pc.writeMu.Lock()
_, err := pc.conn.Write(buf)
pc.writeMu.Unlock()

if err != nil {
return nil, err
}

select {
case msg, ok := <-ch:
if !ok {
// Channel closed -> connection closed
pc.errMu.Lock()
err := pc.err
pc.errMu.Unlock()
if err == nil {
return nil, io.EOF
}
return nil, err
}
return msg, nil
case <-ctx.Done():
return nil, ctx.Err()
}
}

func (pc *pipelinedConn) Close() {
_ = pc.conn.Close()
// readLoop will detect close and clean up
}
