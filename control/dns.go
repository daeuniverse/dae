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
	"sync/atomic"
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
	"github.com/sirupsen/logrus"
)

// responseSlot represents a pending DNS request response slot.
// Uses atomic.Value for lock-free reads and a channel for waiting.
type responseSlot struct {
	msg  atomic.Value // *dnsmessage.Msg
	done chan struct{}
}

// responseSlotPool is a pool of responseSlot objects to reduce allocations.
var responseSlotPool = sync.Pool{
	New: func() interface{} {
		return &responseSlot{
			done: make(chan struct{}),
		}
	},
}

func newResponseSlot() *responseSlot {
	slot := responseSlotPool.Get().(*responseSlot)
	// Reset the channel if it was closed
	select {
	case <-slot.done:
		slot.done = make(chan struct{})
	default:
	}
	return slot
}

func putResponseSlot(slot *responseSlot) {
	// Clear the message reference
	slot.msg.Store((*dnsmessage.Msg)(nil))
	responseSlotPool.Put(slot)
}

func (s *responseSlot) set(msg *dnsmessage.Msg) {
	s.msg.Store(msg)
	close(s.done)
}

func (s *responseSlot) get(ctx context.Context) (*dnsmessage.Msg, error) {
	select {
	case <-s.done:
		msg := s.msg.Load()
		if msg == nil {
			return nil, io.ErrUnexpectedEOF
		}
		return msg.(*dnsmessage.Msg), nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// idBitmap implements O(1) ID allocation using a bitmap
type idBitmap struct {
	bitmap [64]uint64 // 4096 bits
	mu     sync.Mutex
	next   uint32
}

func newIdBitmap() *idBitmap {
	return &idBitmap{}
}

func (b *idBitmap) Allocate() (uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	for i := 0; i < 4096; i++ {
		id := (b.next + uint32(i)) % 4096
		word := id / 64
		bit := id % 64

		if b.bitmap[word]&(1<<bit) == 0 {
			b.bitmap[word] |= 1 << bit
			b.next = (id + 1) % 4096
			return uint16(id), nil
		}
	}

	return 0, fmt.Errorf("no available ID")
}

func (b *idBitmap) Release(id uint16) {
	if id >= 4096 {
		return
	}

	b.mu.Lock()
	word := id / 64
	bit := id % 64
	b.bitmap[word] &^= 1 << bit
	b.mu.Unlock()
}

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

func newDnsForwarder(upstream *dns.Upstream, dialArgument dialArgument, log *logrus.Logger) (DnsForwarder, error) {
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
				return &DoUDP{Upstream: *upstream, Dialer: dialArgument.bestDialer, dialArgument: dialArgument, log: log}, nil
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

// connPool implements a connection pool for DNS forwarders.
// Follows Go best practices from database/sql and net/http.
type connPool struct {
	conns    []*pipelinedConn
	mu       sync.RWMutex
	maxConns int
	index    atomic.Uint32
	dialer   func(context.Context) (netproxy.Conn, error)
}

const connPoolScaleUpPendingThreshold int32 = 64

func newConnPool(maxConns int, dialer func(context.Context) (netproxy.Conn, error)) *connPool {
	if maxConns <= 0 {
		maxConns = 1
	}
	return &connPool{
		conns:    make([]*pipelinedConn, 0, maxConns),
		maxConns: maxConns,
		dialer:   dialer,
	}
}

func (p *connPool) get(ctx context.Context) (*pipelinedConn, error) {
	// Fast path: lock-free-ish read on existing connections.
	p.mu.RLock()
	if len(p.conns) > 0 {
		idx := p.index.Load() % uint32(len(p.conns))
		conn := p.conns[idx]
		load := conn.pendingCount.Load()
		canScaleUp := len(p.conns) < p.maxConns && load >= connPoolScaleUpPendingThreshold

		select {
		case <-conn.closed:
			// Closed connection, fall through to slow path for cleanup.
		default:
			p.mu.RUnlock()
			p.index.Add(1)
			if !canScaleUp {
				return conn, nil
			}
			goto slowPath
		}
	}
	p.mu.RUnlock()

	slowPath:
	// Slow path: need to create new connection or clean up pool
	p.mu.Lock()
	defer p.mu.Unlock()

	// Clean up closed connections before attempting to get/create
	var active []*pipelinedConn
	for _, c := range p.conns {
		select {
		case <-c.closed:
			// Connection is closed, skip it (already cleaned by readLoop)
		default:
			active = append(active, c)
		}
	}
	p.conns = active

	var selected *pipelinedConn
	var selectedLoad int32
	if len(p.conns) > 0 {
		idx := p.index.Load() % uint32(len(p.conns))
		selected = p.conns[idx]
		selectedLoad = selected.pendingCount.Load()

		// If pool is full or current load is low enough, reuse existing connection.
		if len(p.conns) >= p.maxConns || selectedLoad < connPoolScaleUpPendingThreshold {
			p.index.Add(1)
			return selected, nil
		}
	}

	// Create new connection when pool has room and current load suggests contention.
	if len(p.conns) >= p.maxConns && selected != nil {
		p.index.Add(1)
		return selected, nil
	}

	rawConn, err := p.dialer(ctx)
	if err != nil {
		return nil, err
	}

	conn := newPipelinedConn(rawConn)
	p.conns = append(p.conns, conn)
	p.index.Add(1)
	return conn, nil
}

func (p *connPool) close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, conn := range p.conns {
		conn.Close() // pipelinedConn.Close() has no return value
	}
	p.conns = nil
	return nil
}

type DoTLS struct {
	dns.Upstream
	netproxy.Dialer
	dialArgument dialArgument

	pool *connPool
	mu   sync.RWMutex
}

func (d *DoTLS) getPool() *connPool {
	d.mu.RLock()
	if d.pool != nil {
		defer d.mu.RUnlock()
		return d.pool
	}
	d.mu.RUnlock()

	d.mu.Lock()
	defer d.mu.Unlock()

	if d.pool != nil {
		return d.pool
	}

	// Create connection pool with 4 connections (Go best practice)
	d.pool = newConnPool(4, func(ctx context.Context) (netproxy.Conn, error) {
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
		return tlsConn, nil
	})

	return d.pool
}

func (d *DoTLS) getPConn(ctx context.Context) (*pipelinedConn, error) {
	pool := d.getPool()
	return pool.get(ctx)
}

func (d *DoTLS) ForwardDNS(ctx context.Context, data []byte) (*dnsmessage.Msg, error) {
	// With connection pool, we can retry with different connections
	for i := 0; i < 2; i++ {
		pc, err := d.getPConn(ctx)
		if err != nil {
			return nil, err
		}

		msg, err := pc.RoundTrip(ctx, data)
		if err == nil {
			return msg, nil
		}

		// Close the connection explicitly if RoundTrip fails
		pc.Close()

		// Connection might be broken, but pool will handle it
		// Next retry will get a different connection from pool
	}
	return nil, fmt.Errorf("failed to forward DNS after retry")
}

func (d *DoTLS) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.pool != nil {
		err := d.pool.close()
		d.pool = nil
		return err
	}
	return nil
}

type DoTCP struct {
	dns.Upstream
	netproxy.Dialer
	dialArgument dialArgument

	pool *connPool
	mu   sync.RWMutex
}

func (d *DoTCP) getPool() *connPool {
	d.mu.RLock()
	if d.pool != nil {
		defer d.mu.RUnlock()
		return d.pool
	}
	d.mu.RUnlock()

	d.mu.Lock()
	defer d.mu.Unlock()

	if d.pool != nil {
		return d.pool
	}

	// Create connection pool with 4 connections (Go best practice)
	d.pool = newConnPool(4, func(ctx context.Context) (netproxy.Conn, error) {
		return d.dialArgument.bestDialer.DialContext(
			ctx,
			common.MagicNetwork("tcp", d.dialArgument.mark, d.dialArgument.mptcp),
			d.dialArgument.bestTarget.String(),
		)
	})

	return d.pool
}

func (d *DoTCP) getPConn(ctx context.Context) (*pipelinedConn, error) {
	pool := d.getPool()
	return pool.get(ctx)
}

func (d *DoTCP) ForwardDNS(ctx context.Context, data []byte) (*dnsmessage.Msg, error) {
	// With connection pool, we can retry with different connections
	for i := 0; i < 2; i++ {
		pc, err := d.getPConn(ctx)
		if err != nil {
			return nil, err
		}

		msg, err := pc.RoundTrip(ctx, data)
		if err == nil {
			return msg, nil
		}

		// Close the connection explicitly if RoundTrip fails
		pc.Close()

		// Connection might be broken, but pool will handle it
		// Next retry will get a different connection from pool
	}
	return nil, fmt.Errorf("failed to forward DNS after retry")
}

func (d *DoTCP) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.pool != nil {
		err := d.pool.close()
		d.pool = nil
		return err
	}
	return nil
}

// udpConnWithTimestamp wraps a connection with its last use time
type udpConnWithTimestamp struct {
	conn     netproxy.Conn
	lastUsed time.Time
}

// udpConnPool implements a UDP connection pool.
// It uses a poor-man's pool (borrow/return) to reuse sockets sequentially.
// Connections are tracked with timestamps to prevent stale packet issues.
type udpConnPool struct {
	idleConns   chan *udpConnWithTimestamp
	dialer      func(context.Context) (netproxy.Conn, error)
	closed      atomic.Bool
	maxIdleTime time.Duration // Connections older than this are discarded
}

func newUdpConnPool(maxIdle int, dialer func(context.Context) (netproxy.Conn, error)) *udpConnPool {
	return &udpConnPool{
		idleConns:   make(chan *udpConnWithTimestamp, maxIdle),
		dialer:      dialer,
		maxIdleTime: 30 * time.Second, // Discard connections idle for more than 30s
	}
}

func (p *udpConnPool) get(ctx context.Context) (netproxy.Conn, error) {
	if p.closed.Load() {
		return nil, io.ErrClosedPipe
	}

	// Try to get an idle connection, checking for expiry
	for {
		select {
		case connWithTime := <-p.idleConns:
			if connWithTime == nil { // Channel closed (double check)
				return nil, io.ErrClosedPipe
			}

			// Check if connection is too old (prevent stale packets)
			if time.Since(connWithTime.lastUsed) > p.maxIdleTime {
				// Connection expired, close it and try next one
				connWithTime.conn.Close()
				continue
			}

			return connWithTime.conn, nil
		default:
			// No idle connection, create new one
			if p.closed.Load() {
				return nil, io.ErrClosedPipe
			}
			return p.dialer(ctx)
		}
	}
}

func (p *udpConnPool) put(conn netproxy.Conn) {
	if p.closed.Load() {
		conn.Close()
		return
	}

	// Wrap connection with current timestamp
	connWithTime := &udpConnWithTimestamp{
		conn:     conn,
		lastUsed: time.Now(),
	}

	select {
	case p.idleConns <- connWithTime:
		// Returned to pool
	default:
		// Pool full, close connection
		conn.Close()
	}
}

func (p *udpConnPool) close() error {
	if p.closed.Swap(true) {
		return nil
	}
	close(p.idleConns)
	for connWithTime := range p.idleConns {
		if connWithTime != nil && connWithTime.conn != nil {
			connWithTime.conn.Close()
		}
	}
	return nil
}

type DoUDP struct {
	dns.Upstream
	netproxy.Dialer
	dialArgument dialArgument

	pool *udpConnPool
	mu   sync.RWMutex
	log  *logrus.Logger
}

func (d *DoUDP) getPool() *udpConnPool {
	d.mu.RLock()
	if d.pool != nil {
		defer d.mu.RUnlock()
		return d.pool
	}
	d.mu.RUnlock()

	d.mu.Lock()
	defer d.mu.Unlock()

	if d.pool != nil {
		return d.pool
	}

	// Create UDP connection pool with 8 connections (UDP is lightweight)
	d.pool = newUdpConnPool(8, func(ctx context.Context) (netproxy.Conn, error) {
		return d.dialArgument.bestDialer.DialContext(
			ctx,
			common.MagicNetwork("udp", d.dialArgument.mark, d.dialArgument.mptcp),
			d.dialArgument.bestTarget.String(),
		)
	})

	return d.pool
}

func (d *DoUDP) ForwardDNS(ctx context.Context, data []byte) (*dnsmessage.Msg, error) {
	udpPool := d.getPool()
	conn, err := udpPool.get(ctx)
	if err != nil {
		return nil, err
	}

	// Track if connection is bad to avoid returning it to pool
	badConn := false
	defer func() {
		if !badConn {
			udpPool.put(conn)
		}
		// If badConn is true, conn.Close() was already called
	}()

	timeout := 5 * time.Second
	// SetDeadline may fail on connection types that don't support deadlines;
	// the timeout is also handled by the context.
	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Extract original DNS ID for validation
	var originalID uint16
	if len(data) >= 2 {
		originalID = binary.BigEndian.Uint16(data[0:2])
	}

	// Send DNS request directly without creating goroutine
	if _, err = conn.Write(data); err != nil {
		conn.Close() // Mark as bad
		badConn = true
		return nil, err
	}

	// Wait for response
	respBuf := pool.GetFullCap(consts.EthernetMtu)
	defer pool.Put(respBuf)
	n, err := conn.Read(respBuf)
	if err != nil {
		// If timeout, we don't mark connection as bad to avoid expensive reconstruction
		// (especially for SOCKS5 tunnel). Stale packets might be an issue but
		// usually less critical than connection storm.
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return nil, err
		}
		conn.Close() // Mark as bad
		badConn = true
		return nil, err
	}

	// Validate DNS ID to detect stale packets
	if n >= 2 {
		responseID := binary.BigEndian.Uint16(respBuf[0:2])
		if responseID != originalID {
			// This is a stale packet from a previous request
			// Log and close the connection to force fresh one
			if d.log != nil {
				d.log.Warnf("UDP DNS response ID mismatch: expected %d, got %d (stale packet detected)", originalID, responseID)
			}
			conn.Close()
			badConn = true
			return nil, fmt.Errorf("DNS response ID mismatch: stale packet")
		}
	}

	var msg dnsmessage.Msg
	if err = msg.Unpack(respBuf[:n]); err != nil {
		return nil, err
	}
	return &msg, nil
}

func (d *DoUDP) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.pool != nil {
		err := d.pool.close()
		d.pool = nil
		return err
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

	// routing: use sync.Map for better concurrent performance
	pending sync.Map // map[uint16]*responseSlot

	// ID allocation: use bitmap for O(1) allocation
	idAlloc *idBitmap

	// pendingCount tracks in-flight requests for adaptive pool scaling.
	pendingCount atomic.Int32

	// lifecycle
	errMu  sync.Mutex
	err    error
	closed chan struct{}
}

func newPipelinedConn(conn netproxy.Conn) *pipelinedConn {
	pc := &pipelinedConn{
		conn:    conn,
		pending: sync.Map{},
		idAlloc: newIdBitmap(),
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

		// Cleanup all pending - close all response slots
		pc.pending.Range(func(key, value interface{}) bool {
			if slot, ok := value.(*responseSlot); ok {
				slot.set(nil) // Signal with nil to indicate error
			}
			return true
		})
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

		if l == 0 {
			pc.errMu.Lock()
			pc.err = fmt.Errorf("invalid DNS payload length: %d", l)
			pc.errMu.Unlock()
			return
		}

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

		// Use sync.Map for lock-free pending request lookup
		if val, ok := pc.pending.LoadAndDelete(msg.Id); ok {
			slot := val.(*responseSlot)
			slot.set(&msg)
		}
	}
}

func (pc *pipelinedConn) RoundTrip(ctx context.Context, data []byte) (*dnsmessage.Msg, error) {
	// Allocate ID using bitmap allocator (O(1) time complexity)
	id, err := pc.idAlloc.Allocate()
	if err != nil {
		return nil, fmt.Errorf("failed to allocate ID: %w", err)
	}

	// Get response slot from pool
	slot := newResponseSlot()
	defer putResponseSlot(slot)

	// Store the pending request
	pc.pending.Store(id, slot)
	pc.pendingCount.Add(1)

	defer func() {
		pc.pending.Delete(id)
		pc.idAlloc.Release(id)
		pc.pendingCount.Add(-1)
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
	_, err = pc.conn.Write(buf)
	pc.writeMu.Unlock()

	if err != nil {
		return nil, err
	}

	return slot.get(ctx)
}

func (pc *pipelinedConn) Close() {
	_ = pc.conn.Close()
	// readLoop will detect close and clean up
}
