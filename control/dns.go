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
	"errors"
	"fmt"
	"io"
	"math/bits"
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
// It uses a reusable one-element channel to avoid per-request channel reallocation.
type responseSlot struct {
	result chan *dnsmessage.Msg
}

// responseSlotPool is a pool of responseSlot objects to reduce allocations.
var responseSlotPool = sync.Pool{
	New: func() interface{} {
		return &responseSlot{
			result: make(chan *dnsmessage.Msg, 1),
		}
	},
}

func newResponseSlot() *responseSlot {
	return responseSlotPool.Get().(*responseSlot)
}

func putResponseSlot(slot *responseSlot) {
	// Drain stale result before putting back.
	select {
	case <-slot.result:
	default:
	}
	responseSlotPool.Put(slot)
}

func (s *responseSlot) set(msg *dnsmessage.Msg) {
	// Never block read loop on duplicated/late responses.
	select {
	case s.result <- msg:
	default:
	}
}

func (s *responseSlot) get(ctx context.Context) (*dnsmessage.Msg, error) {
	select {
	case msg := <-s.result:
		if msg == nil {
			return nil, io.ErrUnexpectedEOF
		}
		return msg, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

const dnsPipelineMaxIDs = 4096

// idBitmap implements O(1) ID allocation using a bitmap
type idBitmap struct {
	bitmap [64]atomic.Uint64 // 4096 bits
	next   atomic.Uint32
}

func newIdBitmap() *idBitmap {
	return &idBitmap{}
}

func (b *idBitmap) Allocate() (uint16, error) {
	start := b.next.Add(1) - 1
	startWord := (start >> 6) & 63

	for i := uint32(0); i < 64; i++ {
		word := (startWord + i) & 63

		for {
			old := b.bitmap[word].Load()
			if old == ^uint64(0) {
				break // this word is full
			}

			free := ^old
			bit := uint32(bits.TrailingZeros64(free))
			if bit >= 64 {
				break
			}
			mask := uint64(1) << bit

			if b.bitmap[word].CompareAndSwap(old, old|mask) {
				id := (word << 6) | bit
				return uint16(id), nil
			}
		}
	}

	return 0, fmt.Errorf("no available ID")
}

func (b *idBitmap) Release(id uint16) {
	if id >= dnsPipelineMaxIDs {
		return
	}
	word := uint32(id) >> 6
	bit := uint32(id) & 63
	clearMask := ^(uint64(1) << bit)

	for {
		old := b.bitmap[word].Load()
		newVal := old & clearMask
		if old == newVal || b.bitmap[word].CompareAndSwap(old, newVal) {
			return
		}
	}
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
	// Slow path: clean up and decide whether to scale up.
	p.mu.Lock()
	p.pruneClosedLocked()

	var selected *pipelinedConn
	if len(p.conns) > 0 {
		idx := p.index.Load() % uint32(len(p.conns))
		selected = p.conns[idx]
		selectedLoad := selected.pendingCount.Load()

		// If pool is full or current load is low enough, reuse existing connection.
		if len(p.conns) >= p.maxConns || selectedLoad < connPoolScaleUpPendingThreshold {
			p.index.Add(1)
			p.mu.Unlock()
			return selected, nil
		}
	}

	// Need to create a new connection. Unlock first to avoid blocking all get() calls during dial.
	p.mu.Unlock()

	rawConn, err := p.dialer(ctx)
	if err != nil {
		return nil, err
	}

	conn := newPipelinedConn(rawConn)

	// Re-enter critical section: another goroutine may have filled pool while dialing.
	p.mu.Lock()
	p.pruneClosedLocked()
	if len(p.conns) >= p.maxConns {
		if len(p.conns) > 0 {
			idx := p.index.Load() % uint32(len(p.conns))
			selected = p.conns[idx]
			p.index.Add(1)
			p.mu.Unlock()
			conn.Close()
			return selected, nil
		}
		// Defensive: should not happen, but avoid leaking the newly dialed connection.
		p.mu.Unlock()
		conn.Close()
		return nil, fmt.Errorf("conn pool is full but has no active connection")
	}

	p.conns = append(p.conns, conn)
	p.index.Add(1)
	p.mu.Unlock()
	return conn, nil
}

func (p *connPool) pruneClosedLocked() {
	active := p.conns[:0]
	for _, c := range p.conns {
		select {
		case <-c.closed:
			// Connection is closed, skip it (already cleaned by readLoop)
		default:
			active = append(active, c)
		}
	}
	p.conns = active
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
	opsMu       sync.Mutex
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

			if p.closed.Load() {
				_ = connWithTime.conn.Close()
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
	if conn == nil {
		return
	}

	if p.closed.Load() {
		_ = conn.Close()
		return
	}

	// Wrap connection with current timestamp
	connWithTime := &udpConnWithTimestamp{
		conn:     conn,
		lastUsed: time.Now(),
	}

	p.opsMu.Lock()
	defer p.opsMu.Unlock()

	if p.closed.Load() {
		_ = conn.Close()
		return
	}

	select {
	case p.idleConns <- connWithTime:
		// Returned to pool
	default:
		// Pool full, close connection
		_ = conn.Close()
	}
}

func (p *udpConnPool) close() error {
	if p.closed.Swap(true) {
		return nil
	}

	p.opsMu.Lock()
	defer p.opsMu.Unlock()

	for {
		select {
		case connWithTime := <-p.idleConns:
			if connWithTime != nil && connWithTime.conn != nil {
				_ = connWithTime.conn.Close()
			}
		default:
			return nil
		}
	}
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

	deadline, hasDeadline := ctx.Deadline()
	if !hasDeadline {
		deadline = time.Now().Add(consts.DefaultDialTimeout)
	}
	// SetDeadline may fail on connection types that don't support deadlines;
	// context cancellation still provides timeout control.
	_ = conn.SetDeadline(deadline)

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
	const maxStaleResponses = 8
	staleResponses := 0

	for {
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

		if n < 2 {
			staleResponses++
			if staleResponses > maxStaleResponses {
				conn.Close()
				badConn = true
				return nil, fmt.Errorf("too many malformed UDP DNS responses")
			}
			continue
		}

		responseID := binary.BigEndian.Uint16(respBuf[0:2])
		if responseID != originalID {
			// Stale packet from previous request, discard and continue waiting
			// for the response with matching request ID.
			staleResponses++
			if d.log != nil && d.log.IsLevelEnabled(logrus.DebugLevel) {
				d.log.Debugf("discard stale UDP DNS response: expected %d, got %d", originalID, responseID)
			}
			if staleResponses > maxStaleResponses {
				conn.Close()
				badConn = true
				return nil, fmt.Errorf("too many stale UDP DNS responses")
			}
			continue
		}

		var msg dnsmessage.Msg
		if err = msg.Unpack(respBuf[:n]); err != nil {
			conn.Close()
			badConn = true
			return nil, err
		}
		return &msg, nil
	}
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

	// pending stores in-flight requests by DNS ID (0..4095), lock-free on hot path.
	pending [dnsPipelineMaxIDs]atomic.Pointer[responseSlot]

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
		for i := range pc.pending {
			if slot := pc.pending[i].Swap(nil); slot != nil {
				slot.set(nil) // Signal with nil to indicate error
			}
		}
	}()

	for {
		// Read 2-byte length
		var header [2]byte
		if _, err := io.ReadFull(pc.conn, header[:]); err != nil {
			pc.errMu.Lock()
			pc.err = err
			pc.errMu.Unlock()
			return
		}
		l := binary.BigEndian.Uint16(header[:])

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

		respMsg := new(dnsmessage.Msg)
		if err := respMsg.Unpack(buf); err != nil {
			// Protocol error, close connection
			pc.errMu.Lock()
			pc.err = fmt.Errorf("bad DNS packet: %w", err)
			pc.errMu.Unlock()
			pool.Put(buf)
			return
		}
		pool.Put(buf)

		if respMsg.Id < dnsPipelineMaxIDs {
			slot := pc.pending[respMsg.Id].Swap(nil)
			if slot == nil {
				continue
			}
			slot.set(respMsg)
		}
	}
}

func (pc *pipelinedConn) RoundTrip(ctx context.Context, data []byte) (*dnsmessage.Msg, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("invalid DNS request payload: too short")
	}

	// Allocate ID using bitmap allocator (O(1) time complexity)
	id, err := pc.idAlloc.Allocate()
	if err != nil {
		return nil, fmt.Errorf("failed to allocate ID: %w", err)
	}

	// Get response slot from pool
	slot := newResponseSlot()
	defer putResponseSlot(slot)

	// Store the pending request
	if !pc.pending[id].CompareAndSwap(nil, slot) {
		pc.idAlloc.Release(id)
		return nil, fmt.Errorf("pending slot is unexpectedly occupied")
	}
	pc.pendingCount.Add(1)

	defer func() {
		pc.pending[id].CompareAndSwap(slot, nil)
		pc.idAlloc.Release(id)
		pc.pendingCount.Add(-1)
	}()

	// Write request with pooled contiguous buffer to keep a single write path and avoid mutating caller input.
	reqLen := len(data)
	buf := pool.Get(2 + reqLen)
	defer pool.Put(buf)

	binary.BigEndian.PutUint16(buf[0:2], uint16(reqLen))
	copy(buf[2:], data)
	binary.BigEndian.PutUint16(buf[2:4], id)

	pc.writeMu.Lock()
	_, err = pc.conn.Write(buf)
	pc.writeMu.Unlock()

	if err != nil {
		return nil, err
	}

	msg, err := slot.get(ctx)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			// Avoid stale-response cross-delivery after ID reuse.
			// Once a request times out/cancels, late responses are no longer trustworthy
			// for this transport-level pipeline, so we fail fast by recycling the connection.
			pc.Close()
		}
		return nil, err
	}

	return msg, nil
}

func (pc *pipelinedConn) Close() {
	_ = pc.conn.Close()
	// readLoop will detect close and clean up
}
