/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/dae/component/dnstransport"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
	dnsmessage "github.com/miekg/dns"
	"github.com/olicesx/quic-go"
	"github.com/sirupsen/logrus"
)

// responseSlot represents a pending DNS request response slot.
// It uses a reusable one-element channel to avoid per-request channel reallocation.
//
// Recycling discipline: a slot checked out by RoundTrip is returned to the
// pool by exactly one actor. RoundTrip recycles it itself when the pending
// entry was still registered (no setter can reach the slot) or when the
// response was already delivered (the setter finished and never touches the
// slot again). In every other case the pending entry was claimed by
// readLoop/closeWithErr, so recycle responsibility is transferred to that
// setter via abandon. mu serializes set with abandon/recycle so a late
// delivery can never leak into the slot's next pool cycle and cross-answer
// a different request.
type responseSlot struct {
	result chan *dnsmessage.Msg

	mu        sync.Mutex
	settled   bool // a setter completed delivery for this checkout
	abandoned bool // the waiter is gone; the completing setter must recycle
}

// responseSlotPool is a pool of responseSlot objects to reduce allocations.
var responseSlotPool = sync.Pool{
	New: func() any {
		return &responseSlot{
			result: make(chan *dnsmessage.Msg, 1),
		}
	},
}

// doqExchangeTimeout bounds a single DNS-over-QUIC exchange when the caller
// did not already provide a tighter deadline. Quic-go streams only observe
// cancellation through deadlines, and a peer that keeps the connection alive
// while withholding a response must not pin this goroutine, the singleflight
// slot and the open stream indefinitely.
const doqExchangeTimeout = 8 * time.Second

// doqRequestCancelledCode is DOQ_REQUEST_CANCELLED (RFC 9250 §4.3.1), sent
// via STOP_SENDING/RESET_STREAM when a query is abandoned.
const doqRequestCancelledCode quic.StreamErrorCode = 0x3

func newResponseSlot() *responseSlot {
	s := responseSlotPool.Get().(*responseSlot)
	s.mu.Lock()
	s.settled = false
	s.abandoned = false
	s.mu.Unlock()
	return s
}

// recycleLocked resets and returns the slot to the pool. It unlocks mu.
func (s *responseSlot) recycleLocked() {
	s.settled = false
	s.abandoned = false
	// Drain stale result before putting back.
	select {
	case <-s.result:
	default:
	}
	s.mu.Unlock()
	responseSlotPool.Put(s)
}

func putResponseSlot(slot *responseSlot) {
	slot.mu.Lock()
	slot.recycleLocked()
}

func (s *responseSlot) set(msg *dnsmessage.Msg) {
	s.mu.Lock()
	s.settled = true
	// Never block read loop on duplicated/late responses.
	select {
	case s.result <- msg:
	default:
	}
	recycle := s.abandoned
	s.abandoned = false
	s.mu.Unlock()
	if recycle {
		putResponseSlot(s)
	}
}

// abandon hands recycle responsibility to the setter that claimed the pending
// entry. If that setter already delivered, recycle immediately; otherwise the
// next (and only) set recycles the slot.
func (s *responseSlot) abandon() {
	s.mu.Lock()
	if s.settled {
		s.recycleLocked()
		return
	}
	s.abandoned = true
	s.mu.Unlock()
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

	for i := range uint32(64) {
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
				return &DoUDP{
					Upstream:     *upstream,
					Dialer:       dialArgument.bestDialer,
					dialArgument: dialArgument,
					profile:      newDnsLifecycleProfile(dialArgument.bestDialer),
					log:          log,
				}, nil
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

type doHSendFunc func(ctx context.Context, client *http.Client, target string, upstream *dns.Upstream, data []byte) (*dnsmessage.Msg, error)

type DoH struct {
	dns.Upstream
	netproxy.Dialer
	dialArgument      dialArgument
	http3             bool
	mu                sync.Mutex
	closed            bool
	client            *dnstransport.HTTPClientGeneration
	clientGenerations map[*dnstransport.HTTPClientGeneration]struct{}
	clientFactory     func() *http.Client
	sendFunc          doHSendFunc
}

func (d *DoH) sendDNS(ctx context.Context, client *http.Client, data []byte) (*dnsmessage.Msg, error) {
	if d.sendFunc != nil {
		return d.sendFunc(ctx, client, d.dialArgument.bestTarget.String(), &d.Upstream, data)
	}
	return dnstransport.SendHTTPDNS(ctx, client, d.dialArgument.bestTarget.String(), &d.Upstream, data)
}

func (d *DoH) ForwardDNS(ctx context.Context, data []byte) (*dnsmessage.Msg, error) {
	generation := d.getOrCreateClient()
	if generation == nil {
		return nil, net.ErrClosed
	}
	defer func() { d.releaseClient(generation) }()

	msg, err := d.sendDNS(ctx, generation.Client, data)
	if err == nil || ctx.Err() != nil || !dnstransport.ShouldReplaceHTTPClient(err) {
		return msg, err
	}

	next := d.replaceClient(generation)
	previous := generation
	generation = next
	d.releaseClient(previous)
	if generation == nil {
		return nil, net.ErrClosed
	}
	return d.sendDNS(ctx, generation.Client, data)
}

func (d *DoH) ensureClientGenerationsLocked() {
	if d.clientGenerations == nil {
		d.clientGenerations = make(map[*dnstransport.HTTPClientGeneration]struct{})
	}
}

func (d *DoH) newClientGeneration() *dnstransport.HTTPClientGeneration {
	client := d.getClient()
	if d.clientFactory != nil {
		client = d.clientFactory()
	}
	return &dnstransport.HTTPClientGeneration{Client: client}
}

func (d *DoH) getOrCreateClient() *dnstransport.HTTPClientGeneration {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil
	}
	d.ensureClientGenerationsLocked()
	if d.client == nil {
		d.client = d.newClientGeneration()
		d.clientGenerations[d.client] = struct{}{}
	}
	d.client.Active++
	return d.client
}

func (d *DoH) releaseClient(generation *dnstransport.HTTPClientGeneration) {
	dnstransport.ReleaseHTTPClientGeneration(&d.mu, generation, func() {
		delete(d.clientGenerations, generation)
	})
}

func (d *DoH) replaceClient(previous *dnstransport.HTTPClientGeneration) *dnstransport.HTTPClientGeneration {
	var closePrevious bool
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil
	}
	d.ensureClientGenerationsLocked()
	if d.client != nil && d.client != previous {
		d.client.Active++
		current := d.client
		d.mu.Unlock()
		return current
	}
	next := d.newClientGeneration()
	next.Active = 1
	d.client = next
	d.clientGenerations[next] = struct{}{}
	if previous != nil {
		previous.Retired = true
		if previous.Active == 0 {
			closePrevious = true
		}
	}
	d.mu.Unlock()
	if closePrevious {
		previous.Close()
		d.mu.Lock()
		if previous.Retired && previous.Active == 0 {
			delete(d.clientGenerations, previous)
		}
		d.mu.Unlock()
	}
	return next
}

func (d *DoH) getClient() *http.Client {
	var roundTripper http.RoundTripper
	if d.http3 {
		roundTripper = dnstransport.NewHTTP3Transport(d.Hostname, func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
			return dnstransport.DialEarlyOwned(ctx, func(ctx context.Context) (netproxy.Conn, error) {
				return d.dialArgument.bestDialer.DialContext(
					ctx,
					common.MagicNetwork("udp", d.dialArgument.mark, d.dialArgument.mptcp),
					d.dialArgument.bestTarget.String(),
				)
			}, d.dialArgument.bestTarget, tlsCfg, cfg)
		})
	} else {
		roundTripper = dnstransport.NewHTTPTransport(d.Hostname, func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := d.dialArgument.bestDialer.DialContext(
				ctx,
				common.MagicNetwork("tcp", d.dialArgument.mark, d.dialArgument.mptcp),
				d.dialArgument.bestTarget.String(),
			)
			if err != nil {
				return nil, err
			}
			return &netproxy.FakeNetConn{Conn: conn}, nil
		})
	}

	return &http.Client{
		Transport: roundTripper,
		// Disable redirect https://github.com/daeuniverse/dae/pull/649#issuecomment-2379577896
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return fmt.Errorf("do not use a server that will redirect, upstream: %v", d.String())
		},
	}
}

func (d *DoH) Close() error {
	d.mu.Lock()
	d.closed = true
	generations := make([]*dnstransport.HTTPClientGeneration, 0, len(d.clientGenerations))
	for generation := range d.clientGenerations {
		generation.Retired = true
		generations = append(generations, generation)
	}
	d.client = nil
	d.clientGenerations = nil
	d.mu.Unlock()
	for _, generation := range generations {
		generation.Close()
	}
	return nil
}

type DoQ struct {
	dns.Upstream
	netproxy.Dialer
	dialArgument      dialArgument
	mu                sync.Mutex
	connection        quic.EarlyConnection
	closed            bool
	connectionFactory func(context.Context) (quic.EarlyConnection, error)
}

func (d *DoQ) ForwardDNS(ctx context.Context, data []byte) (*dnsmessage.Msg, error) {
	// Bound the whole exchange (dial/open included) by the caller context and
	// the exchange cap.
	exchangeCtx, cancelExchange := context.WithTimeout(ctx, doqExchangeTimeout)
	defer cancelExchange()

	connection, err := d.getOrCreateConnection(exchangeCtx)
	if err != nil {
		return nil, err
	}

	stream, err := connection.OpenStreamSync(exchangeCtx)
	if err != nil {
		if exchangeCtx.Err() != nil {
			return nil, err
		}
		// If failed to open stream, we should try to create a new connection.
		connection, err = d.replaceConnection(exchangeCtx, connection)
		if err != nil {
			return nil, err
		}
		stream, err = connection.OpenStreamSync(exchangeCtx)
		if err != nil {
			return nil, err
		}
	}

	// Apply the exchange deadline to the stream I/O and unblock any parked
	// Read/Write synchronously when the exchange context is done. Cancellation
	// never closes the shared QUIC connection: only this stream is abandoned.
	finSent := false
	writeCanceled := false
	defer func() {
		if !finSent && !writeCanceled {
			// Best effort cleanup; the stream may already be closed by the
			// QUIC implementation.
			_ = stream.Close()
		}
	}()
	if deadline, ok := exchangeCtx.Deadline(); ok {
		_ = stream.SetDeadline(deadline)
	}
	stopWatchdog := context.AfterFunc(exchangeCtx, func() {
		// A past deadline unblocks any Read/Write parked inside quic-go.
		_ = stream.SetDeadline(time.Unix(1, 0))
	})
	defer stopWatchdog()

	// According https://datatracker.ietf.org/doc/html/rfc9250#section-4.2.1
	// msg id should set to 0 when transport over QUIC.
	// thanks https://github.com/natesales/q/blob/1cb2639caf69bd0a9b46494a3c689130df8fb24a/transport/quic.go#L97
	binary.BigEndian.PutUint16(data[0:2], 0)

	// Write the complete query, then close the write side (FIN) before
	// reading: DoQ servers answer only after the query FIN (RFC 9250 §4.2).
	if err := dnstransport.WriteFramedDNSQuery(stream, data); err != nil {
		if exchangeCtx.Err() != nil {
			err = exchangeCtx.Err()
		}
		// The query never completed; abandon the whole stream: reset the
		// write side so the peer can discard the partial query and its
		// resources, and cancel the read side (STOP_SENDING, RFC 9250
		// §4.3.1) so the receive half is released instead of pinning the
		// stream on the reused connection until it is replaced.
		writeCanceled = true
		stream.CancelWrite(doqRequestCancelledCode)
		stream.CancelRead(doqRequestCancelledCode)
		return nil, err
	}
	if err := stream.Close(); err != nil {
		// FIN could not be delivered. quic-go reports an error here when the
		// send half was cancelled (e.g. a peer STOP_SENDING racing the
		// query), not only when the connection is gone, so the receive half
		// may still be open on a healthy connection: cancel it too instead of
		// leaving the stream half-open.
		if exchangeCtx.Err() != nil {
			err = exchangeCtx.Err()
		}
		stream.CancelRead(doqRequestCancelledCode)
		return nil, err
	}
	finSent = true

	msg, err := dnstransport.ReadFramedDNSResponse(stream)
	if err != nil {
		if exchangeCtx.Err() != nil {
			err = exchangeCtx.Err()
		}
		// Abandoning the query: ask the peer to stop transmitting (RFC 9250
		// §4.3.1). No-op once the peer already sent the full response.
		stream.CancelRead(doqRequestCancelledCode)
		return nil, err
	}
	// The framed response has been fully consumed, but quic-go completes a
	// stream only when both halves finish, and the receive half finishes only
	// when a read observes EOF or the stream is cancelled locally. DoQ
	// servers close their send side after answering (RFC 9250 §4.2), yet the
	// FIN can arrive after the payload; without cancellation the read half
	// stays open and holds the stream slot on the reused connection until the
	// connection is replaced. CancelRead releases the receive half and sends
	// STOP_SENDING (RFC 9250 §4.3.1); the slot itself is reclaimed once the
	// peer's FIN or RESET arrives and the send half has completed, which a
	// well-behaved DoQ server provides immediately after answering.
	stream.CancelRead(doqRequestCancelledCode)
	return msg, nil
}

func (d *DoQ) getOrCreateConnection(ctx context.Context) (quic.EarlyConnection, error) {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil, net.ErrClosed
	}
	if d.connection != nil {
		c := d.connection
		d.mu.Unlock()
		return c, nil
	}
	d.mu.Unlock()

	qc, err := d.createConnection(ctx)
	if err != nil {
		return nil, err
	}

	return d.installConnection(qc)
}

func (d *DoQ) replaceConnection(ctx context.Context, previous quic.EarlyConnection) (quic.EarlyConnection, error) {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil, net.ErrClosed
	}
	if d.connection != nil && d.connection != previous {
		c := d.connection
		d.mu.Unlock()
		return c, nil
	}
	var staleConn quic.EarlyConnection
	if d.connection != nil {
		staleConn = d.connection
		d.connection = nil
	}
	d.mu.Unlock()
	// Close the old connection outside d.mu: CloseWithError sends a
	// CONNECTION_CLOSE frame and must not stall concurrent ForwardDNS.
	if staleConn != nil {
		_ = staleConn.CloseWithError(0, "")
	}

	qc, err := d.createConnection(ctx)
	if err != nil {
		return nil, err
	}

	return d.installConnection(qc)
}

func (d *DoQ) installConnection(qc quic.EarlyConnection) (quic.EarlyConnection, error) {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		_ = qc.CloseWithError(0, "")
		return nil, net.ErrClosed
	}
	if d.connection != nil {
		connection := d.connection
		d.mu.Unlock()
		_ = qc.CloseWithError(0, "")
		return connection, nil
	}
	d.connection = qc
	d.mu.Unlock()
	return qc, nil
}

func (d *DoQ) createConnection(ctx context.Context) (quic.EarlyConnection, error) {
	if d.connectionFactory != nil {
		return d.connectionFactory(ctx)
	}
	tlsCfg := &tls.Config{
		NextProtos:         []string{"doq"},
		InsecureSkipVerify: false,
		ServerName:         d.Hostname,
	}
	return dnstransport.DialEarlyOwned(ctx, func(ctx context.Context) (netproxy.Conn, error) {
		return d.dialArgument.bestDialer.DialContext(
			ctx,
			common.MagicNetwork("udp", d.dialArgument.mark, d.dialArgument.mptcp),
			d.dialArgument.bestTarget.String(),
		)
	}, d.dialArgument.bestTarget, tlsCfg, nil)
}

func (d *DoQ) Close() error {
	d.mu.Lock()
	d.closed = true
	conn := d.connection
	d.connection = nil
	d.mu.Unlock()
	if conn != nil {
		// CloseWithError may send a CONNECTION_CLOSE frame; keep d.mu free
		// so concurrent ForwardDNS callers are not stalled behind it.
		return conn.CloseWithError(0, "")
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
	// closed marks the pool as torn down. get()'s slow path dials outside
	// the lock; without this flag, close() can empty the pool mid-dial and
	// the fresh connection would then be appended to a dead pool whose
	// owner has already left, leaking the connection and its readLoop
	// goroutine (which blocks on a deadline-less ReadFull).
	closed bool
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
	if p.closed {
		p.mu.Unlock()
		return nil, errConnPoolClosed
	}
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
	if p.closed {
		// The pool was torn down while we dialed. Nobody will ever close a
		// connection appended now, so discard the fresh one here.
		p.mu.Unlock()
		conn.Close()
		return nil, errConnPoolClosed
	}
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
	p.closed = true
	for _, conn := range p.conns {
		conn.Close() // pipelinedConn.Close() has no return value
	}
	p.conns = nil
	return nil
}

// lazyConnPool provides a thread-safe lazy-initialization wrapper around *connPool.
// It uses sync.Once for one-time initialization and atomic.Value for lock-free reads.
type lazyConnPool struct {
	init   sync.Once
	pool   atomic.Value // stores *connPool
	closed atomic.Bool
}

func (l *lazyConnPool) getOrInit(init func() *connPool) *connPool {
	// If already closed, return nil (closed forwarders are discarded in practice)
	if l.closed.Load() {
		return nil
	}
	l.init.Do(func() {
		p := init()
		l.pool.Store(p)
	})
	if l.closed.Load() {
		// closePool raced the lazy initialization: it observed pool==nil
		// before the Store above and skipped p.close(), so this freshly
		// created pool would escape closure along with every connection
		// readLoop inside it. Close it here (idempotent) and report closed.
		if v := l.pool.Load(); v != nil {
			_ = v.(*connPool).close()
		}
		return nil
	}
	if v := l.pool.Load(); v != nil {
		return v.(*connPool)
	}
	return nil
}

func (l *lazyConnPool) closePool() error {
	l.closed.Swap(true)
	if v := l.pool.Load(); v != nil {
		p := v.(*connPool)
		// Don't Store(nil) - atomic.Value can't hold nil
		return p.close()
	}
	return nil
}

type DoTLS struct {
	dns.Upstream
	netproxy.Dialer
	dialArgument dialArgument

	lazyConnPool // embeds getOrInit / closePool
}

func (d *DoTLS) getPool() *connPool {
	return d.getOrInit(func() *connPool {
		return newConnPool(4, func(ctx context.Context) (netproxy.Conn, error) {
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
				ServerName:         d.Hostname,
			})
			if deadline, ok := ctx.Deadline(); ok {
				_ = tlsConn.SetDeadline(deadline)
			} else {
				_ = tlsConn.SetDeadline(time.Now().Add(consts.DefaultDialTimeout))
			}
			if err = tlsConn.HandshakeContext(ctx); err != nil {
				_ = conn.Close()
				return nil, err
			}
			_ = tlsConn.SetDeadline(time.Time{})
			return tlsConn, nil
		})
	})
}

func (d *DoTLS) getPConn(ctx context.Context) (*pipelinedConn, error) {
	pool := d.getPool()
	if pool == nil {
		return nil, errors.New("connection pool is not available")
	}
	return pool.get(ctx)
}

func (d *DoTLS) ForwardDNS(ctx context.Context, data []byte) (*dnsmessage.Msg, error) {
	var lastErr error
	// With connection pool, we can retry with different connections
	for range 2 {
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
		lastErr = err

		// Connection might be broken, but pool will handle it
		// Next retry will get a different connection from pool
	}
	if lastErr != nil {
		return nil, fmt.Errorf("failed to forward DNS after retry: %w", lastErr)
	}
	return nil, fmt.Errorf("failed to forward DNS after retry")
}

func (d *DoTLS) Close() error {
	return d.closePool()
}

type DoTCP struct {
	dns.Upstream
	netproxy.Dialer
	dialArgument dialArgument

	lazyConnPool // embeds getOrInit / closePool
}

func (d *DoTCP) getPool() *connPool {
	return d.getOrInit(func() *connPool {
		return newConnPool(4, func(ctx context.Context) (netproxy.Conn, error) {
			return d.dialArgument.bestDialer.DialContext(
				ctx,
				common.MagicNetwork("tcp", d.dialArgument.mark, d.dialArgument.mptcp),
				d.dialArgument.bestTarget.String(),
			)
		})
	})
}

func (d *DoTCP) getPConn(ctx context.Context) (*pipelinedConn, error) {
	pool := d.getPool()
	if pool == nil {
		return nil, errors.New("connection pool is not available")
	}
	return pool.get(ctx)
}

func (d *DoTCP) ForwardDNS(ctx context.Context, data []byte) (*dnsmessage.Msg, error) {
	var lastErr error
	// With connection pool, we can retry with different connections
	for range 2 {
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
		lastErr = err

		// Connection might be broken, but pool will handle it
		// Next retry will get a different connection from pool
	}
	if lastErr != nil {
		return nil, fmt.Errorf("failed to forward DNS after retry: %w", lastErr)
	}
	return nil, fmt.Errorf("failed to forward DNS after retry")
}

func (d *DoTCP) Close() error {
	return d.closePool()
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
	liveMu      sync.Mutex
	liveConns   map[netproxy.Conn]struct{}
	maxIdleTime time.Duration // Connections older than this are discarded
	activeCount atomic.Int32
	maxActive   int32
	done        chan struct{}
}

const (
	// dnsUdpPoolMaxIdle keeps a modest number of warm sockets per upstream so bursty
	// DNS traffic can reuse hot sockets without retaining the full active set forever.
	dnsUdpPoolMaxIdle = 16
	// dnsUdpPoolMaxActive bounds the true concurrent capacity of a UDP DNS forwarder.
	// Each socket serves one in-flight request at a time in this implementation, so
	// requests beyond this budget should fail fast instead of queueing in userspace.
	dnsUdpPoolMaxActive = 64
	// dnsUdpMaxResponseSize sizes the DoUDP reply read buffer. DNS replies
	// over UDP can legally reach 65507 bytes when the client advertises
	// EDNS0; an MTU-sized buffer lets the kernel clip the datagram, and the
	// unpack below then fails, turning large replies into hard errors rather
	// than a TC-triggered TCP retry. The shared power-of-two buffer pool
	// buckets this at 64KiB and caps Put() retention at the same size.
	dnsUdpMaxResponseSize = 65536
	// Proxy-backed UDP DNS sockets go stale more easily because they sit behind an
	// upstream relay session rather than a raw UDP socket.
	dnsUdpProxyPoolMaxIdleTime  = 10 * time.Second
	dnsUdpDirectPoolMaxIdleTime = 30 * time.Second
)

// dnsUDPResponseSourceMismatchLogInterval rate-limits the source-mismatch
// warning: an upstream behind a transport that synthesizes the sender address
// would otherwise log on every reply.
const dnsUDPResponseSourceMismatchLogInterval = time.Minute

// Observe-only upstream source validation state. A mismatch is counted and
// rate-limit logged, never dropped, until every transport dae can dial is known
// to report a truthful datagram source (transports that synthesize the sender
// address cannot be distinguished from a forged reply yet).
var (
	dnsUDPResponseSourceMismatchCount  atomic.Uint64
	lastDnsUDPResponseSourceMismatchAt atomic.Int64
)

// udpResponseSourceMismatch reports whether a datagram's reported source
// differs from the endpoint dae dialed. A transport that does not report a
// source address at all yields an invalid address and is treated as unknown,
// not as a mismatch.
func udpResponseSourceMismatch(from, target netip.AddrPort) bool {
	if !from.IsValid() || !target.IsValid() {
		return false
	}
	// An IPv4-mapped IPv6 source (::ffff:a.b.c.d, as reported by a dual-stack
	// socket) denotes the same endpoint as its plain IPv4 form. Comparing the
	// raw values would flag every reply from such an upstream as a mismatch.
	// netip.AddrPort has no Unmap, so unmap both addresses individually.
	return from.Addr().Unmap() != target.Addr().Unmap() || from.Port() != target.Port()
}

func noteDnsUDPResponseSourceMismatch(log *logrus.Logger, target, from netip.AddrPort) {
	dnsUDPResponseSourceMismatchCount.Add(1)
	if log == nil {
		return
	}
	nowNano := time.Now().UnixNano()
	for {
		last := lastDnsUDPResponseSourceMismatchAt.Load()
		if nowNano-last < int64(dnsUDPResponseSourceMismatchLogInterval) {
			return
		}
		if lastDnsUDPResponseSourceMismatchAt.CompareAndSwap(last, nowNano) {
			break
		}
	}
	log.Warnf("UDP DNS reply reported source %v but %v was dialed; the reply is still processed "+
		"(observe-only source validation, mismatches=%d)", from, target, dnsUDPResponseSourceMismatchCount.Load())
}

func newUdpConnPool(maxIdle, maxActive int, dialer func(context.Context) (netproxy.Conn, error)) *udpConnPool {
	if maxIdle <= 0 {
		maxIdle = 1
	}
	if maxActive <= 0 {
		maxActive = maxIdle
	}
	if maxIdle > maxActive {
		maxIdle = maxActive
	}
	p := &udpConnPool{
		idleConns:   make(chan *udpConnWithTimestamp, maxIdle),
		dialer:      dialer,
		liveConns:   make(map[netproxy.Conn]struct{}, maxActive),
		maxIdleTime: dnsUdpDirectPoolMaxIdleTime,
		maxActive:   int32(maxActive),
		done:        make(chan struct{}),
	}
	return p
}

func (p *udpConnPool) registerLiveConn(conn netproxy.Conn) {
	if conn == nil {
		return
	}
	p.liveMu.Lock()
	p.liveConns[conn] = struct{}{}
	p.liveMu.Unlock()
}

func (p *udpConnPool) unregisterLiveConn(conn netproxy.Conn) bool {
	if conn == nil {
		return false
	}
	p.liveMu.Lock()
	_, ok := p.liveConns[conn]
	if ok {
		delete(p.liveConns, conn)
	}
	p.liveMu.Unlock()
	return ok
}

func (p *udpConnPool) snapshotLiveConns() []netproxy.Conn {
	p.liveMu.Lock()
	defer p.liveMu.Unlock()

	conns := make([]netproxy.Conn, 0, len(p.liveConns))
	for conn := range p.liveConns {
		conns = append(conns, conn)
	}
	return conns
}

func (p *udpConnPool) tryAcquireActiveSlot() bool {
	for {
		current := p.activeCount.Load()
		if current >= p.maxActive {
			return false
		}
		if p.activeCount.CompareAndSwap(current, current+1) {
			return true
		}
	}
}

func (p *udpConnPool) releaseActiveSlot() {
	for {
		current := p.activeCount.Load()
		if current <= 0 {
			return
		}
		if p.activeCount.CompareAndSwap(current, current-1) {
			return
		}
	}
}

func (p *udpConnPool) discard(conn netproxy.Conn) {
	if conn == nil {
		return
	}
	_ = conn.Close()
	if p.unregisterLiveConn(conn) {
		p.releaseActiveSlot()
	}
}

func (p *udpConnPool) takeIdleConn() (netproxy.Conn, error, bool) {
	select {
	case connWithTime := <-p.idleConns:
		if connWithTime == nil {
			return nil, io.ErrClosedPipe, true
		}

		if p.closed.Load() {
			p.discard(connWithTime.conn)
			return nil, io.ErrClosedPipe, true
		}

		if time.Since(connWithTime.lastUsed) > p.maxIdleTime {
			p.discard(connWithTime.conn)
			return nil, nil, false
		}

		return connWithTime.conn, nil, true
	default:
		return nil, nil, false
	}
}

func (p *udpConnPool) get(ctx context.Context) (netproxy.Conn, error) {
	if p.closed.Load() {
		return nil, io.ErrClosedPipe
	}

	if conn, err, ok := p.takeIdleConn(); ok {
		if err == nil && conn != nil {
			// Deadlines belong to the current borrower, not the idle pool entry.
			// Clear any leftover request deadline right before handing the socket
			// to a new DNS exchange.
			_ = conn.SetDeadline(time.Time{})
		}
		return conn, err
	}

	if p.closed.Load() {
		return nil, io.ErrClosedPipe
	}

	if p.tryAcquireActiveSlot() {
		conn, err := p.dialer(ctx)
		if err != nil {
			p.releaseActiveSlot()
			return nil, err
		}
		p.registerLiveConn(conn)
		if p.closed.Load() {
			p.discard(conn)
			return nil, io.ErrClosedPipe
		}
		return conn, nil
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, ErrDNSUDPConnPoolExhausted
}

func (p *udpConnPool) put(conn netproxy.Conn) {
	if conn == nil {
		return
	}

	if p.closed.Load() {
		p.discard(conn)
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
		p.discard(conn)
		return
	}

	select {
	case p.idleConns <- connWithTime:

	default:
		// Pool full, close connection
		p.discard(conn)
	}
}

func (p *udpConnPool) close() error {
	if p.closed.Swap(true) {
		return nil
	}
	close(p.done)

	for _, conn := range p.snapshotLiveConns() {
		p.discard(conn)
	}

	p.opsMu.Lock()
	defer p.opsMu.Unlock()

	for {
		select {
		case connWithTime := <-p.idleConns:
			if connWithTime != nil && connWithTime.conn != nil {
				p.discard(connWithTime.conn)
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

	profile UdpLifecycleProfile
	pool    *udpConnPool
	mu      sync.RWMutex
	log     *logrus.Logger
}

func (d *DoUDP) getPool() *udpConnPool {
	if d.profile.Kind == 0 {
		d.mu.Lock()
		if d.profile.Kind == 0 {
			d.profile = newDnsLifecycleProfile(d.dialArgument.bestDialer)
		}
		d.mu.Unlock()
	}

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
	// Keep a bounded but realistic UDP live set. The controller may admit far more
	// concurrent requests globally, but a single UDP upstream can only service one
	// request per socket here, so saturation must fail fast locally instead of
	// accumulating a large waiter queue in userspace.
	d.pool = newUdpConnPool(dnsUdpPoolMaxIdle, dnsUdpPoolMaxActive, func(ctx context.Context) (netproxy.Conn, error) {
		return d.dialArgument.bestDialer.DialContext(
			ctx,
			common.MagicNetwork("udp", d.dialArgument.mark, d.dialArgument.mptcp),
			d.dialArgument.bestTarget.String(),
		)
	})
	if d.profile.PooledConnIdleTTL > 0 {
		d.pool.maxIdleTime = d.profile.PooledConnIdleTTL
	}

	return d.pool
}

func (d *DoUDP) ForwardDNS(ctx context.Context, data []byte) (*dnsmessage.Msg, error) {
	udpPool := d.getPool()
	lifecycle, hasLifecycle := newDnsUdpLifecycleContext(&d.dialArgument, d.profile)
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
	if _, err = netutils.WriteUDPConn(conn, d.dialArgument.bestTarget.String(), data); err != nil {
		udpPool.discard(conn)
		badConn = true
		return nil, err
	}

	// Wait for response. The buffer must cover the full UDP DNS payload
	// range (see dnsUdpMaxResponseSize) so EDNS0-sized replies are never
	// silently truncated by the receive buffer.
	respBuf := pool.GetFullCap(dnsUdpMaxResponseSize)
	defer pool.Put(respBuf)
	const maxStaleResponses = 8
	staleResponses := 0

	for {
		n, from, err := netutils.ReadUDPConnFrom(conn, respBuf)
		if err != nil {
			// Direct UDP sockets can usually survive a single DNS timeout, but a
			// proxy-backed UDP timeout often means the relay-side session has gone
			// stale. Reusing that socket causes timeout loops and stale-response churn.
			if hasLifecycle && lifecycle.shouldDiscardPooledConnOnTimeout(err) {
				udpPool.discard(conn)
				badConn = true
				return nil, err
			}
			if netErr, ok := errors.AsType[net.Error](err); ok && netErr.Timeout() {
				if d.profile.DiscardPooledConnOnTimeout {
					udpPool.discard(conn)
					badConn = true
				}
				return nil, err
			}
			udpPool.discard(conn)
			badConn = true
			return nil, err
		}

		// Observe-only upstream source validation: a datagram that claims to
		// come from a different endpoint than the one dae dialed can only be a
		// spoofed or cross-talked reply. The fix keeps observing for now -
		// transports that synthesize the sender address (some proxy protocols)
		// cannot be told apart from a forged one yet, and dropping on a
		// false positive would break resolution - so the datagram is still
		// processed, but the mismatch is counted and rate-limit logged.
		if udpResponseSourceMismatch(from, d.dialArgument.bestTarget) {
			noteDnsUDPResponseSourceMismatch(d.log, d.dialArgument.bestTarget, from)
		}

		if n < 2 {
			staleResponses++
			if staleResponses > maxStaleResponses {
				udpPool.discard(conn)
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
				udpPool.discard(conn)
				badConn = true
				return nil, fmt.Errorf("too many stale UDP DNS responses")
			}
			continue
		}

		var msg dnsmessage.Msg
		if err = msg.Unpack(respBuf[:n]); err != nil {
			udpPool.discard(conn)
			badConn = true
			return nil, err
		}
		if msg.Truncated {
			return &msg, ErrDNSTruncated
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
	errMu     sync.Mutex
	err       error
	closed    chan struct{}
	closeOnce sync.Once
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

func (pc *pipelinedConn) closeWithErr(err error) {
	pc.closeOnce.Do(func() {
		if err == nil {
			err = io.ErrUnexpectedEOF
		}
		pc.errMu.Lock()
		if pc.err == nil {
			pc.err = err
		}
		pc.errMu.Unlock()

		_ = pc.conn.Close()
		close(pc.closed)

		for i := range pc.pending {
			if slot := pc.pending[i].Swap(nil); slot != nil {
				slot.set(nil)
			}
		}
	})
}

func (pc *pipelinedConn) readLoop() {
	defer pc.closeWithErr(io.ErrUnexpectedEOF)

	const dnsPipelineMaxResponseSize = 65535

	for {
		var header [2]byte
		if _, err := io.ReadFull(pc.conn, header[:]); err != nil {
			pc.closeWithErr(err)
			return
		}
		l := binary.BigEndian.Uint16(header[:])

		if l == 0 || int(l) > dnsPipelineMaxResponseSize {
			pc.closeWithErr(fmt.Errorf("invalid DNS payload length: %d", l))
			return
		}

		buf := pool.Get(int(l))
		if _, err := io.ReadFull(pc.conn, buf); err != nil {
			pool.Put(buf)
			pc.closeWithErr(err)
			return
		}

		respMsg := new(dnsmessage.Msg)
		if err := respMsg.Unpack(buf); err != nil {
			pool.Put(buf)
			pc.closeWithErr(fmt.Errorf("bad DNS packet: %w", err))
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
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Allocate ID using bitmap allocator (O(1) time complexity)
	id, err := pc.idAlloc.Allocate()
	if err != nil {
		return nil, fmt.Errorf("failed to allocate ID: %w", err)
	}

	// Get response slot from pool. The slot must be recycled exactly once per
	// checkout: by the outer defer below when no setter can reach it, or by
	// the setter (readLoop/closeWithErr) after the cleanup defer transfers
	// ownership via abandon.
	slot := newResponseSlot()
	setterRecycles := false
	defer func() {
		if !setterRecycles {
			putResponseSlot(slot)
		}
	}()

	// Store the pending request
	if !pc.pending[id].CompareAndSwap(nil, slot) {
		pc.idAlloc.Release(id)
		return nil, fmt.Errorf("pending slot is unexpectedly occupied")
	}
	pc.pendingCount.Add(1)

	var responseDelivered bool
	defer func() {
		switch {
		case pc.pending[id].CompareAndSwap(slot, nil):
			// Nobody claimed the slot; the outer defer recycles it.
		case responseDelivered:
			// The setter already finished; nothing will touch the slot again
			// and the outer defer recycles it.
		default:
			// readLoop or closeWithErr owns the slot and will (or just did)
			// call set; transfer recycling to that setter so a late delivery
			// cannot write into a slot that already re-entered the pool.
			slot.abandon()
			setterRecycles = true
		}
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

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	deadline, hasDeadline := ctx.Deadline()
	if !hasDeadline {
		deadline = time.Now().Add(consts.DefaultDialTimeout)
	}
	pc.writeMu.Lock()
	_ = pc.conn.SetWriteDeadline(deadline)
	_, err = pc.conn.Write(buf)
	_ = pc.conn.SetWriteDeadline(time.Time{})
	pc.writeMu.Unlock()

	if err != nil {
		return nil, err
	}

	msg, err := slot.get(ctx)
	responseDelivered = err == nil
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
	pc.closeWithErr(io.ErrClosedPipe)
}
