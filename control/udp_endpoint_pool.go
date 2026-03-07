/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	daerrors "github.com/daeuniverse/dae/common/errors"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
	"github.com/sirupsen/logrus"
)

var UdpRoutingResultCacheTtl = 300 * time.Millisecond

// udpEndpointCreateShardCount is the number of sharded mutexes that guard
// concurrent endpoint creation. 16 shards give near-zero contention for
// typical concurrent-create rates while using 4× less mutex memory than 64.
const udpEndpointCreateShardCount = 16
const udpEndpointJanitorInterval = 250 * time.Millisecond

type UdpHandler func(ue *UdpEndpoint, data []byte, from netip.AddrPort) error

type UdpEndpoint struct {
	conn          netproxy.PacketConn
	expiresAtNano atomic.Int64
	handler       UdpHandler
	NatTimeout    time.Duration
	writeMu       sync.Mutex

	Dialer   *dialer.Dialer
	Outbound *outbound.DialerGroup

	// Non-empty indicates this UDP Endpoint is related with a sniffed domain.
	SniffedDomain string
	DialTarget    string

	routingMu         sync.RWMutex
	routingCacheDst   netip.AddrPort
	routingCacheProto uint8
	routingCacheAt    time.Time
	routingCache      bpfRoutingResult
	hasRoutingCache   bool

	lAddr netip.AddrPort
	// respConn is a cached Anyfrom socket used to send responses back to the client.
	// This avoids repeated pool lookups and bind syscalls in the hot path.
	respConn *Anyfrom

	log *logrus.Logger

	dead atomic.Bool

	// poolRef and poolKey allow the read loop to self-remove from the pool the
	// instant it detects death. This minimises the window during which a stale
	// dead entry lurks in the pool and forces callers through the slower
	// dead-check recovery branch in GetOrCreate.
	poolRef *UdpEndpointPool
	poolKey UdpEndpointKey
}

func (ue *UdpEndpoint) logEndpointExit(err error, msg string) {
	if ue.log == nil {
		return
	}
	entry := ue.log.WithError(err).WithField("lAddr", ue.lAddr.String())
	if daerrors.IsUDPEndpointNormalClose(err) {
		entry.Debugln("UdpEndpoint " + msg + " closed normally")
	} else {
		entry.Warnln("UdpEndpoint " + msg + " exited with error")
	}
}

func (ue *UdpEndpoint) start() {
	buf := pool.GetFullCap(consts.EthernetMtu)
	defer pool.Put(buf)
	for {
		n, from, err := ue.conn.ReadFrom(buf[:])
		if err != nil {
			ue.dead.Store(true)
			ue.expiresAtNano.Store(1)
			ue.selfRemoveFromPool()
			ue.logEndpointExit(err, "read loop")
			break
		}
		ue.RefreshTtl()
		if err = ue.handler(ue, buf[:n], from); err != nil {
			ue.dead.Store(true)
			ue.expiresAtNano.Store(1)
			ue.selfRemoveFromPool()
			ue.logEndpointExit(err, "handler")
			break
		}
	}
}

// selfRemoveFromPool performs a best-effort CAS delete of this endpoint from
// its owning pool. It is called by the read loop on exit so that the dead entry
// is evicted immediately — before any writer goroutine has a chance to observe
// it and be forced through the slower dead-check recovery path.
func (ue *UdpEndpoint) selfRemoveFromPool() {
	if ue.poolRef == nil {
		return
	}
	ue.poolRef.pool.CompareAndDelete(ue.poolKey, ue)
}

func (ue *UdpEndpoint) WriteTo(b []byte, addr string) (int, error) {
	// Fast pre-lock dead check: avoid acquiring mutex for an already-dead endpoint.
	if ue.dead.Load() {
		return 0, net.ErrClosed
	}
	// Refresh TTL on write to keep endpoint alive for active connections
	// This is especially important for QUIC connections where the server
	// might respond slowly during handshake
	ue.RefreshTtl()
	ue.writeMu.Lock()
	defer ue.writeMu.Unlock()

	// Post-lock dead check: endpoint may have died while this goroutine was
	// waiting for the mutex. Without this, stale goroutines write to a dead
	// conn whose physical socket is still open — data disappears silently.
	if ue.dead.Load() {
		return 0, net.ErrClosed
	}

	n, err := ue.conn.WriteTo(b, addr)
	if err != nil {
		// Mark dead immediately so goroutines queued behind us fail fast
		// instead of each discovering the error in turn.
		ue.dead.Store(true)
		return n, err
	}
	if n != len(b) {
		ue.dead.Store(true)
		return n, fmt.Errorf("%w: udp endpoint wrote %d/%d bytes to %s", io.ErrShortWrite, n, len(b), addr)
	}
	return n, nil
}

func (ue *UdpEndpoint) Close() error {
	ue.expiresAtNano.Store(0)

	ue.routingMu.Lock()
	ue.hasRoutingCache = false
	ue.routingMu.Unlock()

	return ue.conn.Close()
}

func (ue *UdpEndpoint) RefreshTtl() {
	if ue.NatTimeout <= 0 {
		return
	}
	ue.expiresAtNano.Store(time.Now().Add(ue.NatTimeout).UnixNano())
}

func (ue *UdpEndpoint) IsExpired(nowNano int64) bool {
	expiresAt := ue.expiresAtNano.Load()
	return expiresAt > 0 && nowNano >= expiresAt
}

// IsDead returns true if the endpoint's read loop has exited and should not be reused.
func (ue *UdpEndpoint) IsDead() bool {
	return ue.dead.Load()
}

func (ue *UdpEndpoint) GetCachedRoutingResult(dst netip.AddrPort, l4proto uint8) (*bpfRoutingResult, bool) {
	ttl := UdpRoutingResultCacheTtl
	if ttl <= 0 {
		return nil, false
	}

	ue.routingMu.RLock()
	defer ue.routingMu.RUnlock()

	if !ue.hasRoutingCache {
		return nil, false
	}
	if ue.routingCacheProto != l4proto || ue.routingCacheDst != dst {
		return nil, false
	}
	if time.Since(ue.routingCacheAt) > ttl {
		return nil, false
	}

	result := ue.routingCache
	return &result, true
}

func (ue *UdpEndpoint) UpdateCachedRoutingResult(dst netip.AddrPort, l4proto uint8, result *bpfRoutingResult) {
	if result == nil {
		return
	}
	if UdpRoutingResultCacheTtl <= 0 {
		return
	}

	ue.routingMu.Lock()
	ue.routingCacheDst = dst
	ue.routingCacheProto = l4proto
	ue.routingCacheAt = time.Now()
	ue.routingCache = *result
	ue.hasRoutingCache = true
	ue.routingMu.Unlock()
}

// UdpEndpointKey is the pool key. Dst=0 for Full-Cone NAT, non-zero for QUIC.
type UdpEndpointKey struct {
	Src netip.AddrPort
	Dst netip.AddrPort
}

// UdpEndpointPool is a UDP connection pool.
type UdpEndpointPool struct {
	pool          sync.Map
	createMuShard [udpEndpointCreateShardCount]sync.Mutex
	janitorOnce   sync.Once
}

type UdpEndpointOptions struct {
	Handler    UdpHandler
	NatTimeout time.Duration
	// GetTarget is useful only if the underlay does not support Full-cone.
	GetDialOption func(ctx context.Context) (option *DialOption, err error)
	// Log is the logger to use for endpoint lifecycle events.
	// If nil, logs are discarded.
	Log *logrus.Logger
}

var DefaultUdpEndpointPool = NewUdpEndpointPool()

func NewUdpEndpointPool() *UdpEndpointPool {
	p := &UdpEndpointPool{}
	p.startJanitor()
	return p
}

func (p *UdpEndpointPool) Remove(key UdpEndpointKey, udpEndpoint *UdpEndpoint) (err error) {
	// Use CompareAndDelete for atomic CAS semantics (Go 1.20+ best practice)
	if !p.pool.CompareAndDelete(key, udpEndpoint) {
		udpEndpoint.Close()
		return fmt.Errorf("target udp endpoint is not in the pool")
	}
	udpEndpoint.Close()
	return nil
}

func (p *UdpEndpointPool) Get(key UdpEndpointKey) (udpEndpoint *UdpEndpoint, ok bool) {
	_ue, ok := p.pool.Load(key)
	if !ok {
		return nil, ok
	}
	ue := _ue.(*UdpEndpoint)
	if ue.IsDead() {
		return nil, false
	}
	return ue, ok
}

// createEndpointLocked dials and registers a new UdpEndpoint under the caller's shard lock.
// The caller MUST hold the shard mutex for key before calling this function.
func (p *UdpEndpointPool) createEndpointLocked(key UdpEndpointKey, createOption *UdpEndpointOptions) (*UdpEndpoint, error) {
	if createOption == nil {
		createOption = &UdpEndpointOptions{}
	}
	if createOption.NatTimeout == 0 {
		createOption.NatTimeout = DefaultNatTimeout
	}
	if createOption.Handler == nil {
		return nil, fmt.Errorf("createOption.Handler cannot be nil")
	}

	// Use context.Background() as base for UDP endpoint creation.
	// The timeout context ensures the dial operation doesn't hang indefinitely.
	ctx, cancel := context.WithTimeout(context.Background(), consts.DefaultDialTimeout)
	defer cancel()

	dialOption, err := createOption.GetDialOption(ctx)
	if err != nil {
		return nil, err
	}
	udpConn, err := dialOption.Dialer.DialContext(ctx, dialOption.Network, dialOption.Target)
	if err != nil {
		return nil, err
	}
	if _, ok := udpConn.(netproxy.PacketConn); !ok {
		return nil, fmt.Errorf("protocol does not support udp")
	}
	ue := &UdpEndpoint{
		conn:          udpConn.(netproxy.PacketConn),
		handler:       createOption.Handler,
		NatTimeout:    createOption.NatTimeout,
		Dialer:        dialOption.Dialer,
		Outbound:      dialOption.Outbound,
		SniffedDomain: dialOption.SniffedDomain,
		DialTarget:    dialOption.Target,
		lAddr:         key.Src,
		log:           createOption.Log,
		poolRef:       p,
		poolKey:       key,
	}

	// Pre-cache the Anyfrom socket for responses. Caching is only safe for
	// fixed-destination sessions (Symmetric NAT) where the response bind address
	// remains constant. Full-Cone sessions must lookup on every packet as the
	// server source can change.
	if key.Dst.Port() != 0 {
		if bindAddr, writeAddr := normalizeSendPktAddrFamily(key.Dst, key.Src); !isUnsupportedTransparentUDPPair(bindAddr, writeAddr) {
			if af, _, err := DefaultAnyfromPool.GetOrCreate(bindAddr, AnyfromTimeout); err == nil {
				ue.respConn = af
			}
		}
	}

	ue.RefreshTtl()
	p.pool.Store(key, ue)
	// Receive UDP messages.
	go ue.start()
	return ue, nil
}

func (p *UdpEndpointPool) GetOrCreate(key UdpEndpointKey, createOption *UdpEndpointOptions) (udpEndpoint *UdpEndpoint, isNew bool, err error) {
	_ue, ok := p.pool.Load(key)
	if !ok {
		mu := p.createMuFor(key)
		mu.Lock()
		defer mu.Unlock()

		_ue, ok = p.pool.Load(key)
		if ok {
			ue := _ue.(*UdpEndpoint)
			if ue.IsDead() {
				// Use CompareAndDelete for atomic CAS (best practice)
				p.pool.CompareAndDelete(key, ue)
			} else {
				ue.RefreshTtl()
				return ue, false, nil
			}
		}
		// Create a new endpoint under the shard lock.
		newUe, createErr := p.createEndpointLocked(key, createOption)
		if createErr != nil {
			return nil, true, createErr
		}
		return newUe, true, nil
	}
	ue := _ue.(*UdpEndpoint)

	if ue.IsDead() {
		// Fast path returned a dead endpoint. Acquire the shard lock and handle
		// it non-recursively — equivalent to what a recursive GetOrCreate would do,
		// but without stack overhead or unbounded recursion risk.
		mu := p.createMuFor(key)
		mu.Lock()
		defer mu.Unlock()
		// CAS-delete the dead entry (safe: no-op if another goroutine already replaced it).
		p.pool.CompareAndDelete(key, ue)
		// Double-check: another goroutine may have already placed a live replacement.
		if v, loaded := p.pool.Load(key); loaded {
			fresh := v.(*UdpEndpoint)
			if !fresh.IsDead() {
				fresh.RefreshTtl()
				return fresh, false, nil
			}
			// Still dead — remove it too and fall through to create.
			p.pool.CompareAndDelete(key, fresh)
		}
		// Create a fresh endpoint under the lock.
		newUe, createErr := p.createEndpointLocked(key, createOption)
		if createErr != nil {
			return nil, true, createErr
		}
		return newUe, true, nil
	}
	ue.RefreshTtl()
	return _ue.(*UdpEndpoint), isNew, nil
}

func (p *UdpEndpointPool) createMuFor(key UdpEndpointKey) *sync.Mutex {
	idx := int(hashAddrPort(key.Src) & uint64(udpEndpointCreateShardCount-1))
	return &p.createMuShard[idx]
}

func (p *UdpEndpointPool) startJanitor() {
	p.janitorOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(udpEndpointJanitorInterval)
			defer ticker.Stop()
			for now := range ticker.C {
				nowNano := now.UnixNano()
				p.pool.Range(func(key, value any) bool {
					ue := value.(*UdpEndpoint)
					if !ue.IsExpired(nowNano) {
						return true
					}
					// Use CompareAndDelete for atomic CAS - only delete if still the same expired endpoint
					if p.pool.CompareAndDelete(key, ue) {
						_ = ue.Close()
					}
					return true
				})
			}
		}()
	})
}
