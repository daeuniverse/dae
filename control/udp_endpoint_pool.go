/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
	"github.com/sirupsen/logrus"
)

var UdpRoutingResultCacheTtl = 300 * time.Millisecond

const udpEndpointCreateShardCount = 64
const udpEndpointJanitorInterval = 250 * time.Millisecond

type UdpHandler func(data []byte, from netip.AddrPort) error

type UdpEndpoint struct {
	conn          netproxy.PacketConn
	expiresAtNano atomic.Int64
	handler       UdpHandler
	NatTimeout    time.Duration

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

	log *logrus.Logger

	dead atomic.Bool
}

func (ue *UdpEndpoint) logEndpointExit(err error, msg string) {
	if ue.log == nil {
		return
	}
	entry := ue.log.WithError(err).WithField("lAddr", ue.lAddr.String())
	if isUDPEndpointNormalClose(err) {
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
			ue.logEndpointExit(err, "read loop")
			break
		}
		ue.RefreshTtl()
		if err = ue.handler(buf[:n], from); err != nil {
			ue.dead.Store(true)
			ue.expiresAtNano.Store(1)
			ue.logEndpointExit(err, "handler")
			break
		}
	}
}

func (ue *UdpEndpoint) WriteTo(b []byte, addr string) (int, error) {
	// Refresh TTL on write to keep endpoint alive for active connections
	// This is especially important for QUIC connections where the server
	// might respond slowly during handshake
	ue.RefreshTtl()
	return ue.conn.WriteTo(b, addr)
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

// UdpEndpointPool is a full-cone udp conn pool
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

func (p *UdpEndpointPool) Remove(lAddr netip.AddrPort, udpEndpoint *UdpEndpoint) (err error) {
	// Use CompareAndDelete for atomic CAS semantics (Go 1.20+ best practice)
	if !p.pool.CompareAndDelete(lAddr, udpEndpoint) {
		udpEndpoint.Close()
		return fmt.Errorf("target udp endpoint is not in the pool")
	}
	udpEndpoint.Close()
	return nil
}

func (p *UdpEndpointPool) Get(lAddr netip.AddrPort) (udpEndpoint *UdpEndpoint, ok bool) {
	_ue, ok := p.pool.Load(lAddr)
	if !ok {
		return nil, ok
	}
	return _ue.(*UdpEndpoint), ok
}

func (p *UdpEndpointPool) GetOrCreate(lAddr netip.AddrPort, createOption *UdpEndpointOptions) (udpEndpoint *UdpEndpoint, isNew bool, err error) {
	_ue, ok := p.pool.Load(lAddr)
	if !ok {
		mu := p.createMuFor(lAddr)
		mu.Lock()
		defer mu.Unlock()

		_ue, ok = p.pool.Load(lAddr)
		if ok {
			ue := _ue.(*UdpEndpoint)

			if ue.IsDead() {
				// Use CompareAndDelete for atomic CAS (best practice)
				p.pool.CompareAndDelete(lAddr, ue)
			} else {
				ue.RefreshTtl()
				return ue, false, nil
			}
		}
		// Create an UdpEndpoint.
		if createOption == nil {
			createOption = &UdpEndpointOptions{}
		}
		if createOption.NatTimeout == 0 {
			createOption.NatTimeout = DefaultNatTimeout
		}
		if createOption.Handler == nil {
			return nil, true, fmt.Errorf("createOption.Handler cannot be nil")
		}

		// Use context.Background() as base for UDP endpoint creation.
		// The timeout context ensures the dial operation doesn't hang indefinitely.
		ctx, cancel := context.WithTimeout(context.Background(), consts.DefaultDialTimeout)
		defer cancel()

		dialOption, err := createOption.GetDialOption(ctx)
		if err != nil {
			cancel()
			return nil, false, err
		}
		udpConn, err := dialOption.Dialer.DialContext(ctx, dialOption.Network, dialOption.Target)
		if err != nil {
			return nil, true, err
		}
		if _, ok = udpConn.(netproxy.PacketConn); !ok {
			return nil, true, fmt.Errorf("protocol does not support udp")
		}
		ue := &UdpEndpoint{
			conn:          udpConn.(netproxy.PacketConn),
			handler:       createOption.Handler,
			NatTimeout:    createOption.NatTimeout,
			Dialer:        dialOption.Dialer,
			Outbound:      dialOption.Outbound,
			SniffedDomain: dialOption.SniffedDomain,
			DialTarget:    dialOption.Target,
			lAddr:         lAddr,
			log:           createOption.Log,
		}
		ue.RefreshTtl()
		_ue = ue
		p.pool.Store(lAddr, ue)
		// Receive UDP messages.
		go ue.start()
		isNew = true
	}
	ue := _ue.(*UdpEndpoint)

	if ue.IsDead() {
		// Need to acquire lock before modifying the pool
		mu := p.createMuFor(lAddr)
		mu.Lock()
		// Use CompareAndDelete for atomic CAS - only delete if still the same dead endpoint
		p.pool.CompareAndDelete(lAddr, ue)
		mu.Unlock()
		// Recursively call GetOrCreate to create a new endpoint
		return p.GetOrCreate(lAddr, createOption)
	}
	ue.RefreshTtl()
	return _ue.(*UdpEndpoint), isNew, nil
}

func (p *UdpEndpointPool) createMuFor(lAddr netip.AddrPort) *sync.Mutex {
	idx := int(hashAddrPort(lAddr) & uint64(udpEndpointCreateShardCount-1))
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
