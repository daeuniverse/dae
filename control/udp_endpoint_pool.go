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

	// dead indicates the endpoint's read loop has exited due to error.
	// Once set to true, the endpoint should not be reused and will be
	// cleaned up by the janitor or GetOrCreate's dead endpoint check.
	dead atomic.Bool
}

func (ue *UdpEndpoint) start() {
	buf := pool.GetFullCap(consts.EthernetMtu)
	defer pool.Put(buf)
	for {
		n, from, err := ue.conn.ReadFrom(buf[:])
		if err != nil {
			// Mark this endpoint as dead so GetOrCreate won't reuse it.
			// Also set expiration to past for immediate janitor cleanup.
			ue.dead.Store(true)
			ue.expiresAtNano.Store(1)
			break
		}
		ue.RefreshTtl()
		if err = ue.handler(buf[:n], from); err != nil {
			ue.dead.Store(true)
			ue.expiresAtNano.Store(1)
			break
		}
	}
}

func (ue *UdpEndpoint) WriteTo(b []byte, addr string) (int, error) {
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
	GetDialOption func() (option *DialOption, err error)
}

var DefaultUdpEndpointPool = NewUdpEndpointPool()

func NewUdpEndpointPool() *UdpEndpointPool {
	p := &UdpEndpointPool{}
	p.startJanitor()
	return p
}

func (p *UdpEndpointPool) Remove(lAddr netip.AddrPort, udpEndpoint *UdpEndpoint) (err error) {
	if ue, ok := p.pool.LoadAndDelete(lAddr); ok {
		if ue != udpEndpoint {
			udpEndpoint.Close()
			return fmt.Errorf("target udp endpoint is not in the pool")
		}
		ue.(*UdpEndpoint).Close()
	}
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
			// Check if the existing endpoint is dead (read loop exited).
			// If so, remove it and create a new one.
			if ue.IsDead() {
				p.pool.Delete(lAddr)
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

		dialOption, err := createOption.GetDialOption()
		if err != nil {
			return nil, false, err
		}
		ctx, cancel := context.WithTimeout(context.TODO(), consts.DefaultDialTimeout)
		defer cancel()
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
		}
		ue.RefreshTtl()
		_ue = ue
		p.pool.Store(lAddr, ue)
		// Receive UDP messages.
		go ue.start()
		isNew = true
	}
	ue := _ue.(*UdpEndpoint)
	// Check if the endpoint is dead (read loop exited).
	// If so, remove it and try to create a new one.
	if ue.IsDead() {
		// Need to acquire lock before modifying the pool
		mu := p.createMuFor(lAddr)
		mu.Lock()
		// Double check after acquiring lock
		if _ue2, ok2 := p.pool.Load(lAddr); ok2 && _ue2 == ue {
			p.pool.Delete(lAddr)
		}
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
					if _ue, ok := p.pool.LoadAndDelete(key); ok && _ue == ue {
						_ = ue.Close()
					}
					return true
				})
			}
		}()
	})
}
