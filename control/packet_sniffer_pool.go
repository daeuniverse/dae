/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/component/sniffing"
)

const (
	PacketSnifferTtl              = 3 * time.Second
	packetSnifferCreateShardCount = 64
	packetSnifferJanitorInterval  = 250 * time.Millisecond
)

type PacketSniffer struct {
	*sniffing.Sniffer
	Mu            sync.Mutex
	ttl           time.Duration
	expiresAtNano atomic.Int64
}

func (ps *PacketSniffer) RefreshTtl() {
	if ps.ttl <= 0 {
		return
	}
	ps.expiresAtNano.Store(time.Now().Add(ps.ttl).UnixNano())
}

func (ps *PacketSniffer) IsExpired(nowNano int64) bool {
	expiresAt := ps.expiresAtNano.Load()
	return expiresAt > 0 && nowNano >= expiresAt
}

// PacketSnifferPool is a full-cone udp conn pool
type PacketSnifferPool struct {
	pool          sync.Map
	createMuShard [packetSnifferCreateShardCount]sync.Mutex
	janitorOnce   sync.Once
}
type PacketSnifferOptions struct {
	Ttl time.Duration
}
type PacketSnifferKey struct {
	LAddr netip.AddrPort
	RAddr netip.AddrPort
}

var DefaultPacketSnifferSessionMgr = NewPacketSnifferPool()

func NewPacketSnifferPool() *PacketSnifferPool {
	p := &PacketSnifferPool{}
	p.startJanitor()
	return p
}

func (p *PacketSnifferPool) Remove(key PacketSnifferKey, sniffer *PacketSniffer) (err error) {
	if ue, ok := p.pool.LoadAndDelete(key); ok {
		sniffer.Close()
		if ue != sniffer {
			return fmt.Errorf("target udp endpoint is not in the pool")
		}
	}
	return nil
}

func (p *PacketSnifferPool) Get(key PacketSnifferKey) *PacketSniffer {
	_qs, ok := p.pool.Load(key)
	if !ok {
		return nil
	}
	return _qs.(*PacketSniffer)
}

func (p *PacketSnifferPool) GetOrCreate(key PacketSnifferKey, createOption *PacketSnifferOptions) (qs *PacketSniffer, isNew bool) {
	_qs, ok := p.pool.Load(key)
	if !ok {
		mu := p.createMuFor(key)
		mu.Lock()
		defer mu.Unlock()

		_qs, ok = p.pool.Load(key)
		if ok {
			return _qs.(*PacketSniffer), false
		}
		// Create an PacketSniffer.
		if createOption == nil {
			createOption = &PacketSnifferOptions{}
		}
		if createOption.Ttl == 0 {
			createOption.Ttl = PacketSnifferTtl
		}

		qs = &PacketSniffer{
			Sniffer: sniffing.NewPacketSniffer(nil, createOption.Ttl),
			Mu:      sync.Mutex{},
			ttl:     createOption.Ttl,
		}
		qs.RefreshTtl()
		_qs = qs
		p.pool.Store(key, qs)
		// Receive UDP messages.
		isNew = true
	}
	qs = _qs.(*PacketSniffer)
	qs.RefreshTtl()
	return qs, isNew
}

func (p *PacketSnifferPool) createMuFor(key PacketSnifferKey) *sync.Mutex {
	idx := int(hashPacketSnifferKey(key) & uint64(packetSnifferCreateShardCount-1))
	return &p.createMuShard[idx]
}

func (p *PacketSnifferPool) startJanitor() {
	p.janitorOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(packetSnifferJanitorInterval)
			defer ticker.Stop()
			for now := range ticker.C {
				nowNano := now.UnixNano()
				p.pool.Range(func(key, value any) bool {
					ps := value.(*PacketSniffer)
					if !ps.IsExpired(nowNano) {
						return true
					}
					if _ps, ok := p.pool.LoadAndDelete(key); ok && _ps == ps {
						ps.Close()
					}
					return true
				})
			}
		}()
	})
}
