/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/daeuniverse/dae/component/sniffing"
)

const (
	PacketSnifferTtl = 3 * time.Second
)

type PacketSniffer struct {
	*sniffing.Sniffer
	deadlineTimer *time.Timer
	Mu            sync.Mutex
}

type packetCreateMu struct {
	mu   sync.Mutex
	refs int
}

// PacketSnifferPool is a full-cone udp conn pool
type PacketSnifferPool struct {
	pool          sync.Map
	createMuMap   map[PacketSnifferKey]*packetCreateMu
	createMuMapMu sync.Mutex
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
	return &PacketSnifferPool{
		createMuMap: make(map[PacketSnifferKey]*packetCreateMu),
	}
}

func (p *PacketSnifferPool) acquireCreateMu(key PacketSnifferKey) *packetCreateMu {
	p.createMuMapMu.Lock()
	defer p.createMuMapMu.Unlock()

	cm, ok := p.createMuMap[key]
	if !ok {
		cm = &packetCreateMu{}
		p.createMuMap[key] = cm
	}
	cm.refs++
	return cm
}

func (p *PacketSnifferPool) releaseCreateMu(key PacketSnifferKey, cm *packetCreateMu) {
	p.createMuMapMu.Lock()
	defer p.createMuMapMu.Unlock()

	cm.refs--
	if cm.refs <= 0 {
		delete(p.createMuMap, key)
	}
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
begin:
	if !ok {
		createMu := p.acquireCreateMu(key)
		createMu.mu.Lock()
		defer func() {
			createMu.mu.Unlock()
			p.releaseCreateMu(key, createMu)
		}()

		_qs, ok = p.pool.Load(key)
		if ok {
			goto begin
		}
		// Create an PacketSniffer.
		if createOption == nil {
			createOption = &PacketSnifferOptions{}
		}
		if createOption.Ttl == 0 {
			createOption.Ttl = PacketSnifferTtl
		}

		qs = &PacketSniffer{
			Sniffer:       sniffing.NewPacketSniffer(nil, createOption.Ttl),
			Mu:            sync.Mutex{},
			deadlineTimer: nil,
		}
		qs.deadlineTimer = time.AfterFunc(createOption.Ttl, func() {
			if _qs, ok := p.pool.LoadAndDelete(key); ok {
				if _qs.(*PacketSniffer) == qs {
					qs.Close()
				} else {
					// FIXME: ?
				}
			}
		})
		_qs = qs
		p.pool.Store(key, qs)
		// Receive UDP messages.
		isNew = true
	}
	return _qs.(*PacketSniffer), isNew
}
