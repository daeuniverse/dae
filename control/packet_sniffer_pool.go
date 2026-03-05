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
	PacketSnifferTtl             = 3 * time.Second
	packetSnifferJanitorInterval = 250 * time.Millisecond
	udpSniffNoSniThreshold       = 6
	udpSniffNoSniBypassTtl       = 10 * time.Second
)

// PacketSniffer holds sniffing state for a UDP flow.
// Field order optimized for memory alignment (Go best practice).
type PacketSniffer struct {
	*sniffing.Sniffer
	// 8-byte aligned pointer first

	// 8-byte field
	ttl time.Duration

	// 8-byte atomic
	expiresAtNano atomic.Int64

	// Mutex for protecting sniffing operations
	Mu sync.Mutex

	// Soft negative cache for UDP sniffing: after repeated no-SNI attempts
	// (timeouts / need-more / not-applicable), bypass sniffing temporarily.
	noSniStreak      int
	bypassSniffUntil time.Time
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

func (ps *PacketSniffer) ShouldBypassSniff(now time.Time) bool {
	return now.Before(ps.bypassSniffUntil)
}

func (ps *PacketSniffer) RecordSniffNoSni(now time.Time) {
	ps.noSniStreak++
	if ps.noSniStreak >= udpSniffNoSniThreshold {
		ps.bypassSniffUntil = now.Add(udpSniffNoSniBypassTtl)
		ps.noSniStreak = 0
	}
}

func (ps *PacketSniffer) RecordSniffSuccess() {
	ps.noSniStreak = 0
	ps.bypassSniffUntil = time.Time{}
}

// PacketSnifferPool is a full-cone udp conn pool.
// Uses sync.Map for lock-free concurrent access.
type PacketSnifferPool struct {
	pool        sync.Map
	janitorOnce sync.Once
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
	// Use CompareAndDelete for atomic CAS semantics (Go 1.20+ best practice)
	if !p.pool.CompareAndDelete(key, sniffer) {
		sniffer.Close()
		return fmt.Errorf("target udp endpoint is not in the pool")
	}
	sniffer.Close()
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
	// Fast path: check if exists without any lock
	if _qs, ok := p.pool.Load(key); ok {
		qs = _qs.(*PacketSniffer)
		qs.RefreshTtl()
		return qs, false
	}

	// Slow path: create using LoadOrStore for atomic semantics
	if createOption == nil {
		createOption = &PacketSnifferOptions{}
	}
	if createOption.Ttl == 0 {
		createOption.Ttl = PacketSnifferTtl
	}

	newQs := &PacketSniffer{
		Sniffer: sniffing.NewPacketSniffer(nil, createOption.Ttl),
		ttl:     createOption.Ttl,
	}
	newQs.RefreshTtl()

	// LoadOrStore ensures atomic create-or-get semantics
	actual, loaded := p.pool.LoadOrStore(key, newQs)
	qs = actual.(*PacketSniffer)
	qs.RefreshTtl()
	return qs, !loaded
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
					// Use CompareAndDelete for atomic CAS - only delete if still the same expired sniffer
					if p.pool.CompareAndDelete(key, ps) {
						ps.Close()
					}
					return true
				})
			}
		}()
	})
}
