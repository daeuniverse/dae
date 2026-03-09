/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/component/sniffing"
)

const (
	// PacketSnifferTtl is the TTL for packet sniffer sessions.
	// Increased to 10 seconds to ensure QUIC handshake has enough time to complete
	// under poor network conditions. QUIC Initial packets may require multiple RTTs
	// to gather enough Crypto frames for SNI extraction.
	PacketSnifferTtl = 10 * time.Second

	packetSnifferJanitorInterval = 250 * time.Millisecond

	// udpSniffNoSniThreshold is the number of consecutive no-SNI sniff attempts before
	// temporarily disabling sniffing for this flow. Increased to 12 to reduce false positives
	// under bursty traffic patterns while still protecting against pathological cases.
	udpSniffNoSniThreshold = 12

	// udpSniffNoSniBypassTtl is how long sniffing is disabled after reaching the threshold.
	// Reduced to 3 seconds to limit the impact of temporary failures on subsequent
	// connection attempts (e.g., browser refreshes using the same source port).
	udpSniffNoSniBypassTtl = 3 * time.Second
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
	quicInitialSig   quicInitialFingerprint
	hasQuicInitialSig bool
}

type quicInitialFingerprint struct {
	version uint32
	dstLen  uint8
	srcLen  uint8
	dstConn [20]byte
	srcConn [20]byte
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

// ObserveQuicInitial fingerprints the QUIC Initial connection IDs carried by
// the current flow. The caller must hold ps.Mu. It returns true only when the
// packet is a QUIC Initial for a different connection than the one already
// associated with this sniffer session, which is the safe moment to reset the
// session for source-port reuse without breaking multi-packet handshakes.
func (ps *PacketSniffer) ObserveQuicInitial(data []byte) bool {
	sig, ok := parseQuicInitialFingerprint(data)
	if !ok {
		return false
	}
	if !ps.hasQuicInitialSig {
		ps.quicInitialSig = sig
		ps.hasQuicInitialSig = true
		return false
	}
	return ps.quicInitialSig != sig
}

func parseQuicInitialFingerprint(data []byte) (sig quicInitialFingerprint, ok bool) {
	if !sniffing.IsLikelyQuicInitialPacket(data) {
		return quicInitialFingerprint{}, false
	}
	if len(data) < 7 {
		return quicInitialFingerprint{}, false
	}

	sig.version = binary.BigEndian.Uint32(data[1:5])
	dstLen := int(data[5])
	if dstLen > len(sig.dstConn) {
		return quicInitialFingerprint{}, false
	}
	pos := 6
	if len(data) < pos+dstLen+1 {
		return quicInitialFingerprint{}, false
	}
	copy(sig.dstConn[:], data[pos:pos+dstLen])
	sig.dstLen = uint8(dstLen)
	pos += dstLen

	srcLen := int(data[pos])
	if srcLen > len(sig.srcConn) {
		return quicInitialFingerprint{}, false
	}
	pos++
	if len(data) < pos+srcLen {
		return quicInitialFingerprint{}, false
	}
	copy(sig.srcConn[:], data[pos:pos+srcLen])
	sig.srcLen = uint8(srcLen)
	return sig, true
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
