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
	// Reduced to 5 seconds to balance between completing QUIC handshakes and
	// cleaning up stale sniffing state faster. Most QUIC handshakes complete
	// within 1-2 RTTs, so 5 seconds is sufficient even under poor network conditions.
	PacketSnifferTtl = 5 * time.Second

	packetSnifferJanitorInterval = 250 * time.Millisecond

	// udpSniffNoSniThreshold is the number of consecutive no-SNI sniff attempts before
	// marking the DCID as failed and falling back to IP routing. Reduced to 4 to
	// minimize blocking time for non-QUIC traffic (like STUN) while still allowing
	// some retransmissions for real QUIC connections.
	udpSniffNoSniThreshold = 4

	// udpSniffNoSniBypassTtl is how long sniffing is disabled after reaching the threshold.
	// Reduced to 1 second to quickly resume sniffing after temporary failures.
	udpSniffNoSniBypassTtl = 1 * time.Second

	// consecutiveDecryptFailuresThreshold is the number of consecutive decrypt failures
	// (ErrNotApplicable) before immediately giving up on this DCID. Reduced to 2 to
	// quickly identify non-QUIC traffic that shouldn't be sniffed.
	consecutiveDecryptFailuresThreshold = 2

	// failedQuicDcidCacheShardCount spreads writes across independent shards to
	// keep contention low under bursty QUIC Initial traffic.
	failedQuicDcidCacheShardCount = 64
	// failedQuicDcidCacheMaxEntries hard-bounds memory use for the global QUIC
	// sniff negative cache. Capacity is intentionally finite because the cache is
	// a resilience hint, not correctness-critical state.
	failedQuicDcidCacheMaxEntries = 16384

	// Failure-specific base TTLs. Soft bypasses are short because they often
	// reflect transient "no SNI yet" situations, while parser panics get a
	// stronger cooldown to avoid repeatedly exercising the same bad path.
	failedQuicDcidSoftBypassTtl   = 15 * time.Second
	failedQuicDcidDecryptFailTtl  = 30 * time.Second
	failedQuicDcidPanicTtl        = 1 * time.Minute
	failedQuicDcidMaxTtl          = 5 * time.Minute
	failedQuicDcidMaxBackoffShift = 4
)

type quicDcidFailureReason uint8

const (
	quicDcidFailureReasonSoftBypass quicDcidFailureReason = iota + 1
	quicDcidFailureReasonDecryptFailure
	quicDcidFailureReasonPanic
)

type failedQuicDcidCacheEntry struct {
	expiresAtUnixNano int64
	backoffShift      uint8
}

type failedQuicDcidCacheShard struct {
	mu      sync.RWMutex
	entries map[PacketSnifferKey]failedQuicDcidCacheEntry
}

type failedQuicDcidCache struct {
	maxEntriesPerShard int
	shards             [failedQuicDcidCacheShardCount]failedQuicDcidCacheShard
}

var (
	failedQuicDcidCachePtr atomic.Pointer[failedQuicDcidCache]
)

// SetFailedQuicDcidCache sets the active cache for failed QUIC DCIDs.
// This allows the ControlPlane to provide its instance-local cache while
// maintaining the package-level API for callers.
func SetFailedQuicDcidCache(cache *failedQuicDcidCache) {
	failedQuicDcidCachePtr.Store(cache)
}

func getFailedQuicDcidCache() *failedQuicDcidCache {
	return failedQuicDcidCachePtr.Load()
}

func newFailedQuicDcidCache(maxEntries int) *failedQuicDcidCache {
	if maxEntries <= 0 {
		maxEntries = failedQuicDcidCacheMaxEntries
	}

	perShard := maxEntries / failedQuicDcidCacheShardCount
	if perShard == 0 {
		perShard = 1
	}
	if perShard*failedQuicDcidCacheShardCount < maxEntries {
		perShard++
	}

	cache := &failedQuicDcidCache{
		maxEntriesPerShard: perShard,
	}
	for i := range failedQuicDcidCacheShardCount {
		cache.shards[i].entries = make(map[PacketSnifferKey]failedQuicDcidCacheEntry, perShard)
	}
	return cache
}

func failedQuicDcidBaseTtl(reason quicDcidFailureReason) time.Duration {
	switch reason {
	case quicDcidFailureReasonSoftBypass:
		return failedQuicDcidSoftBypassTtl
	case quicDcidFailureReasonDecryptFailure:
		return failedQuicDcidDecryptFailTtl
	case quicDcidFailureReasonPanic:
		return failedQuicDcidPanicTtl
	default:
		return failedQuicDcidSoftBypassTtl
	}
}

func failedQuicDcidSuppressionTtl(reason quicDcidFailureReason, backoffShift uint8) time.Duration {
	ttl := failedQuicDcidBaseTtl(reason)
	for i := uint8(0); i < backoffShift && ttl < failedQuicDcidMaxTtl; i++ {
		ttl *= 2
		if ttl > failedQuicDcidMaxTtl {
			return failedQuicDcidMaxTtl
		}
	}
	if ttl > failedQuicDcidMaxTtl {
		return failedQuicDcidMaxTtl
	}
	return ttl
}

func hashPacketSnifferKey(key PacketSnifferKey) uint64 {
	h := hashAddrPort(key.LAddr)
	h = wyMix(h^hashAddrPort(key.RAddr), wyHashP0)

	if key.DCIDLen > 0 {
		dcid := key.DCID[:key.DCIDLen]
		for len(dcid) >= 8 {
			h = wyMix(h^binary.LittleEndian.Uint64(dcid[:8]), wyHashP1)
			dcid = dcid[8:]
		}
		if len(dcid) > 0 {
			var tail [8]byte
			copy(tail[:], dcid)
			h = wyMix(h^binary.LittleEndian.Uint64(tail[:]), wyHashP2)
		}
	}
	h ^= uint64(key.DCIDLen)
	h = wyMix(h, wyHashP3)
	h ^= h >> 32
	return h
}

func (k PacketSnifferKey) HasCacheableDcid() bool {
	return k.DCIDLen > 0
}

func (c *failedQuicDcidCache) shardFor(key PacketSnifferKey) *failedQuicDcidCacheShard {
	idx := int(hashPacketSnifferKey(key) & uint64(failedQuicDcidCacheShardCount-1))
	return &c.shards[idx]
}

func (c *failedQuicDcidCache) IsFailed(key PacketSnifferKey, now time.Time) bool {
	if c == nil || !key.HasCacheableDcid() {
		return false
	}

	nowNano := now.UnixNano()
	shard := c.shardFor(key)
	shard.mu.RLock()
	entry, ok := shard.entries[key]
	shard.mu.RUnlock()
	if !ok {
		return false
	}
	if entry.expiresAtUnixNano > nowNano {
		return true
	}

	shard.mu.Lock()
	if current, ok := shard.entries[key]; ok && current == entry && current.expiresAtUnixNano <= nowNano {
		delete(shard.entries, key)
	}
	shard.mu.Unlock()
	return false
}

func (c *failedQuicDcidCache) MarkFailed(key PacketSnifferKey, reason quicDcidFailureReason, now time.Time) {
	if c == nil || !key.HasCacheableDcid() {
		return
	}

	nowNano := now.UnixNano()
	shard := c.shardFor(key)
	shard.mu.Lock()
	defer shard.mu.Unlock()

	if entry, ok := shard.entries[key]; ok && entry.expiresAtUnixNano > nowNano {
		if entry.backoffShift < failedQuicDcidMaxBackoffShift {
			entry.backoffShift++
		}
		newExpiry := now.Add(failedQuicDcidSuppressionTtl(reason, entry.backoffShift)).UnixNano()
		if newExpiry < entry.expiresAtUnixNano {
			newExpiry = entry.expiresAtUnixNano
		}
		entry.expiresAtUnixNano = newExpiry
		shard.entries[key] = entry
		return
	}

	for existingKey, entry := range shard.entries {
		if entry.expiresAtUnixNano <= nowNano {
			delete(shard.entries, existingKey)
		}
	}

	if len(shard.entries) >= c.maxEntriesPerShard {
		var victimKey PacketSnifferKey
		var victimExpiry int64
		haveVictim := false
		for existingKey, entry := range shard.entries {
			if !haveVictim || entry.expiresAtUnixNano < victimExpiry {
				victimKey = existingKey
				victimExpiry = entry.expiresAtUnixNano
				haveVictim = true
			}
		}
		if haveVictim {
			delete(shard.entries, victimKey)
		}
	}

	shard.entries[key] = failedQuicDcidCacheEntry{
		expiresAtUnixNano: now.Add(failedQuicDcidSuppressionTtl(reason, 0)).UnixNano(),
	}
}

func (c *failedQuicDcidCache) CleanupExpired(now time.Time) {
	if c == nil {
		return
	}

	nowNano := now.UnixNano()
	for i := range failedQuicDcidCacheShardCount {
		shard := &c.shards[i]
		shard.mu.Lock()
		for key, entry := range shard.entries {
			if entry.expiresAtUnixNano <= nowNano {
				delete(shard.entries, key)
			}
		}
		shard.mu.Unlock()
	}
}

func (c *failedQuicDcidCache) Clear() {
	if c == nil {
		return
	}

	for i := range failedQuicDcidCacheShardCount {
		shard := &c.shards[i]
		shard.mu.Lock()
		clear(shard.entries)
		shard.mu.Unlock()
	}
}

func (c *failedQuicDcidCache) Len() int {
	if c == nil {
		return 0
	}

	total := 0
	for i := range failedQuicDcidCacheShardCount {
		shard := &c.shards[i]
		shard.mu.RLock()
		total += len(shard.entries)
		shard.mu.RUnlock()
	}
	return total
}

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

	// consecutiveDecryptFailures counts consecutive ErrNotApplicable errors.
	// If decryption fails repeatedly, it indicates malformed packets and we
	// should give up quickly rather than waiting for more packets.
	consecutiveDecryptFailures int

	quicInitialSig    quicInitialFingerprint
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

// PacketSnifferKey identifies a QUIC sniffing session by 5-tuple + DCID.
// Each QUIC connection has a unique Destination Connection ID, so we group
// by DCID to separate different QUIC connections on the same UDP flow.
// This is like grouping passengers by the bus they're waiting for.
type PacketSnifferKey struct {
	LAddr   netip.AddrPort
	RAddr   netip.AddrPort
	DCID    [20]byte // Destination Connection ID (max 20 bytes)
	DCIDLen uint8    // Actual DCID length (0-20)
}

// NewPacketSnifferKey creates a sniffer key with DCID for QUIC connections.
// For non-QUIC packets, DCID is zero and the key falls back to {Src, Dst}.
func NewPacketSnifferKey(src, dst netip.AddrPort, data []byte) PacketSnifferKey {
	key := PacketSnifferKey{
		LAddr: src,
		RAddr: dst,
	}

	// Try to extract DCID from QUIC Initial packet
	if sniffing.IsLikelyQuicInitialPacket(data) && len(data) >= 7 {
		dstLen := int(data[5])
		if dstLen > 0 && dstLen <= 20 {
			pos := 6
			if len(data) >= pos+dstLen {
				key.DCIDLen = uint8(dstLen)
				copy(key.DCID[:], data[pos:pos+dstLen])
			}
		}
	}

	return key
}

var DefaultPacketSnifferSessionMgr = NewPacketSnifferPool()

func NewPacketSnifferPool() *PacketSnifferPool {
	p := &PacketSnifferPool{}
	p.startJanitor()
	return p
}

// Reset clears all packet sniffer sessions.
// Called on reload to prevent stale sniffers from using pre-reload state.
// Uses LoadAndDelete for atomic removal that races safely with concurrent GetOrCreate.
func (p *PacketSnifferPool) Reset() {
	// Two-phase deletion: collect keys first, then delete
	var keys []any
	p.pool.Range(func(key, value any) bool {
		keys = append(keys, key)
		return true
	})
	for _, key := range keys {
		if value, ok := p.pool.LoadAndDelete(key); ok {
			ps := value.(*PacketSniffer)
			_ = ps.Close()
		}
	}
}

func (p *PacketSnifferPool) Remove(key PacketSnifferKey, sniffer *PacketSniffer) (err error) {
	// Use CompareAndDelete for atomic CAS semantics (Go 1.20+ best practice)
	if !p.pool.CompareAndDelete(key, sniffer) {
		_ = sniffer.Close()
		return fmt.Errorf("target udp endpoint is not in the pool")
	}
	_ = sniffer.Close()
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
			// janitorMinScanItems is the minimum number of items to check per cycle.
			// This ensures we make progress on cleanup even when most items are unexpired.
			// With 250ms interval and 5s TTL, items get checked within ~20 cycles = 5s.
			const janitorMinScanItems = 128
			// janitorMaxConsecutiveFresh is the max consecutive fresh (unexpired) items
			// we'll scan before giving up on this cycle. This prevents wasting CPU when
			// the pool is mostly active.
			const janitorMaxConsecutiveFresh = 512
			for now := range ticker.C {
				nowNano := now.UnixNano()
				consecutiveFresh := 0
				totalScanned := 0
				expiredFound := 0

				p.pool.Range(func(key, value any) bool {
					totalScanned++
					ps := value.(*PacketSniffer)
					if ps.IsExpired(nowNano) {
						consecutiveFresh = 0
						expiredFound++
						// Use CompareAndDelete for atomic CAS - only delete if still the same expired sniffer
						if p.pool.CompareAndDelete(key, ps) {
							_ = ps.Close()
						}
						// Continue scanning - there might be more expired items
						return true
					}
					consecutiveFresh++
					// Early exit if we've seen many fresh items without finding expired ones.
					// This bounds the cleanup cost per cycle for large, active pools.
					if consecutiveFresh >= janitorMaxConsecutiveFresh {
						return false
					}
					// Always scan at least a minimum number of items
					if totalScanned >= janitorMinScanItems && expiredFound == 0 {
						// We've scanned enough and found nothing expired - likely a mostly active pool
						return false
					}
					return true
				})
			}
		}()
	})
}

// IsQuicDcidFailed checks if a DCID has been marked as failed due to sniffing timeout.
// Failed DCIDs bypass sniffing entirely and use IP routing directly.
func IsQuicDcidFailed(key PacketSnifferKey) bool {
	return IsQuicDcidFailedAt(key, time.Now())
}

func IsQuicDcidFailedAt(key PacketSnifferKey, now time.Time) bool {
	cache := getFailedQuicDcidCache()
	if cache == nil {
		return false
	}
	return cache.IsFailed(key, now)
}

// MarkQuicDcidFailed marks a DCID as failed, causing subsequent packets with
// the same DCID to bypass sniffing and use IP routing directly.
func MarkQuicDcidFailed(key PacketSnifferKey, reason quicDcidFailureReason) {
	cache := getFailedQuicDcidCache()
	if cache == nil {
		return
	}
	cache.MarkFailed(key, reason, time.Now())
}

// ClearFailedQuicDcids clears all failed DCID entries.
// This should be called on reload or when network conditions improve
// (e.g., after successful health check) to allow retrying sniffing.
func ClearFailedQuicDcids() {
	cache := getFailedQuicDcidCache()
	if cache == nil {
		return
	}
	cache.Clear()
}

// HealthCheckSuccessCallback is a callback function that can be set to
// be notified when health check succeeds. This allows clearing the failed
// DCID cache when network conditions improve.
var HealthCheckSuccessCallback func()

// NotifyHealthCheckSuccess should be called when a health check succeeds.
// This clears the failed QUIC DCID cache to allow retrying sniffing.
func NotifyHealthCheckSuccess() {
	ClearFailedQuicDcids()
	if HealthCheckSuccessCallback != nil {
		HealthCheckSuccessCallback()
	}
}
