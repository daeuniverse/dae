/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"fmt"
	"net/netip"
	"sync/atomic"
	"time"

	dnsmessage "github.com/miekg/dns"
)

// Approximate TTL refresh threshold in seconds.
// Pre-packed response is refreshed when TTL difference exceeds this value.
// This balances between performance (avoiding frequent repack) and TTL accuracy.
// NOTE: Increased from 5 to 15 to reduce memory allocation frequency under high load
// while maintaining acceptable TTL accuracy (15s variance is negligible for DNS caching).
const ttlRefreshThresholdSeconds = 15

// BPF update configuration
const (
	// MinBpfUpdateInterval is the minimum time between BPF map updates for the same cache.
	// This prevents excessive BPF map updates while maintaining freshness.
	MinBpfUpdateInterval = 1 * time.Second

	// MaxBpfUpdateInterval is the maximum time before forcing a BPF map update.
	// Even if data hasn't changed, we refresh periodically to handle edge cases.
	MaxBpfUpdateInterval = 60 * time.Second
)

type dnsPackedResponse struct {
	wire              []byte
	ttl               uint32
	createdAtUnixNano int64
}

type DnsCache struct {
	RouteOwnerKey        string
	RouteProjectionEpoch uint64
	DomainBitmap         []uint32
	Answer               []dnsmessage.RR
	NS                   []dnsmessage.RR
	Extra                []dnsmessage.RR
	Deadline             time.Time
	OriginalDeadline     time.Time // This field is not impacted by `fixed_domain_ttl`.

	// lastRouteSyncNano tracks when route binding was last synced to BPF.
	lastRouteSyncNano atomic.Int64

	// lastBpfDataHash stores a hash of the data used for BPF update.
	// This enables differential updates - only update when data changes.
	lastBpfDataHash atomic.Uint64

	// packedResponse is a pre-packed DNS response message with compression enabled.
	// This avoids repeated Pack() calls on cache hits, significantly reducing latency.
	// The packed response includes: Answer, Rcode=Success, Response=true, RecursionAvailable=true.
	// Note: DNS Message ID is NOT included and must be patched by the caller.
	//
	// OPTIMIZATION: Uses Copy-on-Write with one atomic.Pointer for lock-free
	// reads. The wire bytes and the metadata used to interpret them are one
	// immutable publication unit, so readers cannot mix refresh generations.
	packedResponse           atomic.Pointer[dnsPackedResponse]
	packedResponseRefreshing atomic.Bool
	// deadlineNano caches the Deadline as UnixNano for fast comparison.
	// This avoids time.Time method calls on every cache hit.
	deadlineNano atomic.Int64

	// OPTIMISTIC CACHE (RFC 8767): Stale-while-revalidate support
	// refreshing tracks whether background refresh is in progress.
	// This prevents multiple concurrent refresh attempts for the same cache key.
	refreshing atomic.Bool

	// lastAccessNano tracks when this cache was last accessed (for LRU eviction).
	lastAccessNano atomic.Int64
}

func ttlFromDeadline(deadline time.Time, now time.Time) uint32 {
	deadlineNano := deadline.UnixNano()
	nowNano := now.UnixNano()
	if deadlineNano <= nowNano {
		return 0
	}

	ttlSeconds := (deadlineNano - nowNano) / 1e9
	if ttlSeconds < 1 {
		return 1
	}
	return uint32(ttlSeconds)
}

func (c *DnsCache) GetFqdn() string {
	if len(c.Answer) > 0 {
		return c.Answer[0].Header().Name
	}
	return ""
}

// ComputeBpfDataHash computes a hash of the data used for BPF updates.
// This includes IP addresses from Answer and the DomainBitmap.
// Returns 0 if there are no valid IPs (no update needed).
func (c *DnsCache) ComputeBpfDataHash() uint64 {
	if len(c.Answer) == 0 {
		return 0
	}

	var hash uint64 = 14695981039346656037 // FNV-1a offset basis

	// Hash IP addresses from Answer
	for _, ans := range c.Answer {
		var ipBytes []byte
		switch body := ans.(type) {
		case *dnsmessage.A:
			ipBytes = body.A
		case *dnsmessage.AAAA:
			ipBytes = body.AAAA
		}
		if len(ipBytes) > 0 {
			for _, b := range ipBytes {
				hash ^= uint64(b)
				hash *= 1099511628211 // FNV-1a prime
			}
		}
	}

	// Hash DomainBitmap
	for _, v := range c.DomainBitmap {
		hash ^= uint64(v)
		hash *= 1099511628211
	}

	return hash
}

// NeedsBpfUpdate checks if BPF map update is needed using differential detection.
// Returns true if:
//  1. Minimum interval has passed since last update AND
//     (data has changed OR maximum interval has passed)
//  2. Never been updated before
//
// IMPORTANT: This method uses CAS to prevent race conditions. Only one goroutine
// will successfully trigger an update request.
func (c *DnsCache) NeedsBpfUpdate(now time.Time) bool {
	nowNano := now.UnixNano()
	lastSync := c.lastRouteSyncNano.Load()

	// Never updated - needs update (use CAS to claim first update)
	if lastSync == 0 {
		return c.lastRouteSyncNano.CompareAndSwap(0, nowNano)
	}

	timeSinceLastSync := time.Duration(nowNano - lastSync)

	// Haven't reached minimum interval - skip
	if timeSinceLastSync < MinBpfUpdateInterval {
		return false
	}

	// Maximum interval reached - force update (use CAS to claim)
	if timeSinceLastSync >= MaxBpfUpdateInterval {
		return c.lastRouteSyncNano.CompareAndSwap(lastSync, nowNano)
	}

	// Check if data has changed
	currentHash := c.ComputeBpfDataHash()
	if currentHash == 0 {
		// No valid IPs - no update needed
		return false
	}

	lastHash := c.lastBpfDataHash.Load()
	if currentHash == lastHash {
		// Data unchanged - no update needed
		return false
	}

	// Data changed - use CAS to claim this update
	// Only one goroutine will succeed
	return c.lastRouteSyncNano.CompareAndSwap(lastSync, nowNano)
}

// MarkBpfUpdated marks the BPF map as updated with the current data hash.
// This should be called after a successful BPF update.
func (c *DnsCache) MarkBpfUpdated(now time.Time) {
	c.lastRouteSyncNano.Store(now.UnixNano())
	c.lastBpfDataHash.Store(c.ComputeBpfDataHash())
}

// CloneForReload creates a new generation-local cache wrapper for reload.
//
// WARNING: Answer, NS, and Extra slices share memory with the original cache.
// DO NOT mutate any RR after it has been inserted into the cache.
// Violating this contract will cause data corruption across generations.
//
// Immutable payload such as RR slices and the current packed response are reused
// to avoid the reload-time deep-copy spike. Per-generation routing metadata is
// reset so the new control plane can repopulate BPF state with its own routing
// matcher and lifecycle bookkeeping.
func (c *DnsCache) CloneForReload() *DnsCache {
	newCache := &DnsCache{
		RouteOwnerKey:        c.RouteOwnerKey,
		RouteProjectionEpoch: c.RouteProjectionEpoch,
		Answer:               c.Answer,
		NS:                   c.NS,
		Extra:                c.Extra,
		Deadline:             c.Deadline,
		OriginalDeadline:     c.OriginalDeadline,
	}

	if packed := c.packedResponse.Load(); packed != nil && packed.wire != nil {
		// Packed responses are immutable after publication. Sharing the current
		// snapshot avoids a reload-only copy, and each generation still owns its
		// atomic pointer for future TTL refreshes.
		newCache.packedResponse.Store(packed)
	}

	deadlineNano := c.deadlineNano.Load()
	if deadlineNano == 0 && !c.Deadline.IsZero() {
		deadlineNano = c.Deadline.UnixNano()
	}
	newCache.deadlineNano.Store(deadlineNano)
	newCache.lastAccessNano.Store(c.lastAccessNano.Load())
	newCache.lastRouteSyncNano.Store(0)
	newCache.lastBpfDataHash.Store(0)
	newCache.refreshing.Store(false)

	return newCache
}

// PrepackResponse generates a pre-packed DNS response message.
// This should be called once when creating the cache entry.
// The qname should be the full qualified domain name (with trailing dot).
// Uses approximate TTL - the pre-packed response is refreshed when TTL changes
// by more than ttlRefreshThresholdSeconds.
func (c *DnsCache) PrepackResponse(qname string, qtype uint16) error {
	now := time.Now()

	// Cache deadline as UnixNano for fast comparison
	c.deadlineNano.Store(c.Deadline.UnixNano())

	return c.prepackResponseWithTTL(qname, qtype, ttlFromDeadline(c.Deadline, now), now)
}

func ttlScratchSlice(n int, stack *[8]uint32) []uint32 {
	if n <= len(stack) {
		return stack[:n]
	}
	return make([]uint32, n)
}

func setRecordTTL(rr dnsmessage.RR, ttl uint32) {
	hdr := rr.Header()
	// OPT encodes EDNS version and flags in this field, not a lifetime.
	if hdr.Rrtype != dnsmessage.TypeOPT {
		hdr.Ttl = ttl
	}
}

func setSectionTTL(rrs []dnsmessage.RR, ttl uint32, scratch []uint32) {
	for i, rr := range rrs {
		scratch[i] = rr.Header().Ttl
		setRecordTTL(rr, ttl)
	}
}

// copySectionWithTTL deep-copies a record section and stamps the remaining
// lifetime onto every record. This is the single place where the "materialize a
// stored section onto the wire at a given remaining TTL" policy lives, so the
// pre-packed path and the in-place fallback cannot drift apart.
//
// Answers carry a real TTL: the first answer carries the TTL the upstream
// returned, a cache hit the remaining lifetime of the entry. dae tracks
// freshness of its own address answers through the entry deadline and the stale
// window rather than by telling resolvers not to cache, so nothing here may
// rewrite a lifetime to zero. The EDNS OPT pseudo-record is never treated as a
// TTL (see setRecordTTL).
func copySectionWithTTL(rrs []dnsmessage.RR, ttl uint32) []dnsmessage.RR {
	if rrs == nil {
		return nil
	}
	copied := make([]dnsmessage.RR, len(rrs))
	for i, rr := range rrs {
		record := dnsmessage.Copy(rr)
		setRecordTTL(record, ttl)
		copied[i] = record
	}
	return copied
}

func restoreSectionTTL(rrs []dnsmessage.RR, scratch []uint32) {
	for i, rr := range rrs {
		rr.Header().Ttl = scratch[i]
	}
}

// prepackResponseBeforeStore is a lighter pre-pack path used only before the
// cache entry becomes visible to concurrent readers. It temporarily rewrites
// the TTLs in-place, packs the response, and restores the original TTLs before
// returning. This preserves the stored RR values while avoiding deep copies on
// the cold cache-insert path.
func (c *DnsCache) prepackResponseBeforeStore(qname string, qtype uint16, ttl uint32, now time.Time) error {
	var question [1]dnsmessage.Question
	question[0] = dnsmessage.Question{Name: qname, Qtype: qtype, Qclass: dnsmessage.ClassINET}

	msg := dnsmessage.Msg{
		MsgHdr: dnsmessage.MsgHdr{
			Rcode:              dnsmessage.RcodeSuccess,
			Response:           true,
			RecursionAvailable: true,
			RecursionDesired:   true,
			Truncated:          false,
		},
		Question: question[:],
		Answer:   c.Answer,
		Ns:       c.NS,
		Extra:    c.Extra,
		Compress: true,
	}

	var (
		answerStack [8]uint32
		nsStack     [8]uint32
		extraStack  [8]uint32
	)
	answerTTLs := ttlScratchSlice(len(c.Answer), &answerStack)
	nsTTLs := ttlScratchSlice(len(c.NS), &nsStack)
	extraTTLs := ttlScratchSlice(len(c.Extra), &extraStack)

	setSectionTTL(c.Answer, ttl, answerTTLs)
	setSectionTTL(c.NS, ttl, nsTTLs)
	setSectionTTL(c.Extra, ttl, extraTTLs)
	defer func() {
		restoreSectionTTL(c.Extra, extraTTLs)
		restoreSectionTTL(c.NS, nsTTLs)
		restoreSectionTTL(c.Answer, answerTTLs)
	}()

	packed, err := msg.Pack()
	if err != nil {
		return err
	}

	c.packedResponse.Store(&dnsPackedResponse{
		wire:              packed,
		ttl:               ttl,
		createdAtUnixNano: now.UnixNano(),
	})
	// deadlineNano gates the packed fast path and stale-while-revalidate
	// lookups; leaving it zero makes both treat a freshly stored entry as
	// already expired. Entries are prepacked before they become visible to
	// concurrent readers, so a plain store is sufficient here.
	c.deadlineNano.Store(c.Deadline.UnixNano())
	return nil
}

// prepackResponseWithTTL creates pre-packed response with specified TTL
// OPTIMIZED: Uses Copy-on-Write with atomic pointer swap for thread-safe updates.
// Creates a new []byte slice and atomically swaps the pointer - no blocking readers.
func (c *DnsCache) prepackResponseWithTTL(qname string, qtype uint16, ttl uint32, now time.Time) error {
	msg := &dnsmessage.Msg{
		MsgHdr: dnsmessage.MsgHdr{
			Rcode:              dnsmessage.RcodeSuccess,
			Response:           true,
			RecursionAvailable: true,
			RecursionDesired:   true,
			Truncated:          false,
		},
		Question: []dnsmessage.Question{
			{Name: qname, Qtype: qtype, Qclass: dnsmessage.ClassINET},
		},
		Compress: true,
	}

	msg.Answer = copySectionWithTTL(c.Answer, ttl)
	msg.Ns = copySectionWithTTL(c.NS, ttl)
	msg.Extra = copySectionWithTTL(c.Extra, ttl)

	packed, err := msg.Pack()
	if err != nil {
		return err
	}

	c.packedResponse.Store(&dnsPackedResponse{
		wire:              packed,
		ttl:               ttl,
		createdAtUnixNano: now.UnixNano(),
	})
	return nil
}

// GetPackedResponseWithApproximateTTL returns pre-packed response with approximate TTL.
// OPTIMIZED: Uses Copy-on-Write with atomic.Pointer for lock-free reads.
// Fast path: returns cached pre-packed response if TTL difference is within threshold.
// Slow path: refreshes pre-packed response if TTL has changed significantly.
// THREAD-SAFE: Lock-free reads + atomic updates. No mutex contention.
// PERFORMANCE: Eliminates deep copy + Pack() bottleneck. 10-100x faster for cache hits.
// NOTE: Only returns fresh (unexpired) responses. For stale responses, use GetStaleResponse.
func (c *DnsCache) GetPackedResponseWithApproximateTTL(qname string, qtype uint16, now time.Time) []byte {
	nowNano := now.UnixNano()
	deadlineNano := c.deadlineNano.Load()

	// Check if cache is expired - return nil immediately
	if deadlineNano <= nowNano {
		return nil
	}

	// Calculate current TTL in seconds (avoid float operations)
	currentTTL := uint32((deadlineNano - nowNano) / 1e9)
	if currentTTL == 0 {
		currentTTL = 1
	}

	// Lock-free read: one load observes wire bytes and TTL metadata from the
	// same immutable publication.
	packed := c.packedResponse.Load()
	if packed != nil && packed.wire != nil {
		if packed.ttl >= currentTTL {
			if packed.ttl-currentTTL <= ttlRefreshThresholdSeconds {
				return packed.wire
			}
		} else if currentTTL-packed.ttl <= ttlRefreshThresholdSeconds {
			return packed.wire
		}
	}

	// The separate flag is only a best-effort refresh admission gate; it does
	// not describe the published response and therefore cannot create a mixed
	// response generation.
	if (packed == nil || nowNano-packed.createdAtUnixNano > 1e9) && c.packedResponseRefreshing.CompareAndSwap(false, true) {
		current := c.packedResponse.Load()
		if current == nil || nowNano-current.createdAtUnixNano > 1e9 {
			_ = c.prepackResponseWithTTL(qname, qtype, currentTTL, now)
		}
		c.packedResponseRefreshing.Store(false)
	}

	// Return the latest complete response (it may have a slightly stale TTL).
	packed = c.packedResponse.Load()
	if packed == nil {
		return nil
	}
	return packed.wire
}

// GetStaleResponse returns expired response if within stale-while-revalidate window.
// OPTIMISTIC CACHE (RFC 8767): This is used when cache is expired but still acceptable.
// staleTtl: stale window in seconds. 0 means never expire (always return stale response).
// Returns nil if cache is too stale (beyond staleTtl seconds).
// Caller should check refreshing flag and trigger background refresh if needed.
func (c *DnsCache) GetStaleResponse(now time.Time, staleTtl int) []byte {
	nowNano := now.UnixNano()
	deadlineNano := c.deadlineNano.Load()

	// Cache is not expired - should use GetPackedResponseWithApproximateTTL instead
	if deadlineNano > nowNano {
		return nil
	}

	// Check if within stale-while-revalidate window
	// staleTtl = 0 means never expire (always return stale response)
	if staleTtl > 0 {
		staleNano := deadlineNano + int64(staleTtl)*1e9
		if nowNano > staleNano {
			// Too stale, don't use
			return nil
		}
	}

	// Return stale response (better than nothing)
	packed := c.packedResponse.Load()
	if packed == nil {
		return nil
	}
	return packed.wire
}

// IsRefreshing checks if background refresh is in progress (optimistic cache).
// Returns true if this cache entry is expired and currently being refreshed.
func (c *DnsCache) IsRefreshing() bool {
	return c.refreshing.Load()
}

// MarkRefreshed marks the background refresh as complete (optimistic cache).
// This should be called after successfully refreshing the cache.
func (c *DnsCache) MarkRefreshed() {
	c.refreshing.Store(false)
}

// fillIntoWithTTLInPlace mutates req directly and should only be used when the
// caller has unique ownership of req and will not reuse it after the call,
// including on pack failure. A pack failure is reported to the caller instead
// of degrading into a silent cache miss: the caller turns it into an operator
// visible warning and then resolves the name upstream.
func (c *DnsCache) fillIntoWithTTLInPlace(req *dnsmessage.Msg, now time.Time) ([]byte, error) {
	if req == nil {
		return nil, nil
	}
	req.Answer = nil
	req.Rcode = dnsmessage.RcodeSuccess
	req.Response = true
	req.RecursionAvailable = true
	req.Truncated = false

	if c.Answer == nil {
		req.Compress = true
		resp, err := req.Pack()
		if err != nil {
			return nil, fmt.Errorf("pack cached DNS response without answer: %w", err)
		}
		return resp, nil
	}

	// Calculate remaining TTL based on the provided time
	remainingTTL := ttlFromDeadline(c.Deadline, now)

	// Copy answers with updated TTL. Shared with the pre-packed path so both
	// materializations apply the same record-level TTL policy.
	req.Answer = copySectionWithTTL(c.Answer, remainingTTL)

	req.Compress = true
	resp, err := req.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack cached DNS response: %w", err)
	}
	return resp, nil
}

// FillIntoWithTTL fills the DNS response with correct remaining TTL.
// This is the standard DNS cache behavior - TTL decreases over time.
// Returns the packed response bytes ready to send (with DNS ID = 0, caller should patch).
//
// This method preserves the caller's request on failure by operating on a copy.
// Hot paths that already own the message exclusively should use
// fillIntoWithTTLInPlace to avoid the extra allocation.
func (c *DnsCache) FillIntoWithTTL(req *dnsmessage.Msg, now time.Time) ([]byte, error) {
	if req == nil {
		return nil, nil
	}
	resp := req.Copy()
	if resp == nil {
		return nil, nil
	}
	return c.fillIntoWithTTLInPlace(resp, now)
}

func dnsAnswerIP(rr dnsmessage.RR) (netip.Addr, bool) {
	switch body := rr.(type) {
	case *dnsmessage.A:
		return netip.AddrFromSlice(body.A)
	case *dnsmessage.AAAA:
		return netip.AddrFromSlice(body.AAAA)
	default:
		return netip.Addr{}, false
	}
}
