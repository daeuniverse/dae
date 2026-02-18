/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net/netip"
	"sync/atomic"
	"time"

	dnsmessage "github.com/miekg/dns"
)

// Approximate TTL refresh threshold in seconds.
// Pre-packed response is refreshed when TTL difference exceeds this value.
// This balances between performance (avoiding frequent repack) and TTL accuracy.
const ttlRefreshThresholdSeconds = 5

type DnsCache struct {
	DomainBitmap     []uint32
	Answer           []dnsmessage.RR
	Deadline         time.Time
	OriginalDeadline time.Time // This field is not impacted by `fixed_domain_ttl`.
	lastRouteSyncNano atomic.Int64
	// PackedResponse is a pre-packed DNS response message with compression enabled.
	// This avoids repeated Pack() calls on cache hits, significantly reducing latency.
	// The packed response includes: Answer, Rcode=Success, Response=true, RecursionAvailable=true.
	// Note: DNS Message ID is NOT included and must be patched by the caller.
	PackedResponse []byte
	// packedResponseTTL is the TTL used when creating PackedResponse.
	// Used to determine if refresh is needed (when TTL difference > threshold).
	packedResponseTTL uint32
	// packedResponseCreatedAt is the time when PackedResponse was created.
	packedResponseCreatedAt atomic.Int64 // UnixNano
	// deadlineNano caches the Deadline as UnixNano for fast comparison.
	// This avoids time.Time method calls on every cache hit.
	deadlineNano atomic.Int64
}

func (c *DnsCache) MarkRouteBindingRefreshed(now time.Time) {
	c.lastRouteSyncNano.Store(now.UnixNano())
}

func (c *DnsCache) ShouldRefreshRouteBinding(now time.Time, minInterval time.Duration) bool {
	if minInterval <= 0 {
		return true
	}

	nowNano := now.UnixNano()
	last := c.lastRouteSyncNano.Load()
	if last != 0 && nowNano-last < minInterval.Nanoseconds() {
		return false
	}
	return c.lastRouteSyncNano.CompareAndSwap(last, nowNano)
}

func (c *DnsCache) FillInto(req *dnsmessage.Msg) {
	req.Answer = nil
	if c.Answer != nil {
		req.Answer = make([]dnsmessage.RR, len(c.Answer))
		for i, rr := range c.Answer {
			req.Answer[i] = dnsmessage.Copy(rr)
		}
	}
	req.Rcode = dnsmessage.RcodeSuccess
	req.Response = true
	req.RecursionAvailable = true
	req.Truncated = false
}

// FillIntoWithPacked fills the DNS response using pre-packed data if available.
// This is the fast path for cache hits - it avoids deep copy and packing overhead.
// Returns the packed response bytes (caller should patch the DNS ID if needed).
func (c *DnsCache) FillIntoWithPacked(req *dnsmessage.Msg) []byte {
	// Fast path: use pre-packed response
	if c.PackedResponse != nil {
		// Still need to unpack to fill the request message for logging/tracing
		// But we return the pre-packed bytes for sending
		return c.PackedResponse
	}
	// Slow path: fill and pack (should not happen if cache is properly initialized)
	c.FillInto(req)
	req.Compress = true
	b, err := req.Pack()
	if err != nil {
		return nil
	}
	return b
}

func (c *DnsCache) Clone() *DnsCache {
	newCache := &DnsCache{
		Deadline:         c.Deadline,
		OriginalDeadline: c.OriginalDeadline,
	}

	if c.DomainBitmap != nil {
		newCache.DomainBitmap = make([]uint32, len(c.DomainBitmap))
		copy(newCache.DomainBitmap, c.DomainBitmap)
	}

	if c.Answer != nil {
		newCache.Answer = make([]dnsmessage.RR, len(c.Answer))
		for i, rr := range c.Answer {
			newCache.Answer[i] = dnsmessage.Copy(rr)
		}
	}

	if c.PackedResponse != nil {
		newCache.PackedResponse = make([]byte, len(c.PackedResponse))
		copy(newCache.PackedResponse, c.PackedResponse)
		newCache.packedResponseTTL = c.packedResponseTTL
		newCache.packedResponseCreatedAt.Store(c.packedResponseCreatedAt.Load())
	}

	newCache.deadlineNano.Store(c.deadlineNano.Load())
	newCache.lastRouteSyncNano.Store(c.lastRouteSyncNano.Load())

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
	
	// Calculate remaining TTL
	deadlineNano := c.Deadline.UnixNano()
	nowNano := now.UnixNano()
	
	var ttl uint32
	if deadlineNano > nowNano {
		ttlSeconds := (deadlineNano - nowNano) / 1e9
		if ttlSeconds < 1 {
			ttl = 1
		} else {
			ttl = uint32(ttlSeconds)
		}
	} else {
		ttl = 0
	}
	
	return c.prepackResponseWithTTL(qname, qtype, ttl, now)
}

// prepackResponseWithTTL creates pre-packed response with specified TTL
func (c *DnsCache) prepackResponseWithTTL(qname string, qtype uint16, ttl uint32, now time.Time) error {
	// Create a minimal DNS response message
	msg := &dnsmessage.Msg{
		MsgHdr: dnsmessage.MsgHdr{
			Rcode:              dnsmessage.RcodeSuccess,
			Response:           true,
			RecursionAvailable: true,
			Truncated:          false,
		},
		Question: []dnsmessage.Question{
			{Name: qname, Qtype: qtype, Qclass: dnsmessage.ClassINET},
		},
		Compress: true,
	}
	
	// Copy answers with calculated TTL
	if c.Answer != nil {
		msg.Answer = make([]dnsmessage.RR, len(c.Answer))
		for i, rr := range c.Answer {
			copiedRR := dnsmessage.Copy(rr)
			copiedRR.Header().Ttl = ttl
			msg.Answer[i] = copiedRR
		}
	}
	
	// Pack the message
	packed, err := msg.Pack()
	if err != nil {
		return err
	}
	
	c.PackedResponse = packed
	c.packedResponseTTL = ttl
	c.packedResponseCreatedAt.Store(now.UnixNano())
	return nil
}

// GetPackedResponseWithApproximateTTL returns pre-packed response with approximate TTL.
// OPTIMIZED: Uses atomic operations and UnixNano comparison to avoid time.Time method calls.
// Fast path: returns cached pre-packed response if TTL difference is within threshold.
// Slow path: refreshes pre-packed response if TTL has changed significantly.
func (c *DnsCache) GetPackedResponseWithApproximateTTL(qname string, qtype uint16, now time.Time) []byte {
	nowNano := now.UnixNano()
	deadlineNano := c.deadlineNano.Load()
	
	// Fast expiry check using integer comparison
	if deadlineNano <= nowNano {
		return nil // Expired
	}
	
	// Calculate current TTL in seconds (avoid float operations)
	currentTTL := uint32((deadlineNano - nowNano) / 1e9)
	if currentTTL < 1 {
		currentTTL = 1
	}
	
	// Fast path: use pre-packed response if TTL difference is acceptable
	if c.PackedResponse != nil {
		// Use cached response if TTL difference is within threshold
		// Allow absolute difference comparison without float
		cachedTTL := c.packedResponseTTL
		if cachedTTL >= currentTTL {
			if cachedTTL-currentTTL <= ttlRefreshThresholdSeconds {
				return c.PackedResponse
			}
		} else if currentTTL-cachedTTL <= ttlRefreshThresholdSeconds {
			return c.PackedResponse
		}
	}
	
	// Slow path: refresh pre-packed response with new TTL
	// Use atomic to ensure only one goroutine refreshes per second
	createdNano := c.packedResponseCreatedAt.Load()
	if nowNano-createdNano > 1e9 { // 1 second in nanoseconds
		_ = c.prepackResponseWithTTL(qname, qtype, currentTTL, now)
	}
	
	return c.PackedResponse
}

// FillIntoWithTTL fills the DNS response with correct remaining TTL.
// This is the standard DNS cache behavior - TTL decreases over time.
// Returns the packed response bytes ready to send (with DNS ID = 0, caller should patch).
func (c *DnsCache) FillIntoWithTTL(req *dnsmessage.Msg, now time.Time) []byte {
	req.Answer = nil
	req.Rcode = dnsmessage.RcodeSuccess
	req.Response = true
	req.RecursionAvailable = true
	req.Truncated = false
	
	if c.Answer == nil {
		req.Compress = true
		b, _ := req.Pack()
		return b
	}
	
	// Calculate remaining TTL based on the provided time
	var remainingTTL uint32
	if c.Deadline.After(now) {
		remainingTTL = uint32(c.Deadline.Sub(now).Seconds())
		if remainingTTL < 1 {
			remainingTTL = 1 // Minimum TTL of 1 second
		}
	} else {
		remainingTTL = 0 // Expired
	}
	
	// Copy answers with updated TTL
	req.Answer = make([]dnsmessage.RR, len(c.Answer))
	for i, rr := range c.Answer {
		copiedRR := dnsmessage.Copy(rr)
		// Update TTL to remaining time
		copiedRR.Header().Ttl = remainingTTL
		req.Answer[i] = copiedRR
	}
	
	req.Compress = true
	b, err := req.Pack()
	if err != nil {
		return nil
	}
	return b
}

func (c *DnsCache) IncludeIp(ip netip.Addr) bool {
	for _, ans := range c.Answer {
		switch body := ans.(type) {
		case *dnsmessage.A:
			if !ip.Is4() {
				continue
			}
			if a, ok := netip.AddrFromSlice(body.A); ok && a == ip {
				return true
			}
		case *dnsmessage.AAAA:
			if !ip.Is6() {
				continue
			}
			if a, ok := netip.AddrFromSlice(body.AAAA); ok && a == ip {
				return true
			}
		}
	}
	return false
}

func (c *DnsCache) IncludeAnyIp() bool {
	for _, ans := range c.Answer {
		switch ans.(type) {
		case *dnsmessage.A, *dnsmessage.AAAA:
			return true
		}
	}
	return false
}
