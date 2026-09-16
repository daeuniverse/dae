/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@daeuniverse.org>
 */

package control

import (
	"context"
	"fmt"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/dns"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// backgroundRefresh performs asynchronous cache refresh for optimistic caching
// (RFC 8767). It runs after a stale entry has already been returned to the
// client, so a failure here must leave that entry in place: the client is
// currently being served from it, and evicting it would turn a refresh miss
// into a resolution failure for every subsequent query.
func (c *DnsController) backgroundRefresh(cacheKey string, dnsMessage *dnsmessage.Msg, req *udpRequest, upstreamIndex consts.DnsRequestOutboundIndex, upstream *dns.Upstream) {
	defer func() {
		if recovered := recover(); recovered != nil && c.log != nil {
			c.log.Errorf("panic in background DNS refresh: %v", recovered)
		}
	}()
	if upstreamIndex == consts.DnsRequestOutboundIndex_Reject || dnsMessage == nil {
		return
	}
	ctx, cancel := c.newWorkContext(5 * time.Second)
	defer cancel()
	// Always clear the refreshing flag. Do not look the entry up through
	// LookupDnsRespCache: that helper evicts expired-but-stale entries, which
	// would turn a refresh miss into a hard failure for every later query.
	defer func() {
		if cacheKey == "" {
			return
		}
		if val, ok := c.dnsCache.Load(cacheKey); ok {
			if cache, ok := val.(*DnsCache); ok && cache.IsRefreshing() {
				cache.MarkRefreshed()
			}
		}
	}()

	refresh := dnsMessage.Copy()
	if refresh == nil || len(refresh.Question) == 0 {
		return
	}
	refresh.Response = false
	refresh.Answer = nil
	refresh.Ns = nil
	// Keep the initiating query's Additional section: it carries the
	// request-side OPT (DO bit, EDNS Client Subnet, ...). Re-issuing the
	// refresh without it changes the query semantics, and caching the answer
	// under the original key would then replace a tailored answer with a
	// generic one (RFC 5625 §3/§4.4.2 transparent forwarding; RFC 8767
	// refresh continues the triggering request). The caller always passes a
	// query, never a response, so no response-owned records reach this path.

	if err := c.refreshDnsRespCache(ctx, refresh, req, upstream, cacheKey); err != nil &&
		c.log != nil && c.log.IsLevelEnabled(logrus.DebugLevel) {
		c.log.WithFields(logrus.Fields{
			"cacheKey": cacheKey,
			"error":    err,
		}).Debugf("background refresh failed")
	}
}

// isNegativeResponse reports whether msg is a complete negative answer from
// the configured upstream: NXDOMAIN or a NOERROR response without an answer
// of the requested type (RFC 2308 §2.2 - the answer section may still carry
// CNAME records aliasing to the empty target). Such answers supersede an
// expired positive under RFC 8767 §4, unlike SERVFAIL or timeouts, which must
// leave the old entry in place. Classification must mirror the cache
// admission rule, so a negative that cannot be stored (no SOA, zero negative
// lifetime) still triggers supersession instead of leaving the disproven
// positive in place. An NS-only authority without SOA is a referral, not an
// answer (RFC 2308 §2.2): it does not disprove a cached positive and must
// not supersede it.
func isNegativeResponse(msg *dnsmessage.Msg) bool {
	if msg == nil || !msg.Response || len(msg.Question) == 0 {
		return false
	}
	if msg.Rcode == dnsmessage.RcodeNameError {
		return true
	}
	if msg.Rcode != dnsmessage.RcodeSuccess {
		return false
	}
	if hasRelevantAnswer(msg, msg.Question[0]) {
		return false
	}
	if findAuthoritySoa(msg) == nil && authorityHasNs(msg) {
		return false
	}
	return true
}

// evictSupersededExpiredPositive removes an expired cache entry that an
// accepted negative refresh has superseded. Entries that were replaced with a
// fresher value in the meantime (pointer mismatch or a future deadline) are
// left untouched.
func (c *DnsController) evictSupersededExpiredPositive(cacheKey string) {
	if cacheKey == "" {
		return
	}
	now := time.Now()
	if v, ok := c.dnsCache.Load(cacheKey); ok {
		if entry, ok := v.(*DnsCache); ok && entry.Deadline.Before(now) {
			if c.log != nil && c.log.IsLevelEnabled(logrus.DebugLevel) {
				c.log.WithFields(logrus.Fields{
					"cacheKey": cacheKey,
				}).Debugln("background refresh returned a negative answer; dropping the superseded expired positive")
			}
			c.evictDnsRespCacheIfSame(cacheKey, entry)
		}
	}
}

// refreshDnsRespCache resolves request upstream and replaces the cached
// response under cacheKey. It never deletes the existing entry on failure.
func (c *DnsController) refreshDnsRespCache(ctx context.Context, request *dnsmessage.Msg, req *udpRequest, upstream *dns.Upstream, cacheKey string) error {
	data, err := request.Pack()
	if err != nil {
		return fmt.Errorf("pack DNS packet: %w", err)
	}
	resolution, err := c.resolveDNSUpstream(ctx, 0, req, data, upstream)
	if err != nil {
		return err
	}
	response := resolution.response.Copy()
	response.Id = request.Id
	response.Compress = true
	if cacheKey == "" {
		return nil
	}
	if isNegativeResponse(response) {
		// An accepted NXDOMAIN/NODATA is a successful negative resolution, not
		// a failed exchange: it must not leave the disproven positive in place
		// for the rest of the stale window (RFC 8767 §4 counts authoritative
		// NOERROR/NXDOMAIN as refreshed). SOA-carrying NODATA replaces the
		// entry through the normal negative-cache path (RFC 2308); other
		// negatives remove the superseded expired entry.
		if err := c.NormalizeAndCacheDnsResp_(response, cacheKey); err != nil {
			return err
		}
		c.evictSupersededExpiredPositive(cacheKey)
		return nil
	}
	return c.NormalizeAndCacheDnsResp_(response, cacheKey)
}
