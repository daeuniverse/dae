/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@daeuniverse.org>
 */

package control

import (
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/dns"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// backgroundRefresh performs asynchronous cache refresh for optimistic caching (RFC 8767).
// This is called when a stale cache entry is returned to the client.
// The refresh happens in the background without blocking the client request.
func (c *DnsController) backgroundRefresh(cacheKey string, dnsMessage *dnsmessage.Msg, req *udpRequest, upstreamIndex consts.DnsRequestOutboundIndex, upstream *dns.Upstream) {
	defer func() {
		if r := recover(); r != nil {
			c.log.Errorf("panic in backgroundRefresh: %v", r)
		}
	}()

	// Background refresh must stop when the controller is closing, otherwise
	// reload can get stuck waiting for stale refresh work to time out.
	ctx, cancel := c.newWorkContext(5 * time.Second)
	defer cancel()

	// Ensure refreshing flag is cleared even if refresh fails
	// This prevents permanent deadlock if background refresh fails
	defer func() {
		if cache := c.LookupDnsRespCache(cacheKey, false); cache != nil {
			if cache.IsRefreshing() {
				cache.MarkRefreshed()
			}
		}
	}()

	if upstreamIndex == consts.DnsRequestOutboundIndex_Reject {
		return
	}

	refreshMsg := dnsMessage.Copy()
	if refreshMsg == nil || len(refreshMsg.Question) == 0 {
		return
	}
	refreshMsg.Response = false
	refreshMsg.Answer = nil
	refreshMsg.Ns = nil
	data, err := refreshMsg.Pack()
	if err != nil {
		if c.log.IsLevelEnabled(logrus.DebugLevel) {
			c.log.WithFields(logrus.Fields{
				"cacheKey": cacheKey,
				"error":    err,
			}).Debugf("background refresh failed to pack query")
		}
		return
	}

	// Perform the actual DNS resolution and bypass the stale cache entry that
	// triggered this refresh. Re-entering handleWithResponseWriter_ here would
	// hit the same stale cache and mark the refresh complete without contacting
	// upstream.
	baseCacheKey := dnsCacheBaseKey(cacheKey)
	if err := c.dialSend(ctx, 0, req, data, refreshMsg.Id, upstream, false, nil, cacheKey, baseCacheKey); err != nil {
		if c.log.IsLevelEnabled(logrus.DebugLevel) {
			c.log.WithFields(logrus.Fields{
				"cacheKey": cacheKey,
				"error":    err,
			}).Debugf("background refresh failed")
		}
		return
	}

	if c.log.IsLevelEnabled(logrus.DebugLevel) {
		c.log.WithFields(logrus.Fields{
			"cacheKey": cacheKey,
		}).Debugf("background refresh completed")
	}
}
