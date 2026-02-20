/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@daeuniverse.org>
 */

package control

import (
"context"
"time"

dnsmessage "github.com/miekg/dns"
"github.com/sirupsen/logrus"
)

// backgroundRefresh performs asynchronous cache refresh for optimistic caching (RFC 8767).
// This is called when a stale cache entry is returned to the client.
// The refresh happens in the background without blocking the client request.
func (c *DnsController) backgroundRefresh(cacheKey string, dnsMessage *dnsmessage.Msg, req *udpRequest) {
defer func() {
if r := recover(); r != nil {
c.log.Errorf("panic in backgroundRefresh: %v", r)
}
}()

// Create a background context with timeout
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()

// Perform the actual DNS resolution
// This will update the cache with fresh data
_, err := c.resolveForSingleflight(ctx, dnsMessage, req)
if err != nil {
c.log.WithFields(logrus.Fields{
"cacheKey": cacheKey,
"error":    err,
}).Debugf("background refresh failed")
return
}

// Mark refresh complete
if cache := c.LookupDnsRespCache(cacheKey, false); cache != nil {
cache.MarkRefreshed()
}

c.log.WithFields(logrus.Fields{
"cacheKey": cacheKey,
}).Debugf("background refresh completed")
}
