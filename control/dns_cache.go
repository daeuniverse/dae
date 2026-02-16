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

type DnsCache struct {
	DomainBitmap     []uint32
	Answer           []dnsmessage.RR
	Deadline         time.Time
	OriginalDeadline time.Time // This field is not impacted by `fixed_domain_ttl`.
	lastRouteSyncNano atomic.Int64
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

	newCache.lastRouteSyncNano.Store(c.lastRouteSyncNano.Load())

	return newCache
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
