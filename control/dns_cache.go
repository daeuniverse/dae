/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2023, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"math"
	"net/netip"
	"time"

	"github.com/mohae/deepcopy"
	"golang.org/x/net/dns/dnsmessage"
)

type DnsCache struct {
	DomainBitmap []uint32
	Answers      []dnsmessage.Resource
	Deadline     time.Time
}

func (c *DnsCache) FillInto(req *dnsmessage.Message) {
	req.Answers = deepcopy.Copy(c.Answers).([]dnsmessage.Resource)
	now := time.Now()
	// Set ttl.
	// TODO: give a domain hash (uint64) and let us to know whether the domain matches.
	for i := range req.Answers {
		// Use ceil because we want downstream to send requests to us after our cache missing.
		ttl := math.Ceil(c.Deadline.Sub(now).Seconds())
		if ttl < 0 {
			ttl = 0
		} else if ttl > math.MaxUint32 {
			ttl = math.MaxUint32 - 1
		}
		req.Answers[i].Header.TTL = uint32(ttl)
	}

	req.RCode = dnsmessage.RCodeSuccess
	req.Response = true
	req.RecursionAvailable = true
	req.Truncated = false
}

func (c *DnsCache) IncludeIp(ip netip.Addr) bool {
	for _, ans := range c.Answers {
		switch body := ans.Body.(type) {
		case *dnsmessage.AResource:
			if !ip.Is4() {
				continue
			}
			if netip.AddrFrom4(body.A) == ip {
				return true
			}
		case *dnsmessage.AAAAResource:
			if !ip.Is6() {
				continue
			}
			if netip.AddrFrom16(body.AAAA) == ip {
				return true
			}
		}
	}
	return false
}

func (c *DnsCache) IncludeAnyIp() bool {
	for _, ans := range c.Answers {
		switch ans.Body.(type) {
		case *dnsmessage.AResource, *dnsmessage.AAAAResource:
			return true
		}
	}
	return false
}
