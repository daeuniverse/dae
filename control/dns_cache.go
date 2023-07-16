/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2023, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net/netip"
	"time"

	dnsmessage "github.com/miekg/dns"
	"github.com/mohae/deepcopy"
)

type DnsCache struct {
	DomainBitmap     []uint32
	Answer           []dnsmessage.RR
	Deadline         time.Time
	OriginalDeadline time.Time // This field is not impacted by `fixed_domain_ttl`.
}

func (c *DnsCache) FillInto(req *dnsmessage.Msg) {
	req.Answer = deepcopy.Copy(c.Answer).([]dnsmessage.RR)
	req.Rcode = dnsmessage.RcodeSuccess
	req.Response = true
	req.RecursionAvailable = true
	req.Truncated = false
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
