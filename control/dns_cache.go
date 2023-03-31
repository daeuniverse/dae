/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2023, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"github.com/mohae/deepcopy"
	"golang.org/x/net/dns/dnsmessage"
	"net/netip"
	"time"
)

type DnsCache struct {
	DomainBitmap []uint32
	Answers      []dnsmessage.Resource
	Deadline     time.Time
}

func (c *DnsCache) FillInto(req *dnsmessage.Message) {
	req.Answers = deepcopy.Copy(c.Answers).([]dnsmessage.Resource)
	// No need to align because of no flipping now.
	//// Align question and answer Name.
	//if len(req.Questions) > 0 {
	//	q := req.Questions[0]
	//	for i := range req.Answers {
	//		if strings.EqualFold(req.Answers[i].Header.Name.String(), q.Name.String()) {
	//			req.Answers[i].Header.Name.Data = q.Name.Data
	//		}
	//	}
	//}
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
