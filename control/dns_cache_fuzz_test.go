/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"testing"
	"time"

	dnsmessage "github.com/miekg/dns"
)

func FuzzDnsCache_FillIntoWithTTL(f *testing.F) {
	cache := &DnsCache{
		Answer: []dnsmessage.RR{
			&dnsmessage.A{
				Hdr: dnsmessage.RR_Header{Name: "example.", Rrtype: dnsmessage.TypeA, Class: dnsmessage.ClassINET, Ttl: 300},
				A:   []byte{1, 2, 3, 4},
			},
		},
		Deadline: time.Now().Add(5 * time.Minute),
	}
	now := time.Now()
	f.Add("example.com.", uint16(1))
	f.Add("test.example.org.", uint16(28))
	f.Add("", uint16(0))
	f.Add("a.b.c.d.e.f.g.h.", uint16(255))
	f.Add("xn--n3h.com.", uint16(1))

	f.Fuzz(func(t *testing.T, qname string, qtype uint16) {
		req := new(dnsmessage.Msg)
		req.SetQuestion(qname, qtype)
		_ = cache.FillIntoWithTTL(req, now)
	})
}

func FuzzDnsCache_FillInto(f *testing.F) {
	cache := &DnsCache{
		Answer: []dnsmessage.RR{
			&dnsmessage.A{
				Hdr: dnsmessage.RR_Header{Name: "example.", Rrtype: dnsmessage.TypeA, Class: dnsmessage.ClassINET, Ttl: 300},
				A:   []byte{1, 2, 3, 4},
			},
		},
		Deadline: time.Now().Add(5 * time.Minute),
	}
	f.Add("example.com.", uint16(1))
	f.Add("", uint16(0))

	f.Fuzz(func(t *testing.T, qname string, qtype uint16) {
		req := new(dnsmessage.Msg)
		req.SetQuestion(qname, qtype)
		cache.FillInto(req)
	})
}
