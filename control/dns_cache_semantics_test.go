/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net"
	"testing"
	"time"

	"github.com/daeuniverse/dae/config"
	dnsmessage "github.com/miekg/dns"
)

func newSemanticsController(t *testing.T) *DnsController {
	t.Helper()
	return newCorpusControllerWithDefaultChooser(t, &config.Dns{
		Routing: config.DnsRouting{
			Request:  config.DnsRequestRouting{Fallback: config.FunctionOrString("asis")},
			Response: config.DnsResponseRouting{Fallback: config.FunctionOrString("accept")},
		},
	})
}

func storedEntry(t *testing.T, c *DnsController, cacheKey string) *DnsCache {
	t.Helper()
	v, ok := c.dnsCache.Load(cacheKey)
	if !ok {
		t.Fatalf("no cache entry for %q", cacheKey)
	}
	entry, ok := v.(*DnsCache)
	if !ok {
		t.Fatalf("cache entry for %q has type %T", cacheKey, v)
	}
	return entry
}

// TestPositiveEntryLifetimeUsesMinimumRecordTtl pins RFC 2181/4035 lifetime
// semantics: a short-lived A following a long-lived CNAME must expire the
// whole entry, not extend the A for the CNAME's lifetime.
func TestPositiveEntryLifetimeUsesMinimumRecordTtl(t *testing.T) {
	c := newSemanticsController(t)
	const cacheKey = "semantics-min-ttl|1.1.1.1"

	msg := dnsAResponseMsg("mixed.example.com.", "198.51.100.10")
	msg.Question[0].Qtype = dnsmessage.TypeCNAME
	msg.Answer = []dnsmessage.RR{
		&dnsmessage.CNAME{
			Hdr:    dnsmessage.RR_Header{Name: "mixed.example.com.", Rrtype: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, Ttl: 3600},
			Target: "target.example.com.",
		},
		&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{Name: "target.example.com.", Rrtype: dnsmessage.TypeA, Class: dnsmessage.ClassINET, Ttl: 30},
			A:   net.ParseIP("198.51.100.10").To4(),
		},
	}
	msg.Response = true
	if err := c.NormalizeAndCacheDnsResp_(msg, cacheKey); err != nil {
		t.Fatalf("NormalizeAndCacheDnsResp_: %v", err)
	}
	entry := storedEntry(t, c, cacheKey)
	remaining := time.Until(entry.Deadline)
	if remaining > 35*time.Second || remaining <= 0 {
		t.Fatalf("entry deadline = %v (remaining %v), want ~30s", entry.Deadline, remaining)
	}
}

// TestNodataNegativeLifetimeUsesSoa pins RFC 2308: NODATA lifetime follows
// min(SOA TTL, SOA.MINIMUM) with a cap; the SOA is retained in the entry.
func TestNodataNegativeLifetimeUsesSoa(t *testing.T) {
	c := newSemanticsController(t)
	const cacheKey = "semantics-nodata|1.1.1.1"

	msg := new(dnsmessage.Msg)
	msg.SetQuestion("empty.example.com.", dnsmessage.TypeA)
	msg.Response = true
	msg.Rcode = dnsmessage.RcodeSuccess
	msg.Ns = []dnsmessage.RR{
		&dnsmessage.SOA{
			Hdr:     dnsmessage.RR_Header{Name: "example.com.", Rrtype: dnsmessage.TypeSOA, Class: dnsmessage.ClassINET, Ttl: 300},
			Ns:      "ns1.example.com.",
			Mbox:    "hostmaster.example.com.",
			Serial:  1,
			Refresh: 60,
			Retry:   60,
			Expire:  600,
			Minttl:  10,
		},
	}
	if err := c.NormalizeAndCacheDnsResp_(msg, cacheKey); err != nil {
		t.Fatalf("NormalizeAndCacheDnsResp_: %v", err)
	}
	entry := storedEntry(t, c, cacheKey)
	remaining := time.Until(entry.Deadline)
	if remaining > 15*time.Second || remaining <= 0 {
		t.Fatalf("NODATA deadline = %v (remaining %v), want ~10s (SOA.MINIMUM)", entry.Deadline, remaining)
	}
	if len(entry.NS) == 0 {
		t.Fatal("NODATA entry must retain the SOA in its authority section")
	}
}

// TestNodataLifetimeBoundsRetainedRecordTtls checks both entry deadlines and
// wire TTLs, including zero-TTL records and the OPT pseudo-record exception.
func TestNodataLifetimeBoundsRetainedRecordTtls(t *testing.T) {
	for _, tt := range []struct {
		name    string
		section string
		ttl     uint32
		wantTtl uint32
	}{
		{name: "short_authority", section: "authority", ttl: 180, wantTtl: 180},
		{name: "short_additional", section: "additional", ttl: 90, wantTtl: 90},
		{name: "zero_authority", section: "authority", ttl: 0, wantTtl: 0},
		{name: "zero_additional", section: "additional", ttl: 0, wantTtl: 0},
		{name: "opt_is_not_a_ttl", wantTtl: 300},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := newSemanticsController(t)
			msg := new(dnsmessage.Msg)
			msg.SetQuestion("empty.example.com.", dnsmessage.TypeA)
			msg.Response = true
			msg.Ns = []dnsmessage.RR{&dnsmessage.SOA{
				Hdr:    dnsmessage.RR_Header{Name: "example.com.", Rrtype: dnsmessage.TypeSOA, Class: dnsmessage.ClassINET, Ttl: 300},
				Ns:     "ns.example.com.",
				Mbox:   "hostmaster.example.com.",
				Minttl: 300,
			}}
			switch tt.section {
			case "authority":
				msg.Ns = append(msg.Ns, &dnsmessage.NSEC{
					Hdr:        dnsmessage.RR_Header{Name: "empty.example.com.", Rrtype: dnsmessage.TypeNSEC, Class: dnsmessage.ClassINET, Ttl: tt.ttl},
					NextDomain: "next.example.com.",
					TypeBitMap: []uint16{dnsmessage.TypeAAAA, dnsmessage.TypeRRSIG, dnsmessage.TypeNSEC},
				})
			case "additional":
				msg.Extra = append(msg.Extra, &dnsmessage.A{
					Hdr: dnsmessage.RR_Header{Name: "ns.example.com.", Rrtype: dnsmessage.TypeA, Class: dnsmessage.ClassINET, Ttl: tt.ttl},
					A:   net.ParseIP("198.51.100.53").To4(),
				})
			}
			msg.SetEdns0(1232, false)

			const cacheKey = "semantics-nodata-record-ttl"
			before := time.Now()
			if err := c.NormalizeAndCacheDnsResp_(msg, cacheKey); err != nil {
				t.Fatal(err)
			}
			after := time.Now()
			if tt.wantTtl == 0 {
				if _, ok := c.dnsCache.Load(cacheKey); ok {
					t.Fatal("negative response containing a zero-TTL record must not be cached")
				}
				return
			}

			entry := storedEntry(t, c, cacheKey)
			lifetime := time.Duration(tt.wantTtl) * time.Second
			if entry.Deadline.Before(before.Add(lifetime)) || entry.Deadline.After(after.Add(lifetime)) {
				t.Fatalf("deadline %v does not match lifetime %v", entry.Deadline, lifetime)
			}
			var replay dnsmessage.Msg
			if err := replay.Unpack(entry.GetPackedResponseWithApproximateTTL(msg.Question[0].Name, dnsmessage.TypeA, after)); err != nil {
				t.Fatal(err)
			}
			if len(replay.Ns) != len(msg.Ns) || len(replay.Extra) != len(msg.Extra) {
				t.Fatal("cached response lost retained records")
			}
			for _, section := range [][]dnsmessage.RR{replay.Ns, replay.Extra} {
				for _, rr := range section {
					if rr.Header().Rrtype != dnsmessage.TypeOPT && rr.Header().Ttl > tt.wantTtl {
						t.Fatalf("cached %s TTL = %d, exceeds %d", dnsmessage.TypeToString[rr.Header().Rrtype], rr.Header().Ttl, tt.wantTtl)
					}
				}
			}
			if opt := replay.IsEdns0(); opt == nil || opt.UDPSize() != 1232 || opt.Hdr.Ttl != 0 {
				t.Fatalf("cached OPT changed: %v", opt)
			}
		})
	}
}

// TestCnameOnlyNodataUsesSoaNegativeLifetime pins RFC 2308 §2.2: NODATA means
// no answer of the requested type, so a CNAME-only answer for an A query is a
// terminal negative. Its lifetime must come from the SOA (TTL/MINIMUM/cap and
// retained-record bounds), not from the CNAME's own TTL through the positive
// path: here SOA TTL 86400 and MINIMUM 120 must win over the CNAME TTL of
// 3600, and the replayed message must keep the CNAME and the negative proof.
func TestCnameOnlyNodataUsesSoaNegativeLifetime(t *testing.T) {
	c := newSemanticsController(t)
	msg := new(dnsmessage.Msg)
	msg.SetQuestion("alias.example.com.", dnsmessage.TypeA)
	msg.Response = true
	msg.Answer = []dnsmessage.RR{&dnsmessage.CNAME{
		Hdr:    dnsmessage.RR_Header{Name: "alias.example.com.", Rrtype: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, Ttl: 3600},
		Target: "empty.example.com.",
	}}
	msg.Ns = []dnsmessage.RR{&dnsmessage.SOA{
		Hdr:    dnsmessage.RR_Header{Name: "example.com.", Rrtype: dnsmessage.TypeSOA, Class: dnsmessage.ClassINET, Ttl: 86400},
		Ns:     "ns.example.com.",
		Mbox:   "hostmaster.example.com.",
		Minttl: 120,
	}}

	const cacheKey = "semantics-cname-nodata"
	before := time.Now()
	if err := c.NormalizeAndCacheDnsResp_(msg, cacheKey); err != nil {
		t.Fatal(err)
	}
	after := time.Now()
	entry := storedEntry(t, c, cacheKey)
	lifetime := 120 * time.Second
	if entry.Deadline.Before(before.Add(lifetime)) || entry.Deadline.After(after.Add(lifetime)) {
		t.Fatalf("deadline %v does not match SOA.MINIMUM lifetime %v", entry.Deadline, lifetime)
	}

	var replay dnsmessage.Msg
	raw := entry.GetPackedResponseWithApproximateTTL(msg.Question[0].Name, dnsmessage.TypeA, after)
	if err := replay.Unpack(raw); err != nil {
		t.Fatal(err)
	}
	if len(replay.Answer) != 1 || replay.Answer[0].Header().Rrtype != dnsmessage.TypeCNAME {
		t.Fatalf("replay lost the CNAME answer: %v", replay.Answer)
	}
	if len(replay.Ns) != 1 || replay.Ns[0].Header().Rrtype != dnsmessage.TypeSOA {
		t.Fatal("replay lost the negative proof SOA")
	}
	for _, section := range [][]dnsmessage.RR{replay.Answer, replay.Ns} {
		for _, rr := range section {
			if rr.Header().Ttl > 120 {
				t.Fatalf("cached %s TTL = %d exceeds negative lifetime 120", dnsmessage.TypeToString[rr.Header().Rrtype], rr.Header().Ttl)
			}
		}
	}
}

// TestCnameOnlyWithoutSoaIsNotCached pins RFC 2308 §5: a CNAME-only NODATA
// without authority SOA must not be cached as if it were a positive answer.
func TestCnameOnlyWithoutSoaIsNotCached(t *testing.T) {
	c := newSemanticsController(t)
	msg := new(dnsmessage.Msg)
	msg.SetQuestion("alias.example.com.", dnsmessage.TypeA)
	msg.Response = true
	msg.Answer = []dnsmessage.RR{&dnsmessage.CNAME{
		Hdr:    dnsmessage.RR_Header{Name: "alias.example.com.", Rrtype: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, Ttl: 3600},
		Target: "empty.example.com.",
	}}
	const cacheKey = "semantics-cname-nodata-nosoa"
	if err := c.NormalizeAndCacheDnsResp_(msg, cacheKey); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.dnsCache.Load(cacheKey); ok {
		t.Fatal("SOA-less CNAME-only NODATA must not be cached")
	}
}

// TestCnameQueryAnswerStaysPositive guards the relevance test: a CNAME answer
// to a CNAME question is a genuine positive answer and keeps its own TTL.
func TestCnameQueryAnswerStaysPositive(t *testing.T) {
	c := newSemanticsController(t)
	msg := new(dnsmessage.Msg)
	msg.SetQuestion("alias.example.com.", dnsmessage.TypeCNAME)
	msg.Response = true
	msg.Answer = []dnsmessage.RR{&dnsmessage.CNAME{
		Hdr:    dnsmessage.RR_Header{Name: "alias.example.com.", Rrtype: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, Ttl: 3600},
		Target: "target.example.com.",
	}}

	const cacheKey = "semantics-cname-positive"
	before := time.Now()
	if err := c.NormalizeAndCacheDnsResp_(msg, cacheKey); err != nil {
		t.Fatal(err)
	}
	after := time.Now()
	entry := storedEntry(t, c, cacheKey)
	lifetime := 3600 * time.Second
	if entry.Deadline.Before(before.Add(lifetime)) || entry.Deadline.After(after.Add(lifetime)) {
		t.Fatalf("deadline %v does not match CNAME TTL lifetime %v", entry.Deadline, lifetime)
	}
}

// TestCnameChainWithRequestedTypeStaysPositive guards the relevance test: once
// the answer chain reaches the requested type, the response is positive even
// though a CNAME is present.
func TestCnameChainWithRequestedTypeStaysPositive(t *testing.T) {
	c := newSemanticsController(t)
	msg := new(dnsmessage.Msg)
	msg.SetQuestion("alias.example.com.", dnsmessage.TypeA)
	msg.Response = true
	msg.Answer = []dnsmessage.RR{
		&dnsmessage.CNAME{
			Hdr:    dnsmessage.RR_Header{Name: "alias.example.com.", Rrtype: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, Ttl: 3600},
			Target: "target.example.com.",
		},
		&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{Name: "target.example.com.", Rrtype: dnsmessage.TypeA, Class: dnsmessage.ClassINET, Ttl: 30},
			A:   net.ParseIP("198.51.100.10").To4(),
		},
	}

	const cacheKey = "semantics-cname-chain"
	before := time.Now()
	if err := c.NormalizeAndCacheDnsResp_(msg, cacheKey); err != nil {
		t.Fatal(err)
	}
	after := time.Now()
	entry := storedEntry(t, c, cacheKey)
	lifetime := 30 * time.Second
	if entry.Deadline.Before(before.Add(lifetime)) || entry.Deadline.After(after.Add(lifetime)) {
		t.Fatalf("deadline %v does not match shortest record TTL %v", entry.Deadline, lifetime)
	}
}

// TestUncacheableNegativesAreNotStored pins RFC 2308 §5: no-SOA NODATA,
// NS-only referrals and NXDOMAIN must not create cache entries.
func TestUncacheableNegativesAreNotStored(t *testing.T) {
	c := newSemanticsController(t)

	// NXDOMAIN without SOA handling: never stored (packed cache replays only
	// success responses).
	nx := new(dnsmessage.Msg)
	nx.SetQuestion("gone.example.com.", dnsmessage.TypeA)
	nx.Response = true
	nx.Rcode = dnsmessage.RcodeNameError
	if err := c.NormalizeAndCacheDnsResp_(nx, "semantics-nx"); err != nil {
		t.Fatalf("NormalizeAndCacheDnsResp_(nx): %v", err)
	}
	if _, ok := c.dnsCache.Load("semantics-nx"); ok {
		t.Fatal("NXDOMAIN must not be cached")
	}

	// NODATA without an SOA is not a cacheable negative.
	noSoa := new(dnsmessage.Msg)
	noSoa.SetQuestion("empty-no-soa.example.com.", dnsmessage.TypeA)
	noSoa.Response = true
	if err := c.NormalizeAndCacheDnsResp_(noSoa, "semantics-no-soa"); err != nil {
		t.Fatalf("NormalizeAndCacheDnsResp_(no-soa): %v", err)
	}
	if _, ok := c.dnsCache.Load("semantics-no-soa"); ok {
		t.Fatal("SOA-less NODATA must not be cached")
	}

	// An NS-only authority is a referral, not a negative answer.
	referral := new(dnsmessage.Msg)
	referral.SetQuestion("delegated.example.com.", dnsmessage.TypeA)
	referral.Response = true
	referral.Ns = []dnsmessage.RR{
		&dnsmessage.NS{
			Hdr: dnsmessage.RR_Header{Name: "example.com.", Rrtype: dnsmessage.TypeNS, Class: dnsmessage.ClassINET, Ttl: 3600},
			Ns:  "ns1.other.example.",
		},
	}
	if err := c.NormalizeAndCacheDnsResp_(referral, "semantics-referral"); err != nil {
		t.Fatalf("NormalizeAndCacheDnsResp_(referral): %v", err)
	}
	if _, ok := c.dnsCache.Load("semantics-referral"); ok {
		t.Fatal("NS-only referral must not be cached as a negative")
	}
}

// TestIsNegativeResponseClassification pins the refresh supersession
// classifier (RFC 2308 §2.2 relevance): it must mirror the cache admission
// rule so an uncacheable CNAME-only NODATA still supersedes an expired
// positive under RFC 8767 §4, while genuine positives and ANY answers never
// count as negative.
func TestIsNegativeResponseClassification(t *testing.T) {
	soa := &dnsmessage.SOA{
		Hdr:    dnsmessage.RR_Header{Name: "example.com.", Rrtype: dnsmessage.TypeSOA, Class: dnsmessage.ClassINET, Ttl: 300},
		Ns:     "ns.example.com.",
		Mbox:   "hostmaster.example.com.",
		Minttl: 300,
	}
	cname := func(name string) *dnsmessage.CNAME {
		return &dnsmessage.CNAME{
			Hdr:    dnsmessage.RR_Header{Name: name, Rrtype: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, Ttl: 3600},
			Target: "gone.example.com.",
		}
	}
	a := &dnsmessage.A{
		Hdr: dnsmessage.RR_Header{Name: "alias.example.com.", Rrtype: dnsmessage.TypeA, Class: dnsmessage.ClassINET, Ttl: 300},
		A:   net.ParseIP("198.51.100.9").To4(),
	}

	for _, tt := range []struct {
		name  string
		build func() *dnsmessage.Msg
		want  bool
	}{
		{name: "nil", build: func() *dnsmessage.Msg { return nil }, want: false},
		{name: "not_a_response", build: func() *dnsmessage.Msg {
			msg := new(dnsmessage.Msg)
			msg.SetQuestion("alias.example.com.", dnsmessage.TypeA)
			return msg
		}, want: false},
		{name: "nxdomain", build: func() *dnsmessage.Msg {
			msg := new(dnsmessage.Msg)
			msg.SetQuestion("gone.example.com.", dnsmessage.TypeA)
			msg.Response = true
			msg.Rcode = dnsmessage.RcodeNameError
			return msg
		}, want: true},
		{name: "servfail", build: func() *dnsmessage.Msg {
			msg := new(dnsmessage.Msg)
			msg.SetQuestion("alias.example.com.", dnsmessage.TypeA)
			msg.Response = true
			msg.Rcode = dnsmessage.RcodeServerFailure
			return msg
		}, want: false},
		{name: "empty_noerror_with_soa", build: func() *dnsmessage.Msg {
			msg := new(dnsmessage.Msg)
			msg.SetQuestion("empty.example.com.", dnsmessage.TypeA)
			msg.Response = true
			msg.Ns = []dnsmessage.RR{soa}
			return msg
		}, want: true},
		{name: "cname_only_with_ns_no_soa", build: func() *dnsmessage.Msg {
			// A CNAME answer with an NS-only (SOA-less) authority is a
			// referral-shaped response, not a terminal negative: it must not
			// supersede a cached positive.
			msg := new(dnsmessage.Msg)
			msg.SetQuestion("alias.example.com.", dnsmessage.TypeA)
			msg.Response = true
			msg.Answer = []dnsmessage.RR{cname("alias.example.com.")}
			msg.Ns = []dnsmessage.RR{&dnsmessage.NS{
				Hdr: dnsmessage.RR_Header{Name: "example.com.", Rrtype: dnsmessage.TypeNS, Class: dnsmessage.ClassINET, Ttl: 3600},
				Ns:  "ns1.other.example.",
			}}
			return msg
		}, want: false},
		{name: "cname_only", build: func() *dnsmessage.Msg {
			msg := new(dnsmessage.Msg)
			msg.SetQuestion("alias.example.com.", dnsmessage.TypeA)
			msg.Response = true
			msg.Answer = []dnsmessage.RR{cname("alias.example.com.")}
			return msg
		}, want: true},
		{name: "empty_noerror", build: func() *dnsmessage.Msg {
			msg := new(dnsmessage.Msg)
			msg.SetQuestion("empty.example.com.", dnsmessage.TypeA)
			msg.Response = true
			return msg
		}, want: true},
		{name: "cname_only_with_soa", build: func() *dnsmessage.Msg {
			msg := new(dnsmessage.Msg)
			msg.SetQuestion("alias.example.com.", dnsmessage.TypeA)
			msg.Response = true
			msg.Answer = []dnsmessage.RR{cname("alias.example.com.")}
			msg.Ns = []dnsmessage.RR{soa}
			return msg
		}, want: true},
		{name: "cname_chain_with_target_type", build: func() *dnsmessage.Msg {
			msg := new(dnsmessage.Msg)
			msg.SetQuestion("alias.example.com.", dnsmessage.TypeA)
			msg.Response = true
			msg.Answer = []dnsmessage.RR{cname("alias.example.com."), a}
			return msg
		}, want: false},
		{name: "plain_a", build: func() *dnsmessage.Msg {
			msg := new(dnsmessage.Msg)
			msg.SetQuestion("alias.example.com.", dnsmessage.TypeA)
			msg.Response = true
			msg.Answer = []dnsmessage.RR{a}
			return msg
		}, want: false},
		{name: "ns_only_referral", build: func() *dnsmessage.Msg {
			// RFC 2308 §2.2: an NS-only authority without SOA is a referral,
			// not an answer - it must not supersede a cached positive.
			msg := new(dnsmessage.Msg)
			msg.SetQuestion("delegated.example.com.", dnsmessage.TypeA)
			msg.Response = true
			msg.Ns = []dnsmessage.RR{&dnsmessage.NS{
				Hdr: dnsmessage.RR_Header{Name: "example.com.", Rrtype: dnsmessage.TypeNS, Class: dnsmessage.ClassINET, Ttl: 3600},
				Ns:  "ns1.other.example.",
			}}
			return msg
		}, want: false},
		{name: "any_query_with_answers", build: func() *dnsmessage.Msg {
			msg := new(dnsmessage.Msg)
			msg.SetQuestion("alias.example.com.", dnsmessage.TypeANY)
			msg.Response = true
			msg.Answer = []dnsmessage.RR{a}
			return msg
		}, want: false},
		{name: "any_query_empty", build: func() *dnsmessage.Msg {
			msg := new(dnsmessage.Msg)
			msg.SetQuestion("empty.example.com.", dnsmessage.TypeANY)
			msg.Response = true
			return msg
		}, want: true},
		{name: "mailb_query_with_mb_answer", build: func() *dnsmessage.Msg {
			// RFC 1035 §3.2.3: QTYPE=MAILB requests MB/MG/MR records, never a
			// type-253 answer. The classifier must treat an MB answer as
			// relevant so forwarded MAILB responses stay positively cached.
			msg := new(dnsmessage.Msg)
			msg.SetQuestion("mailbox.example.com.", dnsmessage.TypeMAILB)
			msg.Response = true
			msg.Answer = []dnsmessage.RR{&dnsmessage.A{
				Hdr: dnsmessage.RR_Header{Name: "mailbox.example.com.", Rrtype: dnsmessage.TypeMB, Class: dnsmessage.ClassINET, Ttl: 300},
				A:   net.ParseIP("198.51.100.12").To4(),
			}}
			return msg
		}, want: false},
		{name: "mailb_query_empty", build: func() *dnsmessage.Msg {
			msg := new(dnsmessage.Msg)
			msg.SetQuestion("mailbox.example.com.", dnsmessage.TypeMAILB)
			msg.Response = true
			return msg
		}, want: true},
		{name: "maila_query_with_md_answer", build: func() *dnsmessage.Msg {
			msg := new(dnsmessage.Msg)
			msg.SetQuestion("mailbox.example.com.", dnsmessage.TypeMAILA)
			msg.Response = true
			msg.Answer = []dnsmessage.RR{&dnsmessage.MD{
				Hdr: dnsmessage.RR_Header{Name: "mailbox.example.com.", Rrtype: dnsmessage.TypeMD, Class: dnsmessage.ClassINET, Ttl: 300},
				Md:  "mailhost.example.com.",
			}}
			return msg
		}, want: false},
		{name: "maila_query_with_mf_answer", build: func() *dnsmessage.Msg {
			msg := new(dnsmessage.Msg)
			msg.SetQuestion("mailbox.example.com.", dnsmessage.TypeMAILA)
			msg.Response = true
			msg.Answer = []dnsmessage.RR{&dnsmessage.MF{
				Hdr: dnsmessage.RR_Header{Name: "mailbox.example.com.", Rrtype: dnsmessage.TypeMF, Class: dnsmessage.ClassINET, Ttl: 300},
				Mf:  "mailhost.example.com.",
			}}
			return msg
		}, want: false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := isNegativeResponse(tt.build()); got != tt.want {
				t.Fatalf("isNegativeResponse() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestAnyQueryAnswerRemainsPositive pins RFC 8482 §3: a well-formed ANY
// response carries concrete RRsets (never type-ANY records), so relevance for
// QTYPE=ANY is a non-empty answer section and admission must stay positive.
func TestAnyQueryAnswerRemainsPositive(t *testing.T) {
	c := newSemanticsController(t)
	msg := new(dnsmessage.Msg)
	msg.SetQuestion("anything.example.com.", dnsmessage.TypeANY)
	msg.Response = true
	msg.Answer = []dnsmessage.RR{&dnsmessage.A{
		Hdr: dnsmessage.RR_Header{Name: "anything.example.com.", Rrtype: dnsmessage.TypeA, Class: dnsmessage.ClassINET, Ttl: 60},
		A:   net.ParseIP("198.51.100.11").To4(),
	}}

	const cacheKey = "semantics-any"
	before := time.Now()
	if err := c.NormalizeAndCacheDnsResp_(msg, cacheKey); err != nil {
		t.Fatal(err)
	}
	after := time.Now()
	entry := storedEntry(t, c, cacheKey)
	lifetime := 60 * time.Second
	if entry.Deadline.Before(before.Add(lifetime)) || entry.Deadline.After(after.Add(lifetime)) {
		t.Fatalf("deadline %v does not match answer TTL lifetime %v", entry.Deadline, lifetime)
	}
}

// TestMailaAnswersRemainPositive pins RFC 1035 §3.2.3: MAILA is the obsolete
// meta-query for MD/MF records, and those concrete answer types remain positive
// cache entries rather than being misclassified as NODATA.
func TestMailaAnswersRemainPositive(t *testing.T) {
	for _, tc := range []struct {
		name string
		rr   dnsmessage.RR
	}{
		{
			name: "md",
			rr: &dnsmessage.MD{
				Hdr: dnsmessage.RR_Header{Name: "mailbox.example.com.", Rrtype: dnsmessage.TypeMD, Class: dnsmessage.ClassINET, Ttl: 60},
				Md:  "mailhost.example.com.",
			},
		},
		{
			name: "mf",
			rr: &dnsmessage.MF{
				Hdr: dnsmessage.RR_Header{Name: "mailbox.example.com.", Rrtype: dnsmessage.TypeMF, Class: dnsmessage.ClassINET, Ttl: 60},
				Mf:  "mailhost.example.com.",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newSemanticsController(t)
			msg := new(dnsmessage.Msg)
			msg.SetQuestion("mailbox.example.com.", dnsmessage.TypeMAILA)
			msg.Response = true
			msg.Answer = []dnsmessage.RR{tc.rr}

			if err := c.NormalizeAndCacheDnsResp_(msg, "semantics-maila-"+tc.name); err != nil {
				t.Fatal(err)
			}
			storedEntry(t, c, "semantics-maila-"+tc.name)
		})
	}
}

// TestRefreshNegativeSupersedesExpiredPositive pins RFC 8767 §4: an accepted
// NXDOMAIN from the configured upstream must not leave the disproven expired
// positive in place for the rest of the stale window.
func TestRefreshNegativeSupersedesExpiredPositive(t *testing.T) {
	c := newSemanticsController(t)
	const cacheKey = "semantics-refresh-nx"

	// Plant an expired positive entry exactly as the stale path would leave it.
	expired := &DnsCache{
		Deadline: time.Now().Add(-time.Second),
		Answer: []dnsmessage.RR{&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{Name: "revoked.example.com.", Rrtype: dnsmessage.TypeA, Class: dnsmessage.ClassINET, Ttl: 0},
			A:   net.ParseIP("198.51.100.77").To4(),
		}},
	}
	c.storeDnsCache(cacheKey, expired)

	c.evictSupersededExpiredPositive(cacheKey)
	if _, ok := c.dnsCache.Load(cacheKey); ok {
		t.Fatal("superseded expired positive must be evicted after an accepted negative refresh")
	}

	// A fresh entry (newer positive stored while the refresh was in flight)
	// must be left untouched.
	fresh := &DnsCache{Deadline: time.Now().Add(time.Hour)}
	c.storeDnsCache(cacheKey, fresh)
	c.evictSupersededExpiredPositive(cacheKey)
	if _, ok := c.dnsCache.Load(cacheKey); !ok {
		t.Fatal("fresh entry must survive a delayed negative refresh")
	}
}
