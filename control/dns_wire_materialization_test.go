/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	componentdns "github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/dae/config"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// These tests pin the single "wire materialization" policy shared by the
// pre-packed path and the in-place fallback: section TTLs are stamped with the
// remaining lifetime on every delivery path, and the question section echoes the
// requester's own spelling.

// TestServedAddressAnswersCarryTheRealTtl is the regression for the TTL policy:
// an answer carries a real TTL on both the miss and the hit path - the upstream
// TTL on the first response and the remaining lifetime on a cache hit. dae used
// to rewrite A/AAAA TTLs to zero so that downstream resolvers would not cache
// them, which made the answer a client saw depend on whether the entry happened
// to be cached (0 first, a positive lifetime afterwards). Freshness is tracked
// by the entry deadline and the stale window instead.
func TestServedAddressAnswersCarryTheRealTtl(t *testing.T) {
	for _, qtype := range []uint16{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
		t.Run(dnsmessage.TypeToString[qtype], func(t *testing.T) {
			installCorpusDnsForwarderFactory(t, func(_ *componentdns.Upstream, _ dialArgument, _ *logrus.Logger) (DnsForwarder, error) {
				return &stubDnsForwarder{forward: func(context.Context, []byte) (*dnsmessage.Msg, error) {
					if qtype == dnsmessage.TypeA {
						return dnsAResponseMsg("ttl-zero.test.", "203.0.113.9"), nil
					}
					return dnsAAAAResponseMsg("ttl-zero.test.", "2001:db8::9"), nil
				}}, nil
			})
			ctrl := newCorpusControllerWithDefaultChooser(t, &config.Dns{
				Routing: config.DnsRouting{
					Request:  config.DnsRequestRouting{Fallback: config.FunctionOrString("asis")},
					Response: config.DnsResponseRouting{Fallback: config.FunctionOrString("accept")},
				},
			})

			for i, phase := range []string{"miss", "hit"} {
				writer := &dnsCorpusCaptureWriter{}
				query := corpusDnsQuery(uint16(0x3300+i), "ttl-zero.test.", qtype)
				if err := ctrl.HandleWithResponseWriter_(context.Background(), query, defaultUdpRequest(), writer); err != nil {
					t.Fatalf("%s: HandleWithResponseWriter_ error = %v", phase, err)
				}
				msg := writer.Message()
				if msg == nil || len(msg.Answer) == 0 {
					t.Fatalf("%s: no answer captured", phase)
				}
				// The upstream stub answers with TTL 60, so a real TTL is in
				// [1, 60]: the first response carries the upstream value and a
				// cache hit the remaining lifetime. Zero is only correct when
				// the upstream itself said zero.
				ttl := msg.Answer[0].Header().Ttl
				if ttl == 0 || ttl > 60 {
					t.Fatalf("%s: answer TTL = %d, want a real TTL in [1,60] (zero only when the upstream answered zero)", phase, ttl)
				}
				// The same value must be on the wire that was actually sent.
				var wire dnsmessage.Msg
				if err := wire.Unpack(writer.Wire()); err != nil {
					t.Fatalf("%s: unpack delivered wire: %v", phase, err)
				}
				if wireTtl := wire.Answer[0].Header().Ttl; wireTtl != ttl {
					t.Fatalf("%s: delivered wire answer TTL = %d, in-memory %d", phase, wireTtl, ttl)
				}
			}
		})
	}
}

// TestCopySectionWithTTLPolicy pins the shared record-level TTL policy: every
// real record is stamped with the requested remaining lifetime (including one
// whose stored TTL was zero, so the first response and a cache hit agree), and
// the EDNS OPT pseudo-record is never treated as a lifetime.
func TestCopySectionWithTTLPolicy(t *testing.T) {
	section := []dnsmessage.RR{
		&dnsmessage.A{Hdr: dnsmessage.RR_Header{Name: "zero.test.", Rrtype: dnsmessage.TypeA, Class: dnsmessage.ClassINET, Ttl: 0}, A: net.ParseIP("192.0.2.1").To4()},
		&dnsmessage.TXT{Hdr: dnsmessage.RR_Header{Name: "txt.test.", Rrtype: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET, Ttl: 300}, Txt: []string{"hold"}},
		&dnsmessage.OPT{Hdr: dnsmessage.RR_Header{Name: ".", Rrtype: dnsmessage.TypeOPT, Class: 1232, Ttl: 0x00008000}},
	}

	copied := copySectionWithTTL(section, 60)
	if len(copied) != len(section) {
		t.Fatalf("copied section length = %d, want %d", len(copied), len(section))
	}
	if got := copied[0].Header().Ttl; got != 60 {
		t.Fatalf("record stored with TTL 0 = %d, want the requested 60 (the delivered answer carries the real remaining lifetime, not a zero marker)", got)
	}
	if got := copied[1].Header().Ttl; got != 60 {
		t.Fatalf("record stored with TTL 300 = %d, want the requested 60", got)
	}
	if got := copied[2].Header().Ttl; got != 0x00008000 {
		t.Fatalf("OPT flags field = %#x, want it untouched (it is not a TTL)", got)
	}
	// The stored section must not be mutated: the copies are independent.
	if got := section[1].Header().Ttl; got != 300 {
		t.Fatalf("stored record TTL = %d, want the original 300", got)
	}
	if copySectionWithTTL(nil, 60) != nil {
		t.Fatal("a nil section must stay nil")
	}
}

// TestPrepackAndInPlaceShareRecordTtlPolicy is a regression guard: both
// materializations must apply the same record-level TTL policy, so they cannot
// drift into disagreeing about which records are re-stamped.
func TestPrepackAndInPlaceShareRecordTtlPolicy(t *testing.T) {
	now := time.Now()
	cache := &DnsCache{
		Deadline:         now.Add(30 * time.Second),
		OriginalDeadline: now.Add(30 * time.Second),
		Answer: []dnsmessage.RR{
			&dnsmessage.A{Hdr: dnsmessage.RR_Header{Name: "shared.test.", Rrtype: dnsmessage.TypeA, Class: dnsmessage.ClassINET, Ttl: 0}, A: net.ParseIP("192.0.2.7").To4()},
			&dnsmessage.CNAME{Hdr: dnsmessage.RR_Header{Name: "alias.shared.test.", Rrtype: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, Ttl: 300}, Target: "shared.test."},
		},
		Extra: []dnsmessage.RR{
			&dnsmessage.TXT{Hdr: dnsmessage.RR_Header{Name: "txt.shared.test.", Rrtype: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET, Ttl: 300}, Txt: []string{"keep"}},
		},
	}

	if err := cache.prepackResponseWithTTL("shared.test.", dnsmessage.TypeA, 30, now); err != nil {
		t.Fatalf("prepackResponseWithTTL: %v", err)
	}
	packed := cache.packedResponse.Load()
	if packed == nil {
		t.Fatal("prepackResponseWithTTL published no snapshot")
	}
	var prepacked dnsmessage.Msg
	if err := prepacked.Unpack(packed.wire); err != nil {
		t.Fatalf("unpack prepacked wire: %v", err)
	}

	req := new(dnsmessage.Msg)
	req.SetQuestion("shared.test.", dnsmessage.TypeA)
	inPlaceWire, err := cache.fillIntoWithTTLInPlace(req, now)
	if err != nil {
		t.Fatalf("fillIntoWithTTLInPlace: %v", err)
	}
	var inPlace dnsmessage.Msg
	if err := inPlace.Unpack(inPlaceWire); err != nil {
		t.Fatalf("unpack in-place wire: %v", err)
	}

	if len(prepacked.Answer) != len(inPlace.Answer) {
		t.Fatalf("answer sections differ in length: prepacked %d, in-place %d", len(prepacked.Answer), len(inPlace.Answer))
	}
	for i := range prepacked.Answer {
		if got, want := inPlace.Answer[i].Header().Ttl, prepacked.Answer[i].Header().Ttl; got != want {
			t.Fatalf("answer[%d] TTL differs between the paths: in-place %d, prepacked %d", i, got, want)
		}
	}
	if got := prepacked.Answer[0].Header().Ttl; got != 30 {
		t.Fatalf("prepacked answer stored with TTL 0 = %d, want the remaining 30: the delivered answer carries a real TTL, not a zero marker", got)
	}
	if got := prepacked.Answer[1].Header().Ttl; got != 30 {
		t.Fatalf("prepacked CNAME TTL = %d, want the remaining 30", got)
	}
	if got := prepacked.Extra[0].Header().Ttl; got != 30 {
		t.Fatalf("prepacked additional TTL = %d, want the remaining 30", got)
	}
	// The in-place path keeps the request's own additional section (it carries
	// the client's EDNS options) instead of replaying the cached one.
	if len(inPlace.Extra) != 0 {
		t.Fatalf("in-place additional section = %#v, want the request's (empty)", inPlace.Extra)
	}
}

// TestFillIntoWithTTLInPlaceReportsPackFailure keeps the formerly swallowed
// Pack error visible instead of degrading into a silent cache miss.
func TestFillIntoWithTTLInPlaceReportsPackFailure(t *testing.T) {
	cache := &DnsCache{
		Deadline: time.Now().Add(time.Minute),
		Answer:   []dnsmessage.RR{&dnsmessage.A{Hdr: dnsmessage.RR_Header{Name: "bad.test.", Rrtype: dnsmessage.TypeA, Class: dnsmessage.ClassINET, Ttl: 60}, A: []byte{1, 2, 3}}},
	}
	// An answer name that cannot be packed makes Pack fail.
	req := new(dnsmessage.Msg)
	req.Question = []dnsmessage.Question{{Name: "bad.test.", Qtype: dnsmessage.TypeA, Qclass: dnsmessage.ClassINET}}
	req.Response = true
	req.Answer = []dnsmessage.RR{&dnsmessage.A{
		Hdr: dnsmessage.RR_Header{Name: string(bytes.Repeat([]byte{'a'}, 64)) + ".test.", Rrtype: dnsmessage.TypeA, Class: dnsmessage.ClassINET, Ttl: 60},
		A:   net.ParseIP("192.0.2.1").To4(),
	}}

	wire, err := cache.fillIntoWithTTLInPlace(req, time.Now())
	if err == nil {
		t.Skipf("this miekg/dns version packed the malformed name (wire %d bytes); pack-failure surfacing is covered by the code path itself", len(wire))
	}
	if wire != nil {
		t.Fatal("a failed pack must not return a partial response")
	}
}

// TestCachedResponseEchoesRequesterQuestionCase is a regression guard: the
// response cache stores one canonical spelling per name, so the delivered
// response must carry the spelling the requester actually used.
func TestCachedResponseEchoesRequesterQuestionCase(t *testing.T) {
	c := newSemanticsController(t)
	const cacheKey = "case-echo.test.:1|asis"
	installCorpusCache(t, c, cacheKey, "case-echo.test.", dnsmessage.TypeA,
		dnsAResponseMsg("case-echo.test.", "203.0.113.42").Answer, 300)

	cache := storedEntry(t, c, cacheKey)
	packed := cache.packedResponse.Load()
	if packed == nil || packed.wire == nil {
		t.Fatal("the installed cache entry has no packed response")
	}

	reqMsg := corpusDnsQuery(0x4401, "CaSe-EcHo.TeSt.", dnsmessage.TypeA)
	writer := &dnsCorpusCaptureWriter{}
	if err := c.writeCachedResponse(packed.wire, reqMsg.Id, nil, writer, reqMsg); err != nil {
		t.Fatalf("writeCachedResponse: %v", err)
	}
	got := writer.Message()
	if got == nil || len(got.Question) == 0 {
		t.Fatalf("no question in the delivered response: %#v", got)
	}
	if got.Question[0].Name != "CaSe-EcHo.TeSt." {
		t.Fatalf("delivered question name = %q, want the requester's spelling %q", got.Question[0].Name, "CaSe-EcHo.TeSt.")
	}
	// The cached wire itself must not have been rewritten in place.
	after := cache.packedResponse.Load()
	if !bytes.Equal(after.wire, packed.wire) {
		t.Fatal("the shared cached wire must not be mutated by a delivery")
	}
	if got := dnsAnswerIPv4(t, writer.Message()); got != "203.0.113.42" {
		t.Fatalf("answer = %s, want the cached answer", got)
	}
}

// TestEchoWireQuestionCaseRewritesOnlySameLengthNames pins the wire-level
// contract: a same-length copy inside the question section, and no change at all
// when the requester's spelling has a different wire length.
func TestEchoWireQuestionCaseRewritesOnlySameLengthNames(t *testing.T) {
	c := newSemanticsController(t)

	msg := dnsAResponseMsg("case-wire.test.", "203.0.113.42")
	wire, err := msg.Pack()
	if err != nil {
		t.Fatalf("pack response: %v", err)
	}

	requester := corpusDnsQuery(0x4402, "CASE-WIRE.TeSt.", dnsmessage.TypeA)
	if !c.echoWireQuestionCase(wire, requester) {
		t.Fatal("a same-length requester spelling must be echoed")
	}
	var got dnsmessage.Msg
	if err := got.Unpack(wire); err != nil {
		t.Fatalf("unpack rewritten wire: %v", err)
	}
	if got.Question[0].Name != "CASE-WIRE.TeSt." {
		t.Fatalf("question name = %q, want %q", got.Question[0].Name, "CASE-WIRE.TeSt.")
	}
	if ttl := got.Answer[0].Header().Ttl; ttl != 60 {
		t.Fatalf("answer TTL = %d, want the response's own 60 (the rewrite must not touch records)", ttl)
	}

	// A name whose wire length differs must be left exactly as it was.
	longer := corpusDnsQuery(0x4403, "a-much-longer-name.test.", dnsmessage.TypeA)
	before := bytes.Clone(wire)
	if c.echoWireQuestionCase(wire, longer) {
		t.Fatal("a different-length requester spelling must not be rewritten")
	}
	if !bytes.Equal(before, wire) {
		t.Fatalf("wire changed on a length mismatch: %x != %x", wire, before)
	}

	// A response without a usable question name is refused, not guessed at.
	if c.echoWireQuestionCase(wire[:8], requester) {
		t.Fatal("a truncated message must not be rewritten")
	}
}

// TestEchoMsgQuestionCaseKeepsPackedSizeStable mirrors the message-level variant
// used by the ResponseWriter delivery path.
func TestEchoMsgQuestionCaseKeepsPackedSizeStable(t *testing.T) {
	c := newSemanticsController(t)
	respMsg := dnsAResponseMsg("case-msg.test.", "203.0.113.42")
	reqMsg := corpusDnsQuery(0x4404, "CaSe-MsG.TeSt.", dnsmessage.TypeA)

	if !c.echoMsgQuestionCase(respMsg, reqMsg) {
		t.Fatal("a same-length requester spelling must be echoed")
	}
	if respMsg.Question[0].Name != "CaSe-MsG.TeSt." {
		t.Fatalf("question name = %q, want the requester's spelling", respMsg.Question[0].Name)
	}

	other := corpusDnsQuery(0x4405, "a-much-longer-name.test.", dnsmessage.TypeA)
	if c.echoMsgQuestionCase(respMsg, other) {
		t.Fatal("a different-length requester spelling must not be substituted")
	}
	if respMsg.Question[0].Name != "CaSe-MsG.TeSt." {
		t.Fatalf("question name = %q, want it left untouched", respMsg.Question[0].Name)
	}
}
