/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	componentdns "github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/dae/config"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

// This file is the Phase 0 DNS compatibility corpus for the semantic
// architecture refactor. It mirrors the routing corpus pattern: each fixture
// declares a DNS routing program plus a set of cases that exercise a specific
// behaviour, and the ReplayDns driver runs the fixture against the current
// DnsController implementation to pin the observable result.
//
// Coverage target (per Phase 0 acceptance clause 2):
//   - UDP transport: cache miss / cache hit / cache stale + background refresh
//   - TCP transport: UDP failure triggering TCP fallback
//   - Reject-before-cache: routing-level reject must short-circuit cache hits
//   - Negative upstream response: NXDOMAIN is delivered but not stored as an
//     address cache entry
//   - QUIC sniffing: response routing driven by sniffed SNI (planned; needs
//     sniffing pipeline hook)
//   - Concurrency cap: REFUSED on overload
//
// Future phases (DNS projection split, three-valued response routing, etc.)
// MUST keep these corpus tests passing. Cases with WireHex pin the canonical
// packed response byte-for-byte; all cases continue to assert the response
// shape that matters for their behavior.

// DnsCorpusCase captures a single DNS request and the observable response
// shape the corpus is pinning. Selected deterministic cases also pin their
// complete packed response wire through DnsCorpusExpected.WireHex.
type DnsCorpusCase struct {
	Name       string
	Query      func() *dnsmessage.Msg
	Request    func() *udpRequest
	PreState   func(t *testing.T, ctrl *DnsController)
	PostAssert func(t *testing.T, ctrl *DnsController, response *dnsmessage.Msg)
	Expected   DnsCorpusExpected
}

// DnsCorpusExpected describes the observable response shape. HasRcode and
// HasAnswerCount make zero-valued DNS semantics assertable: both NOERROR and
// an empty answer are meaningful compatibility outcomes.
type DnsCorpusExpected struct {
	HasRcode       bool
	Rcode          int
	HasAnswerCount bool
	AnswerCount    int
	AnswerIPv4     string // empty = no assertion
	AnswerIPv6     string // empty = no assertion
	HasAnswerTTL   bool
	AnswerTTLMin   uint32
	AnswerTTLMax   uint32
	// WireHex is the canonical unframed DNS response wire. Canonicalization
	// preserves the complete message except section TTLs, which are asserted
	// separately because a cache response necessarily carries elapsed time.
	// Empty means this case deliberately asserts shape only, such as the
	// time-sensitive stale cache fixture.
	WireHex string
}

// DnsCorpusFixture bundles a DNS routing configuration with cases.
type DnsCorpusFixture struct {
	Name        string
	Description string
	BuildConfig func() *config.Dns
	// BestDialerChooser lets each fixture decide how the dial argument is
	// built. The default corpus chooser just returns the request's realDst.
	BestDialerChooser func(ctx context.Context, snapshot DnsRequestSnapshot, upstream *componentdns.Upstream) (*dialArgument, error)
	// ForwarderFactory lets each fixture decide how upstream traffic is
	// served. Most fixtures inject a canned response, occasionally gated on
	// l4proto to simulate UDP failure / TCP fallback.
	ForwarderFactory func(upstream *componentdns.Upstream, dialArg dialArgument, log *logrus.Logger) (DnsForwarder, error)
	Cases            []DnsCorpusCase
}

// DnsCorpusFixtures returns the full Phase 0 DNS corpus. Add a constructor
// here to extend coverage; downstream refactor phases replay the same slice
// and must produce byte-identical observable results.
func DnsCorpusFixtures() []DnsCorpusFixture {
	return []DnsCorpusFixture{
		udpCacheMissFixture(),
		udpCacheHitFixture(),
		udpCacheHitAAAAFixture(),
		negativeResponseFixture(),
		udpCacheStaleOptimisticFixture(),
		udpCacheStaleCnameNodataRefreshFixture(),
		tcpUdpFallbackFixture(),
		tcpUdpBlackholeFallbackFixture(),
		rejectBeforeCacheFixture(),
	}
}

// ReplayDns runs a fixture against a fresh DnsController. The driver:
//
//  1. Builds a controller from the fixture's config.
//  2. Installs the fixture's best-dialer chooser and forwarder factory.
//  3. For each case: optionally invokes PreState, then HandleWithResponseWriter_,
//     and asserts the captured response matches the expected shape.
//
// The factory swap is restored via t.Cleanup so the test does not leak
// global state into siblings.
func ReplayDns(t *testing.T, fixture DnsCorpusFixture) {
	t.Helper()
	installCorpusDnsForwarderFactory(t, fixture.ForwarderFactory)

	ctrl := newCorpusDnsController(t, fixture.BuildConfig())

	chooser := fixture.BestDialerChooser
	if chooser == nil {
		chooser = defaultCorpusChooser
	}
	setScopedBestDialerChooser(ctrl, chooser)

	for _, tc := range fixture.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			if tc.PreState != nil {
				tc.PreState(t, ctrl)
			}
			writer := &dnsCorpusCaptureWriter{}
			var req *udpRequest
			if tc.Request != nil {
				req = tc.Request()
			} else {
				req = defaultUdpRequest()
			}
			query := tc.Query()
			if query == nil {
				t.Fatalf("%s: nil Query in case %s", fixture.Name, tc.Name)
			}
			if err := ctrl.HandleWithResponseWriter_(context.Background(), query, req, writer); err != nil {
				t.Fatalf("HandleWithResponseWriter_ error = %v", err)
			}
			msg := writer.Message()
			if msg == nil {
				t.Fatalf("no response captured")
			}
			assertDnsShape(t, tc.Expected, msg)
			assertDnsWire(t, tc.Expected.WireHex, writer.Wire())
			if tc.PostAssert != nil {
				tc.PostAssert(t, ctrl, msg)
			}
		})
	}
}

// newCorpusDnsController builds a controller wired to a fixture's DNS config.
func newCorpusDnsController(t testing.TB, cfg *config.Dns) *DnsController {
	t.Helper()
	if cfg == nil {
		t.Fatalf("fixture returned nil Dns config")
	}
	routing, err := componentdns.New(cfg, &componentdns.NewOption{
		Logger: logrus.New(),
		UpstreamReadyCallback: func(*componentdns.Upstream) error {
			return nil
		},
	})
	require.NoError(t, err)

	ctrl, err := NewDnsController(routing, &DnsControllerOption{
		Log:                logrus.New(),
		LifecycleContext:   context.Background(),
		OptimisticCache:    true,
		OptimisticCacheTtl: 60,
		CacheAccessCallback: func(*DnsCache) error {
			return nil
		},
		NewCache: func(fqdn string, answers, ns, extra []dnsmessage.RR, deadline, originalDeadline time.Time) (*DnsCache, error) {
			return &DnsCache{
				Answer:           answers,
				NS:               ns,
				Extra:            extra,
				Deadline:         deadline,
				OriginalDeadline: originalDeadline,
			}, nil
		},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = ctrl.Close() })
	return ctrl
}

// defaultCorpusChooser matches the request's destination (UDP/IPv4). Sufficient
// for fixtures that do not need to dial a specific upstream host.
func defaultCorpusChooser(ctx context.Context, snapshot DnsRequestSnapshot, upstream *componentdns.Upstream) (*dialArgument, error) {
	return &dialArgument{
		l4proto:    consts.L4ProtoStr_UDP,
		ipversion:  consts.IpVersionStr_4,
		bestTarget: snapshot.RealDst,
	}, nil
}

// newCorpusControllerWithDefaultChooser builds a corpus controller whose
// best-dialer chooser matches the request destination (UDP/IPv4).
func newCorpusControllerWithDefaultChooser(t *testing.T, cfg *config.Dns) *DnsController {
	t.Helper()
	ctrl := newCorpusDnsController(t, cfg)
	setScopedBestDialerChooser(ctrl, defaultCorpusChooser)
	return ctrl
}

// installCorpusDnsForwarderFactory swaps the global forwarder factory for the
// duration of the test. A nil factory keeps the current one.
func installCorpusDnsForwarderFactory(t *testing.T, factory func(*componentdns.Upstream, dialArgument, *logrus.Logger) (DnsForwarder, error)) {
	t.Helper()
	if factory == nil {
		return
	}
	previous := dnsForwarderFactory
	dnsForwarderFactory = factory
	t.Cleanup(func() {
		dnsForwarderFactory = previous
	})
}

// defaultUdpRequest is the placeholder request for cases that do not need
// specific source/destination addresses.
func defaultUdpRequest() *udpRequest {
	return &udpRequest{
		realSrc:       netip.MustParseAddrPort("192.0.2.10:41000"),
		realDst:       netip.MustParseAddrPort("1.1.1.1:53"),
		routingResult: &bpfRoutingResult{},
	}
}

// corpusDnsQuery builds a query with a fixed ID so a fixture can safely pin
// the complete packed response rather than only its parsed fields.
func corpusDnsQuery(id uint16, qname string, qtype uint16) *dnsmessage.Msg {
	msg := new(dnsmessage.Msg)
	msg.SetQuestion(qname, qtype)
	msg.Id = id
	return msg
}

// installCorpusCache stores a deterministic pre-packed cache entry. The
// production cache calculates TTLs from time.Now, which is correct in normal
// operation but unsuitable for a byte golden. A long-lived entry and an
// explicitly packed TTL keep the fixture independent of clock rounding.
func installCorpusCache(t testing.TB, ctrl *DnsController, cacheKey, qname string, qtype uint16, answers []dnsmessage.RR, ttl uint32) {
	t.Helper()

	now := time.Now()
	deadline := now.Add(time.Duration(ttl) * time.Second)
	cache := &DnsCache{
		RouteOwnerKey:    cacheKey,
		Answer:           cloneCorpusRRs(answers),
		Deadline:         deadline,
		OriginalDeadline: deadline,
	}
	if err := cache.prepackResponseBeforeStore(qname, qtype, ttl, now); err != nil {
		t.Fatalf("prepack deterministic DNS cache response: %v", err)
	}
	// Keep the fixture's explicitly packed TTL stable for its entire synthetic
	// cache lifetime. Production entries continue to refresh from wall clock.
	packed := cache.packedResponse.Load()
	if packed == nil {
		t.Fatal("prepack deterministic DNS cache response produced no snapshot")
	}
	stable := *packed
	stable.createdAtUnixNano = deadline.UnixNano()
	cache.packedResponse.Store(&stable)
	// Publish through the controller's store so the entry also registers in
	// the base-key index, exactly as a production insert would.
	ctrl.storeDnsCache(cacheKey, cache)
}

func cloneCorpusRRs(rrs []dnsmessage.RR) []dnsmessage.RR {
	if rrs == nil {
		return nil
	}
	clone := make([]dnsmessage.RR, len(rrs))
	for i, rr := range rrs {
		clone[i] = dnsmessage.Copy(rr)
	}
	return clone
}

// dnsCorpusCaptureWriter records the exact message supplied by the controller
// to its response adapter. It intentionally stores an unframed DNS wire: UDP
// writes that wire directly, while TCP adapters add only their length prefix.
type dnsCorpusCaptureWriter struct {
	msg  *dnsmessage.Msg
	wire []byte
}

func (w *dnsCorpusCaptureWriter) LocalAddr() net.Addr  { return nil }
func (w *dnsCorpusCaptureWriter) RemoteAddr() net.Addr { return nil }
func (w *dnsCorpusCaptureWriter) TsigStatus() error    { return nil }
func (w *dnsCorpusCaptureWriter) TsigTimersOnly(bool)  {}
func (w *dnsCorpusCaptureWriter) Hijack()              {}
func (w *dnsCorpusCaptureWriter) Close() error         { return nil }

func (w *dnsCorpusCaptureWriter) WriteMsg(msg *dnsmessage.Msg) error {
	copy := msg.Copy()
	wire, err := copy.Pack()
	if err != nil {
		return err
	}
	w.msg = copy
	w.wire = append(w.wire[:0], wire...)
	return nil
}

func (w *dnsCorpusCaptureWriter) Write(wire []byte) (int, error) {
	var msg dnsmessage.Msg
	if err := msg.Unpack(wire); err != nil {
		return 0, err
	}
	w.msg = msg.Copy()
	w.wire = append(w.wire[:0], wire...)
	return len(wire), nil
}

func (w *dnsCorpusCaptureWriter) Message() *dnsmessage.Msg {
	if w.msg == nil {
		return nil
	}
	return w.msg.Copy()
}

func (w *dnsCorpusCaptureWriter) Wire() []byte {
	return append([]byte(nil), w.wire...)
}

// assertDnsShape checks only the explicitly asserted fields.
func assertDnsShape(t *testing.T, want DnsCorpusExpected, got *dnsmessage.Msg) {
	t.Helper()
	if want.HasRcode && got.Rcode != want.Rcode {
		t.Fatalf("rcode = %d, want %d", got.Rcode, want.Rcode)
	}
	if want.HasAnswerCount && len(got.Answer) != want.AnswerCount {
		t.Fatalf("answer count = %d, want %d", len(got.Answer), want.AnswerCount)
	}
	if want.AnswerIPv4 != "" {
		ip := dnsAnswerIPv4(t, got)
		if ip != want.AnswerIPv4 {
			t.Fatalf("answer IPv4 = %s, want %s", ip, want.AnswerIPv4)
		}
	}
	if want.AnswerIPv6 != "" {
		ip := dnsAnswerIPv6(t, got)
		if ip != want.AnswerIPv6 {
			t.Fatalf("answer IPv6 = %s, want %s", ip, want.AnswerIPv6)
		}
	}
	if want.HasAnswerTTL {
		if len(got.Answer) == 0 {
			t.Fatalf("answer TTL = missing answer, want [%d, %d]", want.AnswerTTLMin, want.AnswerTTLMax)
		}
		if ttl := got.Answer[0].Header().Ttl; ttl < want.AnswerTTLMin || ttl > want.AnswerTTLMax {
			t.Fatalf("answer TTL = %d, want [%d, %d]", ttl, want.AnswerTTLMin, want.AnswerTTLMax)
		}
	}
}

func assertDnsWire(t *testing.T, wantHex string, got []byte) {
	t.Helper()
	if wantHex == "" {
		return
	}
	want, err := hex.DecodeString(wantHex)
	if err != nil {
		t.Fatalf("decode DNS wire golden %q: %v", wantHex, err)
	}
	canonical, err := canonicalDnsWire(got)
	if err != nil {
		t.Fatalf("canonicalize DNS response wire: %v", err)
	}
	if !bytes.Equal(canonical, want) {
		t.Fatalf("canonical DNS response wire = %x, raw = %x, want %x", canonical, got, want)
	}
}

// canonicalDnsWire makes elapsed cache TTLs deterministic without hiding any
// other response field. It changes only RR TTL octets in the already packed
// wire, retaining name compression and every other byte. IDs remain fixed by
// each fixture.
func canonicalDnsWire(wire []byte) ([]byte, error) {
	if len(wire) < 12 {
		return nil, fmt.Errorf("DNS message is too short: %d bytes", len(wire))
	}
	canonical := bytes.Clone(wire)
	offset := 12

	questionCount := int(binary.BigEndian.Uint16(canonical[4:6]))
	for range questionCount {
		var err error
		offset, err = skipDNSWireName(canonical, offset)
		if err != nil {
			return nil, fmt.Errorf("skip DNS question name: %w", err)
		}
		if offset+4 > len(canonical) {
			return nil, fmt.Errorf("DNS question type/class truncated at offset %d", offset)
		}
		offset += 4
	}

	for _, recordCount := range []int{
		int(binary.BigEndian.Uint16(canonical[6:8])),
		int(binary.BigEndian.Uint16(canonical[8:10])),
		int(binary.BigEndian.Uint16(canonical[10:12])),
	} {
		for range recordCount {
			var err error
			offset, err = skipDNSWireName(canonical, offset)
			if err != nil {
				return nil, fmt.Errorf("skip DNS record name: %w", err)
			}
			if offset+10 > len(canonical) {
				return nil, fmt.Errorf("DNS record header truncated at offset %d", offset)
			}
			for i := 4; i < 8; i++ {
				canonical[offset+i] = 0
			}
			rdataLength := int(binary.BigEndian.Uint16(canonical[offset+8 : offset+10]))
			offset += 10
			if offset+rdataLength > len(canonical) {
				return nil, fmt.Errorf("DNS record data truncated at offset %d", offset)
			}
			offset += rdataLength
		}
	}
	if offset != len(canonical) {
		return nil, fmt.Errorf("unexpected trailing DNS bytes at offset %d", offset)
	}
	return canonical, nil
}

func skipDNSWireName(wire []byte, offset int) (int, error) {
	for {
		if offset >= len(wire) {
			return 0, fmt.Errorf("name truncated at offset %d", offset)
		}
		labelLength := wire[offset]
		switch labelLength & 0xc0 {
		case 0:
			offset++
			if labelLength == 0 {
				return offset, nil
			}
			if offset+int(labelLength) > len(wire) {
				return 0, fmt.Errorf("label truncated at offset %d", offset)
			}
			offset += int(labelLength)
		case 0xc0:
			if offset+2 > len(wire) {
				return 0, fmt.Errorf("compression pointer truncated at offset %d", offset)
			}
			return offset + 2, nil
		default:
			return 0, fmt.Errorf("unsupported DNS label type %#x at offset %d", labelLength, offset)
		}
	}
}

func TestCanonicalDnsWireZeroesRRTTLs(t *testing.T) {
	msg := new(dnsmessage.Msg)
	msg.Id = 0x7a01
	msg.SetQuestion("canonical.test.", dnsmessage.TypeA)
	msg.Response = true
	msg.RecursionAvailable = true
	msg.Compress = true
	msg.Answer = []dnsmessage.RR{&dnsmessage.A{
		Hdr: dnsmessage.RR_Header{Name: "canonical.test.", Rrtype: dnsmessage.TypeA, Class: dnsmessage.ClassINET, Ttl: 31},
		A:   net.ParseIP("192.0.2.31").To4(),
	}}
	msg.Ns = []dnsmessage.RR{&dnsmessage.NS{
		Hdr: dnsmessage.RR_Header{Name: "canonical.test.", Rrtype: dnsmessage.TypeNS, Class: dnsmessage.ClassINET, Ttl: 32},
		Ns:  "ns.canonical.test.",
	}}
	msg.Extra = []dnsmessage.RR{&dnsmessage.A{
		Hdr: dnsmessage.RR_Header{Name: "ns.canonical.test.", Rrtype: dnsmessage.TypeA, Class: dnsmessage.ClassINET, Ttl: 33},
		A:   net.ParseIP("192.0.2.33").To4(),
	}}

	raw, err := msg.Pack()
	if err != nil {
		t.Fatalf("pack DNS response: %v", err)
	}
	canonical, err := canonicalDnsWire(raw)
	if err != nil {
		t.Fatalf("canonicalize DNS response: %v", err)
	}

	var decoded dnsmessage.Msg
	if err := decoded.Unpack(canonical); err != nil {
		t.Fatalf("unpack canonical DNS response: %v", err)
	}
	if decoded.Id != msg.Id || decoded.Rcode != msg.Rcode || !decoded.Response {
		t.Fatalf("canonical DNS header = %+v, want id=%#x response=true rcode=%d", decoded.MsgHdr, msg.Id, msg.Rcode)
	}
	for _, section := range [][]dnsmessage.RR{decoded.Answer, decoded.Ns, decoded.Extra} {
		for _, rr := range section {
			if ttl := rr.Header().Ttl; ttl != 0 {
				t.Fatalf("canonical DNS TTL = %d, want 0 for %T", ttl, rr)
			}
		}
	}
}

// dnsAnswerIPv6 extracts the first AAAA answer canonical form. Mirrors the
// shape of dnsAnswerIPv4 so corpus fixtures can assert either family without
// duplicating parsing logic.
func dnsAnswerIPv6(t *testing.T, msg *dnsmessage.Msg) string {
	t.Helper()
	if msg == nil {
		t.Fatalf("nil response message")
		return ""
	}
	if len(msg.Answer) == 0 {
		t.Fatalf("no answer records")
	}
	aaaa, ok := msg.Answer[0].(*dnsmessage.AAAA)
	if !ok {
		t.Fatalf("first answer is %T, want *AAAA", msg.Answer[0])
	}
	return netip.MustParseAddr(aaaa.AAAA.String()).String()
}
