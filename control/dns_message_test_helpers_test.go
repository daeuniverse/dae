/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"

	componentdns "github.com/daeuniverse/dae/component/dns"
	dnsmessage "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// DNS message/controller helpers recovered from pruned dns_cache_scope_test.go
// (Sprint 5 T1). Referenced by multiple surviving non-bulk fuzz-corpus test
// files, so centralized here. No build tag (matches original).

// dnsAResponseMsg builds a single-A-record DNS response message.
func dnsAResponseMsg(name string, ip string) *dnsmessage.Msg {
	msg := new(dnsmessage.Msg)
	msg.SetReply(&dnsmessage.Msg{})
	msg.SetQuestion(name, dnsmessage.TypeA)
	msg.Answer = []dnsmessage.RR{
		&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{
				Name:   dnsmessage.CanonicalName(name),
				Rrtype: dnsmessage.TypeA,
				Class:  dnsmessage.ClassINET,
				Ttl:    60,
			},
			A: net.ParseIP(ip).To4(),
		},
	}
	return msg
}

// setScopedBestDialerChooser overrides the scoped best-dialer chooser on a
// DnsController for corpus/scoped tests.
func setScopedBestDialerChooser(ctrl *DnsController, chooser func(ctx context.Context, snapshot DnsRequestSnapshot, upstream *componentdns.Upstream) (*dialArgument, error)) {
	rt := ctrl.runtime()
	if rt == nil {
		return
	}
	updated := *rt
	updated.bestDialerChooser = chooser
	ctrl.runtimeState.Store(&updated)
}

// dnsAnswerIPv4 extracts the first A-record IP from a DNS message.
// Recovered from dns_cache_scope_test.go.
func dnsAnswerIPv4(t *testing.T, msg *dnsmessage.Msg) string {
	t.Helper()
	require.NotNil(t, msg)
	require.NotEmpty(t, msg.Answer)
	a, ok := msg.Answer[0].(*dnsmessage.A)
	require.True(t, ok)
	return netip.MustParseAddr(a.A.String()).String()
}

// captureResponseWriter is a miekg/dns ResponseWriter capturing the last
// WriteMsg. Recovered from dns_cache_scope_test.go.
type captureResponseWriter struct {
	mu  sync.Mutex
	msg *dnsmessage.Msg
}

func (w *captureResponseWriter) LocalAddr() net.Addr       { return nil }
func (w *captureResponseWriter) RemoteAddr() net.Addr      { return nil }
func (w *captureResponseWriter) TsigStatus() error         { return nil }
func (w *captureResponseWriter) TsigTimersOnly(bool)       {}
func (w *captureResponseWriter) Hijack()                   {}
func (w *captureResponseWriter) Close() error              { return nil }
func (w *captureResponseWriter) Write([]byte) (int, error) { return 0, nil }

func (w *captureResponseWriter) WriteMsg(msg *dnsmessage.Msg) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.msg = msg.Copy()
	return nil
}

func (w *captureResponseWriter) Message() *dnsmessage.Msg {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.msg == nil {
		return nil
	}
	return w.msg.Copy()
}

// domainRoutingACache builds a DnsCache carrying a domain-routing bitmap via
// an A record. Recovered from domain_routing_tracker_test.go.
func domainRoutingACache(ownerKey string, ip string, bitmap []uint32) *DnsCache {
	return &DnsCache{
		RouteOwnerKey: ownerKey,
		DomainBitmap:  bitmap,
		Answer: []dnsmessage.RR{
			&dnsmessage.A{
				Hdr: dnsmessage.RR_Header{
					Name:   "shared.test.",
					Rrtype: dnsmessage.TypeA,
					Class:  dnsmessage.ClassINET,
					Ttl:    60,
				},
				A: net.ParseIP(ip).To4(),
			},
		},
	}
}

// domainRoutingBitmap builds a fixed-length bitmap sized to the bpf routing
// table. Recovered from domain_routing_tracker_test.go.
func domainRoutingBitmap(words ...uint32) []uint32 {
	bitmap := make([]uint32, len(bpfDomainRouting{}.Bitmap))
	copy(bitmap, words)
	return bitmap
}
