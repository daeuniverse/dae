/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net"
	"testing"
	"time"

	dnsmessage "github.com/miekg/dns"
)

func newDeadlineRegressionCache(now time.Time) *DnsCache {
	return &DnsCache{
		Deadline: now.Add(60 * time.Second),
		Answer: []dnsmessage.RR{
			&dnsmessage.A{
				Hdr: dnsmessage.RR_Header{
					Name:   "example.com.",
					Rrtype: dnsmessage.TypeA,
					Class:  dnsmessage.ClassINET,
					Ttl:    60,
				},
				A: net.ParseIP("192.0.2.1"),
			},
		},
	}
}

// TestPrepackBeforeStoreInitializesDeadlineNano guards the store-path prepack:
// leaving deadlineNano zero makes GetPackedResponseWithApproximateTTL treat
// every fresh entry as already expired (disabling the packed fast path) and
// makes GetStaleResponse reject every entry inside the stale-while-revalidate
// window, so the optimistic cache silently never serves.
func TestPrepackBeforeStoreInitializesDeadlineNano(t *testing.T) {
	now := time.Now()
	cache := newDeadlineRegressionCache(now)
	if err := cache.prepackResponseBeforeStore("example.com.", dnsmessage.TypeA, 60, now); err != nil {
		t.Fatalf("prepackResponseBeforeStore: %v", err)
	}

	if got, want := cache.deadlineNano.Load(), cache.Deadline.UnixNano(); got != want {
		t.Fatalf("deadlineNano = %d, want %d", got, want)
	}
	if packed := cache.GetPackedResponseWithApproximateTTL("example.com.", dnsmessage.TypeA, now.Add(time.Second)); packed == nil {
		t.Fatal("packed fast path returned nil for a fresh entry")
	}
	if stale := cache.GetStaleResponse(now.Add(61*time.Second), 60); stale == nil {
		t.Fatal("stale lookup returned nil inside the stale window")
	}
	if stale := cache.GetStaleResponse(now.Add(122*time.Second), 60); stale != nil {
		t.Fatal("stale lookup returned data beyond the stale window")
	}
}
