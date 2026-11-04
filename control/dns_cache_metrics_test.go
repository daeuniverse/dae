/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/dns"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

func newMetricsTestController(t *testing.T) *DnsController {
	t.Helper()
	log := logrus.New()
	log.SetOutput(io.Discard)
	c := newTestDnsController()
	c.log = log
	return c
}

func storeFreshDNSCache(t *testing.T, c *DnsController, cacheKey, qname string, qtype uint16) {
	t.Helper()
	cache := &DnsCache{
		Answer: []dnsmessage.RR{&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{
				Name:   qname,
				Rrtype: qtype,
				Class:  dnsmessage.ClassINET,
				Ttl:    300,
			},
			A: []byte{1, 2, 3, 4},
		}},
		Deadline:         time.Now().Add(time.Minute),
		OriginalDeadline: time.Now().Add(time.Minute),
	}
	if qtype == dnsmessage.TypeAAAA {
		cache.Answer = []dnsmessage.RR{&dnsmessage.AAAA{
			Hdr: dnsmessage.RR_Header{
				Name:   qname,
				Rrtype: dnsmessage.TypeAAAA,
				Class:  dnsmessage.ClassINET,
				Ttl:    300,
			},
			AAAA: []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		}}
	}
	if err := cache.PrepackResponse(qname, qtype); err != nil {
		t.Fatalf("PrepackResponse: %v", err)
	}
	c.storeDnsCache(cacheKey, cache)
}

func TestDNSCacheDeliveryCountsOneHit(t *testing.T) {
	c := newMetricsTestController(t)
	const qname = "hit.example.com."
	key := c.cacheKey(qname, dnsmessage.TypeA)
	storeFreshDNSCache(t, c, key, qname, dnsmessage.TypeA)

	msg := new(dnsmessage.Msg)
	msg.SetQuestion(qname, dnsmessage.TypeA)
	delivery := &dnsCacheDelivery{}
	handled, err := c.serveFromRespCacheWithRefresh_(msg, nil, &noopDNSResponseWriter{}, key, 0, nil, delivery)
	if err != nil || !handled {
		t.Fatalf("serve cache: handled=%v err=%v", handled, err)
	}
	c.noteDNSCacheServed(delivery, true)
	counters := c.DnsCountersSnapshot()
	if counters.CacheHitTotal != 1 {
		t.Fatalf("cache hits = %d, want 1", counters.CacheHitTotal)
	}
	if counters.CacheLazyHitTotal != 0 {
		t.Fatalf("lazy hits = %d, want 0 after a second note on the same request", counters.CacheLazyHitTotal)
	}
}

func TestDNSSuppressedNonPreferredCacheReplyIsNotAHit(t *testing.T) {
	c := newMetricsTestController(t)
	setTestDnsControllerRuntime(c, func(rt *dnsControllerRuntimeState) {
		rt.qtypePrefer = dnsmessage.TypeAAAA
	})
	const qname = "suppress.example.com."
	storeFreshDNSCache(t, c, c.cacheKey(qname, dnsmessage.TypeAAAA), qname, dnsmessage.TypeAAAA)
	aKey := c.cacheKey(qname, dnsmessage.TypeA)
	storeFreshDNSCache(t, c, aKey, qname, dnsmessage.TypeA)

	msg := new(dnsmessage.Msg)
	msg.SetQuestion(qname, dnsmessage.TypeA)
	handled, err := c.serveFromRespCacheWithRefresh_(msg, nil, &noopDNSResponseWriter{}, aKey, 0, nil, &dnsCacheDelivery{})
	if err != nil || !handled {
		t.Fatalf("suppressed cache reply: handled=%v err=%v", handled, err)
	}
	if got := c.DnsCountersSnapshot().CacheHitTotal; got != 0 {
		t.Fatalf("cache hits = %d, want 0 for a suppressed non-preferred reply", got)
	}
}

func TestDNSStaleServedRefreshCountsLazyHit(t *testing.T) {
	c := newMetricsTestController(t)
	setTestDnsControllerRuntime(c, func(rt *dnsControllerRuntimeState) {
		rt.optimisticCacheEnabled = true
		rt.optimisticCacheTtl = 120
		rt.bestDialerChooser = func(context.Context, DnsRequestSnapshot, *dns.Upstream) (*dialArgument, error) {
			return nil, errors.New("no dialer")
		}
	})
	const qname = "stale.example.com."
	key := c.cacheKey(qname, dnsmessage.TypeA)
	cache := &DnsCache{
		Answer: []dnsmessage.RR{&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{
				Name:   qname,
				Rrtype: dnsmessage.TypeA,
				Class:  dnsmessage.ClassINET,
				Ttl:    30,
			},
			A: []byte{9, 9, 9, 9},
		}},
		Deadline:         time.Now().Add(-30 * time.Second),
		OriginalDeadline: time.Now().Add(-30 * time.Second),
	}
	cache.deadlineNano.Store(cache.Deadline.UnixNano())
	if err := cache.PrepackResponse(qname, dnsmessage.TypeA); err != nil {
		t.Fatalf("PrepackResponse: %v", err)
	}
	c.storeDnsCache(key, cache)

	msg := new(dnsmessage.Msg)
	msg.SetQuestion(qname, dnsmessage.TypeA)
	upstream := &dns.Upstream{Scheme: "udp", Hostname: "1.1.1.1", Port: 53}
	handled, err := c.serveFromRespCacheWithRefresh_(msg, &udpRequest{}, &noopDNSResponseWriter{}, key, 0, upstream, &dnsCacheDelivery{})
	if err != nil || !handled {
		t.Fatalf("stale cache reply: handled=%v err=%v", handled, err)
	}
	counters := c.DnsCountersSnapshot()
	if counters.CacheHitTotal != 1 || counters.CacheLazyHitTotal != 1 {
		t.Fatalf("hits=%d lazy=%d, want 1 and 1", counters.CacheHitTotal, counters.CacheLazyHitTotal)
	}
}

func TestPostSingleflightPackedWriteIsNotAHitUnlessLeaderUsedCache(t *testing.T) {
	c := newMetricsTestController(t)
	const qname = "packed-after-upstream.example.com."
	key := c.cacheKey(qname, dnsmessage.TypeA)
	storeFreshDNSCache(t, c, key, qname, dnsmessage.TypeA)

	freshQuery := func() *dnsmessage.Msg {
		msg := new(dnsmessage.Msg)
		msg.SetQuestion(qname, dnsmessage.TypeA)
		return msg
	}

	handled, err := c.deliverSingleflightPackedCache(freshQuery(), nil, &noopDNSResponseWriter{}, key, dnsSingleflightResult{
		fromCache: false,
		lazy:      true,
	}, &dnsCacheDelivery{})
	if err != nil || !handled {
		t.Fatalf("packed write after upstream store: handled=%v err=%v", handled, err)
	}
	counters := c.DnsCountersSnapshot()
	if counters.CacheHitTotal != 0 || counters.CacheLazyHitTotal != 0 {
		t.Fatalf("upstream-resolved packed write counted as a hit: hits=%d lazy=%d", counters.CacheHitTotal, counters.CacheLazyHitTotal)
	}

	handled, err = c.deliverSingleflightPackedCache(freshQuery(), nil, &noopDNSResponseWriter{}, key, dnsSingleflightResult{
		fromCache: true,
		lazy:      true,
	}, &dnsCacheDelivery{})
	if err != nil || !handled {
		t.Fatalf("packed write of a leader cache short-circuit: handled=%v err=%v", handled, err)
	}
	counters = c.DnsCountersSnapshot()
	if counters.CacheHitTotal != 1 || counters.CacheLazyHitTotal != 1 {
		t.Fatalf("leader cache short-circuit hits=%d lazy=%d, want 1 and 1", counters.CacheHitTotal, counters.CacheLazyHitTotal)
	}
}

func TestDNSUpstreamQuestionMismatchCountsAsError(t *testing.T) {
	c := newMetricsTestController(t)
	metric := c.getOrCreateDnsUpstreamMetric("udp://1.1.1.1:53")
	resp := new(dnsmessage.Msg)
	resp.SetQuestion("other.example.com.", dnsmessage.TypeA)
	err := c.finishDNSUpstreamExchange(metric, "udp://1.1.1.1:53", time.Now(), dnsmessage.Question{
		Name:  "example.com.",
		Qtype: dnsmessage.TypeA,
	}, resp, nil)
	if err == nil {
		t.Fatal("expected question-echo mismatch")
	}
	snapshot := c.DnsUpstreamSnapshot()["udp://1.1.1.1:53"]
	if snapshot.ErrTotal != 1 {
		t.Fatalf("upstream err = %d, want 1", snapshot.ErrTotal)
	}
	if snapshot.Latency.Count != 1 {
		t.Fatalf("upstream latency count = %d, want 1", snapshot.Latency.Count)
	}
}
