/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/dns"
	dnsmessage "github.com/miekg/dns"
)

func TestDNSRuntimeBehaviorPublicationLitmus(t *testing.T) {
	controller := &DnsController{dnsControllerStore: newDnsControllerStore()}
	configs := []*DnsControllerOption{
		{OptimisticCache: false, OptimisticCacheTtl: 101, MaxCacheSize: 1001},
		{OptimisticCache: true, OptimisticCacheTtl: 202, MaxCacheSize: 2002},
	}
	if err := controller.TryUpdateRuntime(configs[0], (*dns.Dns)(nil)); err != nil {
		t.Fatalf("initialize runtime: %v", err)
	}

	const iterations = 200_000
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	var invalid atomicBehaviorTuple

	go func() {
		defer wg.Done()
		<-start
		for i := range iterations {
			if err := controller.TryUpdateRuntime(configs[i&1], (*dns.Dns)(nil)); err != nil {
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		<-start
		for range iterations {
			enabled, ttl, _, maxSize := controller.currentOptimisticCacheConfig()
			if (enabled && ttl == 202 && maxSize == 2002) || (!enabled && ttl == 101 && maxSize == 1001) {
				continue
			}
			invalid = atomicBehaviorTuple{enabled: enabled, ttl: ttl, maxSize: maxSize}
			return
		}
	}()
	close(start)
	wg.Wait()

	if invalid != (atomicBehaviorTuple{}) {
		t.Fatalf("observed behavior tuple from no published generation: %+v", invalid)
	}
}

type atomicBehaviorTuple struct {
	enabled bool
	ttl     int
	maxSize int
}

func TestDNSPackedResponsePublicationLitmus(t *testing.T) {
	cache := &DnsCache{
		Answer: []dnsmessage.RR{&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{Name: "publication.test.", Rrtype: dnsmessage.TypeA, Class: dnsmessage.ClassINET, Ttl: 1},
			A:   []byte{192, 0, 2, 1},
		}},
		Deadline: time.Now().Add(time.Hour),
	}
	if err := cache.prepackResponseWithTTL("publication.test.", dnsmessage.TypeA, 101, time.Now()); err != nil {
		t.Fatalf("initialize packed response: %v", err)
	}

	const iterations = 100_000
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	mismatch := make(chan struct {
		wireTTL uint32
		metaTTL uint32
	}, 1)

	go func() {
		defer wg.Done()
		<-start
		for i := range iterations {
			ttl := uint32(101)
			if i&1 != 0 {
				ttl = 202
			}
			if err := cache.prepackResponseWithTTL("publication.test.", dnsmessage.TypeA, ttl, time.Now()); err != nil {
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		<-start
		for range iterations {
			packed := cache.packedResponse.Load()
			if packed == nil {
				continue
			}
			var msg dnsmessage.Msg
			if err := msg.Unpack(packed.wire); err != nil || len(msg.Answer) == 0 {
				continue
			}
			wireTTL := msg.Answer[0].Header().Ttl
			if wireTTL == packed.ttl {
				continue
			}
			select {
			case mismatch <- struct {
				wireTTL uint32
				metaTTL uint32
			}{wireTTL: wireTTL, metaTTL: packed.ttl}:
			default:
			}
			return
		}
	}()
	close(start)
	wg.Wait()
	close(mismatch)

	if got, ok := <-mismatch; ok {
		t.Fatalf("observed packed response from generation %d with generation %d metadata", got.wireTTL, got.metaTTL)
	}
}

func TestRoutingEpochActiveSlotCacheRejectsStaleLookupLitmus(t *testing.T) {
	core := &controlPlaneCore{}
	core.publishActiveRoutingEpochSlotCache(0)
	staleObservation := core.routingEpochActiveSlotCache.Load()

	// A slow reader has already obtained slot 0 from the kernel map. The
	// publisher invalidates that observation and installs slot 1 before the
	// reader resumes and attempts to cache its stale lookup result.
	core.invalidateActiveRoutingEpochSlotCache()
	publishing := core.routingEpochActiveSlotCache.Load()
	if core.cacheActiveRoutingEpochSlot(publishing, 0) {
		t.Fatal("reader cached an old slot while selector publication was in progress")
	}
	if core.routingEpochActiveSlotCache.Load() != publishing {
		t.Fatal("reader replaced the in-progress selector publication token")
	}

	core.publishActiveRoutingEpochSlotCache(1)
	if core.cacheActiveRoutingEpochSlot(staleObservation, 0) {
		t.Fatal("stale lookup replaced the publisher's cache token")
	}

	published := core.routingEpochActiveSlotCache.Load()
	if published == nil || !published.valid || published.slot != 1 {
		t.Fatalf("active slot cache = %+v, want published slot 1", published)
	}
}

func TestRoutingEpochActiveSlotCacheFailedPublicationRestoresPeers(t *testing.T) {
	primary := &controlPlaneCore{}
	peer := &controlPlaneCore{}
	primary.publishActiveRoutingEpochSlotCache(0)
	peer.publishActiveRoutingEpochSlotCache(0)
	primaryPrevious := primary.routingEpochActiveSlotCache.Load()
	peerPrevious := peer.routingEpochActiveSlotCache.Load()

	publication := beginRoutingEpochActiveSlotCachePublication(primary, peer)
	for name, core := range map[string]*controlPlaneCore{"primary": primary, "peer": peer} {
		cached := core.routingEpochActiveSlotCache.Load()
		if cached == nil || !cached.publishing {
			t.Fatalf("%s cache = %+v during publication, want publishing token", name, cached)
		}
	}

	// ActiveRoutingEpochMap.Update failed, so the selector still names the
	// exact cache snapshots that preceded this publication attempt.
	publication.restore()
	if got := primary.routingEpochActiveSlotCache.Load(); got != primaryPrevious {
		t.Fatalf("primary cache = %p after failed publication, want %p", got, primaryPrevious)
	}
	if got := peer.routingEpochActiveSlotCache.Load(); got != peerPrevious {
		t.Fatalf("peer cache = %p after failed publication, want %p", got, peerPrevious)
	}
}
