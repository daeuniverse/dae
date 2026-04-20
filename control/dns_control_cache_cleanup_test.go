/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"io"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func TestDnsController_LookupExpiredCacheNonBlockingWithSlowRemoveCallback(t *testing.T) {
	c := &DnsController{
		dnsControllerStore: &dnsControllerStore{
			janitorStop: make(chan struct{}),
			janitorDone: make(chan struct{}),
			evictorDone: make(chan struct{}),
			evictorQ:    make(chan *DnsCache, 8),
		},
	}
	setTestDnsControllerRuntime(c, func(rt *dnsControllerRuntimeState) {
		rt.cacheRemoveCallback = func(cache *DnsCache) error {
			time.Sleep(250 * time.Millisecond)
			return nil
		}
	})
	c.startCacheEvictor()
	defer func() {
		close(c.janitorStop)
		<-c.evictorDone
	}()

	cacheKey := "slow-remove"
	c.dnsCache.Store(cacheKey, &DnsCache{Deadline: time.Now().Add(-time.Second), OriginalDeadline: time.Now().Add(-time.Second)})

	start := time.Now()
	require.Nil(t, c.LookupDnsRespCache(cacheKey, false))
	elapsed := time.Since(start)

	require.Less(t, elapsed, 120*time.Millisecond, "expired lookup should not block on remove callback")
}

func TestDnsController_EvictExpiredDnsCache(t *testing.T) {
	var removed atomic.Int32
	c := setTestDnsControllerRuntime(&DnsController{}, func(rt *dnsControllerRuntimeState) {
		rt.cacheRemoveCallback = func(cache *DnsCache) error {
			removed.Add(1)
			return nil
		}
	})

	now := time.Now()
	expired := &DnsCache{Deadline: now.Add(-time.Second), OriginalDeadline: now.Add(-time.Second)}
	live := &DnsCache{Deadline: now.Add(time.Second), OriginalDeadline: now.Add(time.Second)}

	c.dnsCache.Store("expired", expired)
	c.dnsCache.Store("live", live)

	c.evictExpiredDnsCache(now)

	_, ok := c.dnsCache.Load("expired")
	require.False(t, ok, "expired cache must be removed")

	_, ok = c.dnsCache.Load("live")
	require.True(t, ok, "non-expired cache must be kept")

	require.EqualValues(t, 1, removed.Load(), "remove callback should be called once")
}

func TestDnsController_LookupExpiredCacheEvictsEntry(t *testing.T) {
	var removed atomic.Int32
	c := setTestDnsControllerRuntime(&DnsController{}, func(rt *dnsControllerRuntimeState) {
		rt.cacheRemoveCallback = func(cache *DnsCache) error {
			removed.Add(1)
			return nil
		}
	})

	cacheKey := "lookup-expired"
	now := time.Now()
	cache := &DnsCache{Deadline: now.Add(-time.Second), OriginalDeadline: now.Add(-time.Second)}
	c.dnsCache.Store(cacheKey, cache)

	require.Nil(t, c.LookupDnsRespCache(cacheKey, false))
	_, ok := c.dnsCache.Load(cacheKey)
	require.False(t, ok, "expired cache should be evicted on lookup")
	require.EqualValues(t, 1, removed.Load(), "remove callback should be called once")
}

func TestDnsController_RemoveDnsRespCacheTriggersCallback(t *testing.T) {
	var removed atomic.Int32
	c := setTestDnsControllerRuntime(&DnsController{}, func(rt *dnsControllerRuntimeState) {
		rt.cacheRemoveCallback = func(cache *DnsCache) error {
			removed.Add(1)
			return nil
		}
	})

	cacheKey := "remove-key"
	c.dnsCache.Store(cacheKey, &DnsCache{Deadline: time.Now().Add(time.Minute)})

	c.RemoveDnsRespCache(cacheKey)

	_, ok := c.dnsCache.Load(cacheKey)
	require.False(t, ok, "cache should be removed")
	require.EqualValues(t, 1, removed.Load(), "remove callback should be called")
}

func newDnsControllerForRemovalTracking(t *testing.T) (*DnsController, func() []string) {
	t.Helper()

	var (
		mu      sync.Mutex
		removed []string
	)
	controller := &DnsController{}
	setTestDnsControllerRuntime(controller, func(rt *dnsControllerRuntimeState) {
		rt.cacheRemoveCallback = func(cache *DnsCache) error {
			mu.Lock()
			defer mu.Unlock()
			removed = append(removed, dnsCacheAnswerIPs(cache)...)
			return nil
		}
		rt.newCache = func(fqdn string, answers, ns, extra []dnsmessage.RR, deadline time.Time, originalDeadline time.Time) (*DnsCache, error) {
			return &DnsCache{
				Answer:           answers,
				NS:               ns,
				Extra:            extra,
				Deadline:         deadline,
				OriginalDeadline: originalDeadline,
			}, nil
		}
	})
	snapshot := func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), removed...)
	}
	return controller, snapshot
}

func TestDnsController_RemoveDnsRespCache_PreservesSharedScopedIps(t *testing.T) {
	controller, removed := newDnsControllerForRemovalTracking(t)

	baseKey := controller.cacheKey("shared-remove.test.", dnsmessage.TypeA)
	req1 := &udpRequest{realDst: netip.MustParseAddrPort("8.8.8.8:53")}
	req2 := &udpRequest{realDst: netip.MustParseAddrPort("1.1.1.1:53")}
	cacheKey1 := controller.responseCacheKey(baseKey, req1, consts.DnsRequestOutboundIndex_AsIs, nil)
	cacheKey2 := controller.responseCacheKey(baseKey, req2, consts.DnsRequestOutboundIndex_AsIs, nil)

	require.NoError(t, controller.UpdateDnsCacheTtlWithKey(cacheKey1, "shared-remove.test.", dnsmessage.TypeA, dnsAResponseMsg("shared-remove.test.", "203.0.113.10").Answer, nil, nil, 60))
	require.NoError(t, controller.UpdateDnsCacheTtlWithKey(cacheKey2, "shared-remove.test.", dnsmessage.TypeA, dnsAResponseMsg("shared-remove.test.", "203.0.113.10").Answer, nil, nil, 60))

	controller.RemoveDnsRespCache(cacheKey1)

	require.Empty(t, removed(), "shared scoped IP should remain while another scoped cache entry is still live")
}

func TestDnsController_UpdateDnsCacheTtlWithKey_PreservesSharedScopedStaleIps(t *testing.T) {
	controller, removed := newDnsControllerForRemovalTracking(t)

	baseKey := controller.cacheKey("shared-refresh.test.", dnsmessage.TypeA)
	req1 := &udpRequest{realDst: netip.MustParseAddrPort("8.8.8.8:53")}
	req2 := &udpRequest{realDst: netip.MustParseAddrPort("1.1.1.1:53")}
	cacheKey1 := controller.responseCacheKey(baseKey, req1, consts.DnsRequestOutboundIndex_AsIs, nil)
	cacheKey2 := controller.responseCacheKey(baseKey, req2, consts.DnsRequestOutboundIndex_AsIs, nil)

	require.NoError(t, controller.UpdateDnsCacheTtlWithKey(cacheKey1, "shared-refresh.test.", dnsmessage.TypeA, dnsAResponseMsg("shared-refresh.test.", "203.0.113.10").Answer, nil, nil, 60))
	require.NoError(t, controller.UpdateDnsCacheTtlWithKey(cacheKey2, "shared-refresh.test.", dnsmessage.TypeA, dnsAResponseMsg("shared-refresh.test.", "203.0.113.10").Answer, nil, nil, 60))

	require.NoError(t, controller.UpdateDnsCacheTtlWithKey(cacheKey1, "shared-refresh.test.", dnsmessage.TypeA, dnsAResponseMsg("shared-refresh.test.", "203.0.113.20").Answer, nil, nil, 60))

	require.Empty(t, removed(), "refreshing one scoped cache entry must not remove an IP still present in a sibling scope")
}

func TestDnsController_RemoveDnsRespCacheFamily_DeduplicatesSharedScopedIps(t *testing.T) {
	controller, removed := newDnsControllerForRemovalTracking(t)

	baseKey := controller.cacheKey("shared-family.test.", dnsmessage.TypeA)
	req1 := &udpRequest{realDst: netip.MustParseAddrPort("8.8.8.8:53")}
	req2 := &udpRequest{realDst: netip.MustParseAddrPort("1.1.1.1:53")}
	cacheKey1 := controller.responseCacheKey(baseKey, req1, consts.DnsRequestOutboundIndex_AsIs, nil)
	cacheKey2 := controller.responseCacheKey(baseKey, req2, consts.DnsRequestOutboundIndex_AsIs, nil)

	require.NoError(t, controller.UpdateDnsCacheTtlWithKey(cacheKey1, "shared-family.test.", dnsmessage.TypeA, dnsAResponseMsg("shared-family.test.", "203.0.113.10").Answer, nil, nil, 60))
	require.NoError(t, controller.UpdateDnsCacheTtlWithKey(cacheKey2, "shared-family.test.", dnsmessage.TypeA, dnsAResponseMsg("shared-family.test.", "203.0.113.10").Answer, nil, nil, 60))

	controller.RemoveDnsRespCacheFamily(baseKey)

	require.Equal(t, []string{"203.0.113.10"}, removed(), "family removal should emit each shared scoped IP once")
}

func TestDnsController_RemoveDnsRespCache_RecomputesKnowledgeFromRemainingScopedEntries(t *testing.T) {
	ctrl := newScopedDnsController(t)

	baseKey := ctrl.cacheKey("knowledge-scope.test.", dnsmessage.TypeA)
	req1 := &udpRequest{realDst: netip.MustParseAddrPort("8.8.8.8:53")}
	req2 := &udpRequest{realDst: netip.MustParseAddrPort("1.1.1.1:53")}
	cacheKey1 := ctrl.responseCacheKey(baseKey, req1, consts.DnsRequestOutboundIndex_AsIs, nil)
	cacheKey2 := ctrl.responseCacheKey(baseKey, req2, consts.DnsRequestOutboundIndex_AsIs, nil)

	require.NoError(t, ctrl.__updateDnsCacheDeadline(cacheKey1, "knowledge-scope.test.", dnsmessage.TypeA, dnsAResponseMsg("knowledge-scope.test.", "8.8.8.8").Answer, nil, nil, func(now time.Time, _ string) (time.Time, time.Time) {
		deadline := now.Add(25 * time.Millisecond)
		return deadline, deadline
	}))
	require.NoError(t, ctrl.__updateDnsCacheDeadline(cacheKey2, "knowledge-scope.test.", dnsmessage.TypeA, dnsAResponseMsg("knowledge-scope.test.", "1.1.1.1").Answer, nil, nil, func(now time.Time, _ string) (time.Time, time.Time) {
		deadline := now.Add(150 * time.Millisecond)
		return deadline, deadline
	}))

	require.True(t, ctrl.HasDnsKnowledge(baseKey), "knowledge should exist while scoped cache entries are present")

	ctrl.RemoveDnsRespCache(cacheKey2)

	require.True(t, ctrl.HasDnsKnowledge(baseKey), "knowledge should fall back to the remaining scoped cache entry")
	require.Eventually(t, func() bool {
		return !ctrl.HasDnsKnowledge(baseKey)
	}, 300*time.Millisecond, 10*time.Millisecond, "knowledge should expire with the last remaining scoped cache entry, not the removed one")
}

func TestDnsController_EvictExpiredDnsCache_RemovesKnowledgeForLastScopedEntry(t *testing.T) {
	ctrl := newScopedDnsController(t)

	baseKey := ctrl.cacheKey("knowledge-expire.test.", dnsmessage.TypeA)
	req := &udpRequest{realDst: netip.MustParseAddrPort("9.9.9.9:53")}
	cacheKey := ctrl.responseCacheKey(baseKey, req, consts.DnsRequestOutboundIndex_AsIs, nil)

	require.NoError(t, ctrl.__updateDnsCacheDeadline(cacheKey, "knowledge-expire.test.", dnsmessage.TypeA, dnsAResponseMsg("knowledge-expire.test.", "9.9.9.9").Answer, nil, nil, func(now time.Time, _ string) (time.Time, time.Time) {
		deadline := now.Add(20 * time.Millisecond)
		return deadline, deadline
	}))
	require.True(t, ctrl.HasDnsKnowledge(baseKey), "knowledge should exist before expiry")

	time.Sleep(40 * time.Millisecond)
	ctrl.evictExpiredDnsCache(time.Now())

	require.False(t, ctrl.HasDnsKnowledge(baseKey), "expiring the last scoped cache entry should clear dns knowledge")
	_, ok := ctrl.dnsCache.Load(cacheKey)
	require.False(t, ok, "expired cache entry should be evicted")
}

func TestDnsController_EvictLRUIfFull_RemovesKnowledgeForEvictedBaseKey(t *testing.T) {
	ctrl := newScopedDnsController(t)
	ctrl.maxCacheSize.Store(1)

	baseKey1 := ctrl.cacheKey("knowledge-lru-old.test.", dnsmessage.TypeA)
	req1 := &udpRequest{realDst: netip.MustParseAddrPort("8.8.4.4:53")}
	cacheKey1 := ctrl.responseCacheKey(baseKey1, req1, consts.DnsRequestOutboundIndex_AsIs, nil)
	require.NoError(t, ctrl.UpdateDnsCacheTtlWithKey(cacheKey1, "knowledge-lru-old.test.", dnsmessage.TypeA, dnsAResponseMsg("knowledge-lru-old.test.", "8.8.4.4").Answer, nil, nil, 60))

	baseKey2 := ctrl.cacheKey("knowledge-lru-new.test.", dnsmessage.TypeA)
	req2 := &udpRequest{realDst: netip.MustParseAddrPort("1.0.0.1:53")}
	cacheKey2 := ctrl.responseCacheKey(baseKey2, req2, consts.DnsRequestOutboundIndex_AsIs, nil)
	require.NoError(t, ctrl.UpdateDnsCacheTtlWithKey(cacheKey2, "knowledge-lru-new.test.", dnsmessage.TypeA, dnsAResponseMsg("knowledge-lru-new.test.", "1.0.0.1").Answer, nil, nil, 60))

	oldValue, ok := ctrl.dnsCache.Load(cacheKey1)
	require.True(t, ok)
	oldCache, ok := oldValue.(*DnsCache)
	require.True(t, ok)
	oldCache.lastAccessNano.Store(time.Now().Add(-time.Minute).UnixNano())

	newValue, ok := ctrl.dnsCache.Load(cacheKey2)
	require.True(t, ok)
	newCache, ok := newValue.(*DnsCache)
	require.True(t, ok)
	newCache.lastAccessNano.Store(time.Now().UnixNano())

	ctrl.evictLRUIfFull()

	require.False(t, ctrl.HasDnsKnowledge(baseKey1), "knowledge should be cleared for the base key evicted by LRU")
	require.True(t, ctrl.HasDnsKnowledge(baseKey2), "knowledge for the surviving cache entry should remain")
	_, ok = ctrl.dnsCache.Load(cacheKey1)
	require.False(t, ok, "oldest cache entry should be evicted by LRU")
}

func TestDnsController_CloseNoPanicDuringBpfUpdate(t *testing.T) {
	var callbackCount atomic.Int32
	c := &DnsController{
		dnsControllerStore: &dnsControllerStore{
			janitorStop: make(chan struct{}),
			janitorDone: make(chan struct{}),
			evictorDone: make(chan struct{}),
			evictorQ:    nil,
		},
		log: nil,
	}
	setTestDnsControllerRuntime(c, func(rt *dnsControllerRuntimeState) {
		rt.cacheAccessCallback = func(cache *DnsCache) error {
			callbackCount.Add(1)
			return nil
		}
	})

	c.startDnsCacheJanitor()
	c.startCacheEvictor()

	var wg sync.WaitGroup
	stopCh := make(chan struct{})

	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stopCh:
					return
				default:
					cache := &DnsCache{
						Deadline:         time.Now().Add(time.Minute),
						OriginalDeadline: time.Now().Add(time.Minute),
					}
					c.triggerBpfUpdateIfNeeded(cache, time.Now())
					runtime.Gosched()
				}
			}
		}()
	}

	time.Sleep(5 * time.Millisecond)

	close(stopCh)

	done := make(chan error, 1)
	go func() {
		done <- c.Close()
	}()

	select {
	case err := <-done:
		require.NoError(t, err, "Close should not return error")
	case <-time.After(5 * time.Second):
		t.Fatal("Close took too long - possible deadlock")
	}

	wg.Wait()
}

func TestDnsController_CloseWaitsForShutdownTasksConcurrently(t *testing.T) {
	oldTimeout := gracefulShutdownWaitTimeout
	gracefulShutdownWaitTimeout = 100 * time.Millisecond
	defer func() {
		gracefulShutdownWaitTimeout = oldTimeout
	}()

	logger := logrus.New()
	logger.SetOutput(io.Discard)

	c := &DnsController{
		dnsControllerStore: &dnsControllerStore{
			janitorStop:   make(chan struct{}),
			janitorDone:   make(chan struct{}),
			evictorDone:   make(chan struct{}),
			bpfUpdateStop: make(chan struct{}),
		},
		log: logger,
	}
	c.bpfUpdateWg.Add(1)

	start := time.Now()
	err := c.Close()
	elapsed := time.Since(start)

	c.bpfUpdateWg.Done()

	require.NoError(t, err)
	require.Less(t, elapsed, 220*time.Millisecond, "shutdown waits should run concurrently instead of stacking")
}

func TestDnsController_OnDnsCacheEvictedConcurrentClose(t *testing.T) {
	janitorDone := make(chan struct{})
	evictorDone := make(chan struct{})
	close(janitorDone)
	close(evictorDone)

	controller := &DnsController{
		dnsControllerStore: &dnsControllerStore{
			janitorStop: make(chan struct{}),
			janitorDone: janitorDone,
			evictorDone: evictorDone,
			evictorQ:    make(chan *DnsCache, 1),
			evictorWake: make(chan struct{}, 1),
		},
	}
	setTestDnsControllerRuntime(controller, func(rt *dnsControllerRuntimeState) {
		rt.cacheRemoveCallback = func(cache *DnsCache) error { return nil }
	})

	const (
		goroutines = 8
		iterations = 256
	)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < iterations; j++ {
				controller.onDnsCacheEvicted(&DnsCache{})
			}
		}()
	}

	closeDone := make(chan error, 1)
	go func() {
		<-start
		closeDone <- controller.Close()
	}()

	close(start)
	wg.Wait()
	require.NoError(t, <-closeDone)
}

func TestDnsController_UpdateDnsCacheTtlRemovesOnlyStaleIpsOnReplacement(t *testing.T) {
	type ipSet []string

	var (
		addedMu   sync.Mutex
		removedMu sync.Mutex
		added     []ipSet
		removed   []ipSet
	)

	controller := &DnsController{}
	setTestDnsControllerRuntime(controller, func(rt *dnsControllerRuntimeState) {
		rt.cacheAccessCallback = func(cache *DnsCache) error {
			addedMu.Lock()
			defer addedMu.Unlock()
			added = append(added, dnsCacheAnswerIPs(cache))
			return nil
		}
		rt.cacheRemoveCallback = func(cache *DnsCache) error {
			removedMu.Lock()
			defer removedMu.Unlock()
			removed = append(removed, dnsCacheAnswerIPs(cache))
			return nil
		}
		rt.newCache = func(fqdn string, answers, ns, extra []dnsmessage.RR, deadline time.Time, originalDeadline time.Time) (*DnsCache, error) {
			return &DnsCache{
				Answer:           answers,
				NS:               ns,
				Extra:            extra,
				Deadline:         deadline,
				OriginalDeadline: originalDeadline,
			}, nil
		}
	})

	require.NoError(t, controller.UpdateDnsCacheTtl("example.com.", dnsmessage.TypeA, []dnsmessage.RR{
		newTestARecord("example.com.", "1.1.1.1"),
		newTestARecord("example.com.", "2.2.2.2"),
	}, nil, nil, 60))

	require.NoError(t, controller.UpdateDnsCacheTtl("example.com.", dnsmessage.TypeA, []dnsmessage.RR{
		newTestARecord("example.com.", "2.2.2.2"),
		newTestARecord("example.com.", "3.3.3.3"),
	}, nil, nil, 60))

	addedMu.Lock()
	defer addedMu.Unlock()
	removedMu.Lock()
	defer removedMu.Unlock()

	require.Len(t, added, 2)
	require.Equal(t, ipSet{"1.1.1.1", "2.2.2.2"}, added[0])
	require.Equal(t, ipSet{"2.2.2.2", "3.3.3.3"}, added[1])
	require.Len(t, removed, 1)
	require.Equal(t, ipSet{"1.1.1.1"}, removed[0], "only IPs absent from the refreshed cache should be removed")
}

func TestStaleDnsSideEffectsSkipsSharedIps(t *testing.T) {
	prev := &DnsCache{
		Answer: []dnsmessage.RR{
			newTestARecord("example.com.", "1.1.1.1"),
			newTestARecord("example.com.", "2.2.2.2"),
		},
	}
	next := &DnsCache{
		Answer: []dnsmessage.RR{
			newTestARecord("example.com.", "2.2.2.2"),
			newTestARecord("example.com.", "3.3.3.3"),
		},
	}

	stale := staleDnsSideEffects(prev, next)
	require.NotNil(t, stale)
	require.Equal(t, []string{"1.1.1.1"}, dnsCacheAnswerIPs(stale))
}

func TestStaleDnsSideEffectsSupportsTailSubslice(t *testing.T) {
	prev := &DnsCache{
		Answer: []dnsmessage.RR{
			newTestARecord("example.com.", "1.1.1.1"),
			newTestARecord("example.com.", "2.2.2.2"),
		},
	}
	next := &DnsCache{
		Answer: []dnsmessage.RR{
			newTestARecord("example.com.", "1.1.1.1"),
			newTestARecord("example.com.", "3.3.3.3"),
		},
	}

	stale := staleDnsSideEffects(prev, next)
	require.NotNil(t, stale)
	require.Equal(t, []string{"2.2.2.2"}, dnsCacheAnswerIPs(stale))
	require.Same(t, prev.Answer[1], stale.Answer[0], "single stale answers should reuse the original RR without copying")
}

func TestDnsController_EvictorSpillAvoidsGoroutineBurst(t *testing.T) {
	var processed atomic.Int32
	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})

	controller := &DnsController{
		dnsControllerStore: &dnsControllerStore{
			janitorStop: make(chan struct{}),
			janitorDone: make(chan struct{}),
			evictorDone: make(chan struct{}),
			evictorQ:    make(chan *DnsCache, 1),
			evictorWake: make(chan struct{}, 1),
		},
	}
	setTestDnsControllerRuntime(controller, func(rt *dnsControllerRuntimeState) {
		rt.cacheRemoveCallback = func(cache *DnsCache) error {
			if processed.Add(1) == 1 {
				close(firstStarted)
				<-releaseFirst
			}
			return nil
		}
	})
	controller.startCacheEvictor()
	defer func() {
		close(controller.janitorStop)
		<-controller.evictorDone
	}()

	controller.onDnsCacheEvicted(&DnsCache{})
	<-firstStarted

	baseGoroutines := runtime.NumGoroutine()
	const overflowed = 256
	for i := 0; i < overflowed; i++ {
		controller.onDnsCacheEvicted(&DnsCache{})
	}

	time.Sleep(50 * time.Millisecond)
	afterGoroutines := runtime.NumGoroutine()
	require.Less(t, afterGoroutines-baseGoroutines, 8, "overflow eviction path should not create a goroutine per item")

	close(releaseFirst)
	require.Eventually(t, func() bool {
		return processed.Load() == overflowed+1
	}, 3*time.Second, 10*time.Millisecond, "all evicted caches should still be processed")
}

func TestDnsController_EvictorShutdownDrainsSpill(t *testing.T) {
	var processed atomic.Int32
	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})

	controller := &DnsController{
		dnsControllerStore: &dnsControllerStore{
			janitorStop: make(chan struct{}),
			janitorDone: make(chan struct{}),
			evictorDone: make(chan struct{}),
			evictorQ:    make(chan *DnsCache, 1),
			evictorWake: make(chan struct{}, 1),
		},
	}
	setTestDnsControllerRuntime(controller, func(rt *dnsControllerRuntimeState) {
		rt.cacheRemoveCallback = func(cache *DnsCache) error {
			if processed.Add(1) == 1 {
				close(firstStarted)
				<-releaseFirst
			}
			return nil
		}
	})
	controller.startCacheEvictor()

	const total = 32
	controller.onDnsCacheEvicted(&DnsCache{})
	<-firstStarted
	for i := 1; i < total; i++ {
		controller.onDnsCacheEvicted(&DnsCache{})
	}

	done := make(chan struct{})
	go func() {
		close(controller.janitorStop)
		<-controller.evictorDone
		close(done)
	}()

	select {
	case <-done:
		t.Fatal("evictor exited before the in-flight callback completed")
	case <-time.After(50 * time.Millisecond):
	}

	close(releaseFirst)

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("evictor shutdown did not finish in time")
	}

	require.EqualValues(t, total, processed.Load(), "shutdown should drain queued and spilled evictions")
}

func newTestARecord(name, ip string) *dnsmessage.A {
	return &dnsmessage.A{
		Hdr: dnsmessage.RR_Header{
			Name:   name,
			Rrtype: dnsmessage.TypeA,
			Class:  dnsmessage.ClassINET,
			Ttl:    60,
		},
		A: net.ParseIP(ip).To4(),
	}
}

func dnsCacheAnswerIPs(cache *DnsCache) []string {
	if cache == nil {
		return nil
	}
	var ips []string
	for _, ans := range cache.Answer {
		switch body := ans.(type) {
		case *dnsmessage.A:
			ips = append(ips, body.A.String())
		case *dnsmessage.AAAA:
			ips = append(ips, body.AAAA.String())
		}
	}
	return ips
}
