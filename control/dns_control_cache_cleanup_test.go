/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	dnsmessage "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestDnsController_LookupExpiredCacheNonBlockingWithSlowRemoveCallback(t *testing.T) {
	c := &DnsController{
		cacheRemoveCallback: func(cache *DnsCache) error {
			time.Sleep(250 * time.Millisecond)
			return nil
		},
		janitorStop: make(chan struct{}),
		janitorDone: make(chan struct{}),
		evictorDone: make(chan struct{}),
		evictorQ:    make(chan *DnsCache, 8),
	}
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
	c := &DnsController{
		cacheRemoveCallback: func(cache *DnsCache) error {
			removed.Add(1)
			return nil
		},
	}

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
	c := &DnsController{
		cacheRemoveCallback: func(cache *DnsCache) error {
			removed.Add(1)
			return nil
		},
	}

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
	c := &DnsController{
		cacheRemoveCallback: func(cache *DnsCache) error {
			removed.Add(1)
			return nil
		},
	}

	cacheKey := "remove-key"
	c.dnsCache.Store(cacheKey, &DnsCache{Deadline: time.Now().Add(time.Minute)})

	c.RemoveDnsRespCache(cacheKey)

	_, ok := c.dnsCache.Load(cacheKey)
	require.False(t, ok, "cache should be removed")
	require.EqualValues(t, 1, removed.Load(), "remove callback should be called")
}

func TestDnsController_CloseNoPanicDuringBpfUpdate(t *testing.T) {
	var callbackCount atomic.Int32
	c := &DnsController{
		cacheAccessCallback: func(cache *DnsCache) error {
			callbackCount.Add(1)
			return nil
		},
		janitorStop: make(chan struct{}),
		janitorDone: make(chan struct{}),
		evictorDone: make(chan struct{}),
		evictorQ:    nil,
		log:         nil,
	}

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

func TestDnsController_UpdateDnsCacheTtlRemovesOnlyStaleIpsOnReplacement(t *testing.T) {
	type ipSet []string

	var (
		addedMu   sync.Mutex
		removedMu sync.Mutex
		added     []ipSet
		removed   []ipSet
	)

	controller := &DnsController{
		cacheAccessCallback: func(cache *DnsCache) error {
			addedMu.Lock()
			defer addedMu.Unlock()
			added = append(added, dnsCacheAnswerIPs(cache))
			return nil
		},
		cacheRemoveCallback: func(cache *DnsCache) error {
			removedMu.Lock()
			defer removedMu.Unlock()
			removed = append(removed, dnsCacheAnswerIPs(cache))
			return nil
		},
		newCache: func(fqdn string, answers, ns, extra []dnsmessage.RR, deadline time.Time, originalDeadline time.Time) (*DnsCache, error) {
			return &DnsCache{
				Answer:           answers,
				NS:               ns,
				Extra:            extra,
				Deadline:         deadline,
				OriginalDeadline: originalDeadline,
			}, nil
		},
	}

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
		cacheRemoveCallback: func(cache *DnsCache) error {
			if processed.Add(1) == 1 {
				close(firstStarted)
				<-releaseFirst
			}
			return nil
		},
		janitorStop: make(chan struct{}),
		janitorDone: make(chan struct{}),
		evictorDone: make(chan struct{}),
		evictorQ:    make(chan *DnsCache, 1),
		evictorWake: make(chan struct{}, 1),
	}
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
		cacheRemoveCallback: func(cache *DnsCache) error {
			if processed.Add(1) == 1 {
				close(firstStarted)
				<-releaseFirst
			}
			return nil
		},
		janitorStop: make(chan struct{}),
		janitorDone: make(chan struct{}),
		evictorDone: make(chan struct{}),
		evictorQ:    make(chan *DnsCache, 1),
		evictorWake: make(chan struct{}, 1),
	}
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
			ips = append(ips, net.IP(body.A).String())
		case *dnsmessage.AAAA:
			ips = append(ips, net.IP(body.AAAA).String())
		}
	}
	return ips
}
