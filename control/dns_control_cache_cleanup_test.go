/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"sync/atomic"
	"testing"
	"time"

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
