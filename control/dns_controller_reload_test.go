/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

// TestDnsController_RuntimeWorkersSurviveContextCancel verifies that the BPF
// update worker, DNS cache janitor, and cache evictor do NOT exit when the old
// generation's lifecycle context is canceled during a staged reload.
//
// Regression test for: after reload, shared DnsController background workers
// keep watching the old generation's Done channel, exit during retirement, and
// stop maintaining DNS cache / domain_routing side effects after cutover.
func TestDnsController_RuntimeWorkersSurviveContextCancel(t *testing.T) {
	oldJanitorInterval := dnsCacheJanitorInterval
	dnsCacheJanitorInterval = 10 * time.Millisecond
	t.Cleanup(func() {
		dnsCacheJanitorInterval = oldJanitorInterval
	})

	// Phase 1: Create DNS controller with the "old generation" context.
	oldCtx, oldCancel := context.WithCancel(context.Background())
	defer oldCancel()

	var bpfUpdateCount atomic.Int64
	var cacheRemoveCount atomic.Int64
	log := logrus.New()
	log.SetLevel(logrus.DebugLevel)

	controller, err := NewDnsController(nil, &DnsControllerOption{
		Log:              log,
		LifecycleContext: oldCtx,
		CacheAccessCallback: func(cache *DnsCache) error {
			bpfUpdateCount.Add(1)
			return nil
		},
		CacheRemoveCallback: func(cache *DnsCache) error {
			cacheRemoveCount.Add(1)
			return nil
		},
	})
	require.NoError(t, err)
	require.NotNil(t, controller)
	defer func() { require.NoError(t, controller.Close()) }()

	// Trigger a BPF update to lazily start the worker.
	cache := &DnsCache{Deadline: time.Now().Add(time.Hour)}
	cache.MarkBpfUpdated(time.Time{}) // Force NeedsBpfUpdate to return true
	controller.triggerBpfUpdateIfNeeded(cache, time.Now().Add(-DnsCacheRouteRefreshInterval))
	// Wait for the worker to process the task.
	require.Eventually(t, func() bool { return bpfUpdateCount.Load() >= 1 }, 2*time.Second, 10*time.Millisecond,
		"BPF update worker should process initial task")

	// Phase 2: Simulate reload — UpdateRuntime with new context (as ReuseDNSControllerFrom does).
	newCtx, newCancel := context.WithCancel(context.Background())
	defer newCancel()

	controller.UpdateRuntime(&DnsControllerOption{
		Log:              log,
		LifecycleContext: newCtx,
		CacheAccessCallback: func(cache *DnsCache) error {
			bpfUpdateCount.Add(1)
			return nil
		},
		CacheRemoveCallback: func(cache *DnsCache) error {
			cacheRemoveCount.Add(1)
			return nil
		},
	}, nil)

	// Phase 3: Cancel the OLD context (simulates old CP retirement).
	oldCancel()
	// Give goroutines time to react to the cancellation.
	time.Sleep(100 * time.Millisecond)

	// Phase 4: Verify the BPF update worker is still alive by sending another update.
	countBefore := bpfUpdateCount.Load()
	cache2 := &DnsCache{Deadline: time.Now().Add(time.Hour)}
	cache2.MarkBpfUpdated(time.Time{})
	controller.triggerBpfUpdateIfNeeded(cache2, time.Now().Add(-DnsCacheRouteRefreshInterval))

	require.Eventually(t, func() bool { return bpfUpdateCount.Load() > countBefore }, 2*time.Second, 10*time.Millisecond,
		"BPF update worker must survive old context cancellation and continue processing tasks")

	// Phase 5: Verify the DNS cache janitor is still alive by evicting an expired entry.
	expiredKey := "expired.example.com.A"
	controller.dnsCache.Store(expiredKey, &DnsCache{
		Deadline:         time.Now().Add(-time.Second),
		OriginalDeadline: time.Now().Add(-time.Second),
	})
	require.Eventually(t, func() bool {
		_, ok := controller.dnsCache.Load(expiredKey)
		return !ok
	}, 2*time.Second, 10*time.Millisecond,
		"DNS cache janitor must survive old context cancellation and continue evicting expired cache entries")

	// Phase 6: Verify the cache evictor is still alive by delivering side-effect removals.
	removeCountBefore := cacheRemoveCount.Load()
	controller.onDnsCacheEvicted(&DnsCache{Deadline: time.Now().Add(time.Hour)})
	require.Eventually(t, func() bool { return cacheRemoveCount.Load() > removeCountBefore }, 2*time.Second, 10*time.Millisecond,
		"cache evictor must survive old context cancellation and continue draining removal callbacks")
}
