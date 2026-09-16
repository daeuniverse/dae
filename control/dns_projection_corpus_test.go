/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	stderrors "errors"
	"testing"
	"time"
)

func TestPhase5DnsProjectionLifecycleCorpusTTLRetrySharedIPAcrossEpoch(t *testing.T) {
	t0 := time.Date(2042, time.March, 14, 15, 9, 26, 0, time.UTC)
	controller := newTestDnsController()
	oldTracker := newDomainRoutingTracker()
	newTracker := newDomainRoutingTracker()

	cacheA := domainRoutingACache("phase5-a.example.:1", "203.0.113.77", domainRoutingBitmap(0x1))
	cacheA.RouteProjectionEpoch = 1
	cacheA.Deadline = t0.Add(time.Minute)
	cacheA.OriginalDeadline = cacheA.Deadline
	cacheB := domainRoutingACache("phase5-b.example.:1", "203.0.113.77", domainRoutingBitmap(0x2))
	cacheB.RouteProjectionEpoch = 1
	cacheB.Deadline = t0.Add(2 * time.Minute)
	cacheB.OriginalDeadline = cacheB.Deadline
	controller.storeDnsCache(cacheA.RouteOwnerKey, cacheA)
	controller.storeDnsCache(cacheB.RouteOwnerKey, cacheB)

	var oldProjectionCalls int
	failCacheA := false
	setTestDnsControllerRuntime(controller, func(rt *dnsControllerRuntimeState) {
		rt.routeProjectionEpoch = 1
		rt.cacheAccessCallback = func(cache *DnsCache) error {
			oldProjectionCalls++
			if failCacheA && cache == cacheA {
				return stderrors.New("phase 5 projection failure")
			}
			return phase5ProjectCache(oldTracker, 0, cache)
		}
	})
	oldRuntime := controller.runtime()

	for _, cache := range []*DnsCache{cacheA, cacheB} {
		if !controller.processBpfUpdateTask(phase5ProjectionTask(cache, oldRuntime), false) {
			t.Fatalf("initial projection for %q was not processed", cache.RouteOwnerKey)
		}
	}
	phase5RequireTrackerBitmap(t, oldTracker, cacheA, 0x3)

	controller.bpfRetryWake = make(chan struct{}, 1)
	controller.bpfRetryPending = make(map[bpfProjectionRetryKey]*bpfUpdateTask)
	failCacheA = true
	if !controller.processBpfUpdateTask(phase5ProjectionTask(cacheA, oldRuntime), false) {
		t.Fatal("failed projection was not processed")
	}
	retries, overflow := controller.takeBpfProjectionRetryIntents()
	if overflow {
		t.Fatal("unexpected retry overflow")
	}
	if len(retries) != 1 {
		t.Fatalf("retry intents = %d, want 1", len(retries))
	}
	retry := retries[0]
	if retry.retryAttempt != 1 {
		t.Fatalf("retry attempt = %d, want 1", retry.retryAttempt)
	}
	scheduler := newBpfProjectionRetryScheduler()
	scheduler.addAt(retry, t0)
	if due := scheduler.popDue(t0.Add(bpfProjectionRetryDelay(retry.retryAttempt)).Add(-time.Nanosecond)); len(due) != 0 {
		t.Fatalf("early retries = %d, want 0", len(due))
	}

	cacheA2 := cacheA.CloneForReload()
	cacheA2.RouteProjectionEpoch = 2
	cacheA2.DomainBitmap = domainRoutingBitmap(0x4)
	cacheB2 := cacheB.CloneForReload()
	cacheB2.RouteProjectionEpoch = 2
	cacheB2.DomainBitmap = domainRoutingBitmap(0x2)
	controller.storeDnsCache(cacheA2.RouteOwnerKey, cacheA2)
	controller.storeDnsCache(cacheB2.RouteOwnerKey, cacheB2)

	var newProjectionCalls int
	setTestDnsControllerRuntime(controller, func(rt *dnsControllerRuntimeState) {
		rt.routeProjectionEpoch = 2
		rt.cacheAccessCallback = func(cache *DnsCache) error {
			newProjectionCalls++
			return phase5ProjectCache(newTracker, 1, cache)
		}
		rt.cacheDeleteCallback = func(_ string, cache *DnsCache) error {
			return phase5RemoveCache(newTracker, 1, cache)
		}
	})
	newRuntime := controller.runtime()

	due := scheduler.popDue(t0.Add(bpfProjectionRetryDelay(retry.retryAttempt)))
	if len(due) != 1 {
		t.Fatalf("due retries = %d, want 1", len(due))
	}
	oldCallsBeforeStaleRetry := oldProjectionCalls
	if !controller.processBpfUpdateTask(due[0], false) {
		t.Fatal("stale retry was not processed")
	}
	if oldProjectionCalls != oldCallsBeforeStaleRetry || newProjectionCalls != 0 {
		t.Fatalf("stale retry invoked projection callbacks: old=%d new=%d", oldProjectionCalls, newProjectionCalls)
	}
	if _, ok := scheduler.nextDue(); ok {
		t.Fatal("stale retry remained scheduled")
	}
	phase5RequireTrackerBitmap(t, oldTracker, cacheA, 0x3)

	for _, cache := range []*DnsCache{cacheA2, cacheB2} {
		if !controller.processBpfUpdateTask(phase5ProjectionTask(cache, newRuntime), false) {
			t.Fatalf("epoch 2 projection for %q was not processed", cache.RouteOwnerKey)
		}
	}
	phase5RequireTrackerBitmap(t, newTracker, cacheA2, 0x6)

	controller.evictExpiredDnsCache(cacheA2.Deadline)
	if _, ok := controller.dnsCache.Load(cacheA2.RouteOwnerKey); ok {
		t.Fatal("expired owner A remained in the DNS cache")
	}
	if _, ok := controller.dnsCache.Load(cacheB2.RouteOwnerKey); !ok {
		t.Fatal("unexpired owner B was removed from the DNS cache")
	}
	phase5RequireTrackerBitmap(t, newTracker, cacheB2, 0x2)
	phase5RequireTrackerBitmap(t, oldTracker, cacheA, 0x3)

	controller.evictExpiredDnsCache(cacheB2.Deadline)
	phase5RequireTrackerAbsent(t, newTracker, cacheB2)
}

func phase5ProjectionTask(cache *DnsCache, runtime *dnsControllerRuntimeState) *bpfUpdateTask {
	return &bpfUpdateTask{
		cache:                cache,
		routeProjectionEpoch: runtime.routeProjectionEpoch,
	}
}

func phase5ProjectCache(tracker *domainRoutingTracker, slot uint32, cache *DnsCache) error {
	snapshot, err := buildDomainRoutingOwnerSnapshot(cache)
	if err != nil {
		return err
	}
	return tracker.syncOwnerForSlot(nil, slot, cache.RouteOwnerKey, snapshot)
}

func phase5RemoveCache(tracker *domainRoutingTracker, slot uint32, cache *DnsCache) error {
	return tracker.syncOwnerForSlot(nil, slot, cache.RouteOwnerKey, domainRoutingOwnerSnapshot{})
}

func phase5RequireTrackerBitmap(t *testing.T, tracker *domainRoutingTracker, cache *DnsCache, want uint32) {
	t.Helper()
	got, ok := phase5TrackerBitmapForCache(t, tracker, cache)
	if !ok {
		t.Fatalf("domain routing state for %q is absent", cache.RouteOwnerKey)
	}
	if got != want {
		t.Fatalf("domain routing bitmap for %q = %#x, want %#x", cache.RouteOwnerKey, got, want)
	}
}

func phase5RequireTrackerAbsent(t *testing.T, tracker *domainRoutingTracker, cache *DnsCache) {
	t.Helper()
	if got, ok := phase5TrackerBitmapForCache(t, tracker, cache); ok {
		t.Fatalf("domain routing state for %q = %#x, want absent", cache.RouteOwnerKey, got)
	}
}

func phase5TrackerBitmapForCache(t *testing.T, tracker *domainRoutingTracker, cache *DnsCache) (uint32, bool) {
	t.Helper()
	snapshot, err := buildDomainRoutingOwnerSnapshot(cache)
	if err != nil {
		t.Fatalf("build domain routing snapshot for %q: %v", cache.RouteOwnerKey, err)
	}
	if len(snapshot.ips) != 1 {
		t.Fatalf("domain routing IP count for %q = %d, want 1", cache.RouteOwnerKey, len(snapshot.ips))
	}
	for key := range snapshot.ips {
		tracker.mu.Lock()
		state := tracker.ips[key]
		tracker.mu.Unlock()
		if state == nil {
			return 0, false
		}
		return state.merged.Bitmap[0], true
	}
	return 0, false
}
