/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"sync"
	"sync/atomic"
	"time"

	stickyip "github.com/daeuniverse/outbound/dialer/stickyip"
)

// Re-export from stickyip package
type StickyIpDialer = stickyip.StickyIpDialer
type ProxyIpCache = stickyip.ProxyIpCache

var NewProxyIpCache = stickyip.NewProxyIpCache

// globalProxyIpCache is the global cache for proxy server sticky IP entries.
// It ensures that the same proxy domain resolves to the same IP across all dialers.
var globalProxyIpCache = NewProxyIpCache()

type proxyIpCacheRegistry struct {
	sync.Mutex
	caches map[string]map[*ProxyIpCache]int
}

var globalProxyIpCacheRegistry = &proxyIpCacheRegistry{
	caches: make(map[string]map[*ProxyIpCache]int),
}

func registerProxyCache(proxyAddr string, cache *ProxyIpCache) {
	if proxyAddr == "" || cache == nil || cache == globalProxyIpCache {
		return
	}
	globalProxyIpCacheRegistry.Lock()
	defer globalProxyIpCacheRegistry.Unlock()
	cacheSet := globalProxyIpCacheRegistry.caches[proxyAddr]
	if cacheSet == nil {
		cacheSet = make(map[*ProxyIpCache]int)
		globalProxyIpCacheRegistry.caches[proxyAddr] = cacheSet
	}
	cacheSet[cache]++
}

func unregisterProxyCache(proxyAddr string, cache *ProxyIpCache) {
	if proxyAddr == "" || cache == nil || cache == globalProxyIpCache {
		return
	}
	globalProxyIpCacheRegistry.Lock()
	defer globalProxyIpCacheRegistry.Unlock()
	cacheSet := globalProxyIpCacheRegistry.caches[proxyAddr]
	if cacheSet == nil {
		return
	}
	cacheSet[cache]--
	if cacheSet[cache] <= 0 {
		delete(cacheSet, cache)
	}
	if len(cacheSet) == 0 {
		delete(globalProxyIpCacheRegistry.caches, proxyAddr)
	}
}

// invalidateProxyCache removes the cached IP for a proxy address.
// This should be called when consecutive failures are detected.
func invalidateProxyCache(proxyAddr string) {
	globalProxyIpCache.Invalidate(proxyAddr)

	globalProxyIpCacheRegistry.Lock()
	cacheSet := globalProxyIpCacheRegistry.caches[proxyAddr]
	caches := make([]*ProxyIpCache, 0, len(cacheSet))
	for cache := range cacheSet {
		caches = append(caches, cache)
	}
	globalProxyIpCacheRegistry.Unlock()

	for _, cache := range caches {
		cache.Invalidate(proxyAddr)
	}
}

// proxyIpHealthTracker tracks consecutive failures for proxy IPs.
type proxyIpHealthTracker struct {
	sync.Mutex
	failures      map[string]proxyIpFailureEntry
	nextCleanupAt time.Time
}

var globalProxyIpHealthTracker = &proxyIpHealthTracker{
	failures: make(map[string]proxyIpFailureEntry),
}

var reloadProxyFailureSuppression atomic.Int32
var reloadProxyFailureSuppressUntil atomic.Int64

type proxyIpFailureEntry struct {
	count       int32
	lastUpdated time.Time
}

const (
	maxConsecutiveFailures      = 3
	proxyFailureTTL             = 15 * time.Minute
	proxyFailureCleanupInterval = 5 * time.Minute
	reloadFailureQuiesce        = Timeout + 10*time.Second
)

func (t *proxyIpHealthTracker) maybeCleanupLocked(now time.Time) {
	if !t.nextCleanupAt.IsZero() && now.Before(t.nextCleanupAt) {
		return
	}
	for proxyAddr, entry := range t.failures {
		if now.Sub(entry.lastUpdated) >= proxyFailureTTL {
			delete(t.failures, proxyAddr)
		}
	}
	t.nextCleanupAt = now.Add(proxyFailureCleanupInterval)
}

func resetGlobalProxyState() {
	globalProxyIpCache = NewProxyIpCache()

	globalProxyIpCacheRegistry.Lock()
	globalProxyIpCacheRegistry.caches = make(map[string]map[*ProxyIpCache]int)
	globalProxyIpCacheRegistry.Unlock()

	globalProxyIpHealthTracker.Lock()
	globalProxyIpHealthTracker.failures = make(map[string]proxyIpFailureEntry)
	globalProxyIpHealthTracker.nextCleanupAt = time.Time{}
	globalProxyIpHealthTracker.Unlock()
}

// ResetGlobalProxyStateForReload rotates process-global proxy sticky-IP and
// failure-tracker state before building a replacement generation. Existing
// dialers keep using the cache objects they already hold, while the new
// generation starts from a clean global view instead of inheriting poisoned
// proxy IP or failure state from the previous generation.
func ResetGlobalProxyStateForReload() {
	resetGlobalProxyState()
}

// BeginReloadProxyFailureSuppression suppresses cross-dialer proxy-IP failure
// promotion while reload is actively cutting over between generations. The
// matching EndReloadProxyFailureSuppression must be called when the reload
// attempt fully settles or aborts.
func BeginReloadProxyFailureSuppression() {
	reloadProxyFailureSuppression.Add(1)
}

// EndReloadProxyFailureSuppression releases one outstanding reload-time
// suppression scope.
func EndReloadProxyFailureSuppression() {
	for {
		current := reloadProxyFailureSuppression.Load()
		if current <= 0 {
			return
		}
		if reloadProxyFailureSuppression.CompareAndSwap(current, current-1) {
			if current == 1 {
				reloadProxyFailureSuppressUntil.Store(time.Now().Add(reloadFailureQuiesce).UnixNano())
			}
			return
		}
	}
}

func proxyFailureSuppressedForReload() bool {
	if reloadProxyFailureSuppression.Load() > 0 {
		return true
	}
	return time.Now().UnixNano() < reloadProxyFailureSuppressUntil.Load()
}

// recordProxyFailure records a failure for the given proxy address.
// Returns true if the threshold has been reached.
func recordProxyFailure(proxyAddr string) bool {
	now := time.Now()

	globalProxyIpHealthTracker.Lock()
	globalProxyIpHealthTracker.maybeCleanupLocked(now)

	entry := globalProxyIpHealthTracker.failures[proxyAddr]
	entry.count++
	entry.lastUpdated = now

	if entry.count >= maxConsecutiveFailures {
		delete(globalProxyIpHealthTracker.failures, proxyAddr)
		globalProxyIpHealthTracker.Unlock()

		// Invalidate the cache to force IP refresh.
		invalidateProxyCache(proxyAddr)
		return true
	}

	globalProxyIpHealthTracker.failures[proxyAddr] = entry
	globalProxyIpHealthTracker.Unlock()
	return false
}

// recordProxySuccess resets the failure counter for a proxy address.
func recordProxySuccess(proxyAddr string) {
	globalProxyIpHealthTracker.Lock()
	defer globalProxyIpHealthTracker.Unlock()
	delete(globalProxyIpHealthTracker.failures, proxyAddr)
}
