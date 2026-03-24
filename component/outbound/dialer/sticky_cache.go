/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"sync"

	stickyip "github.com/daeuniverse/outbound/dialer/stickyip"
)

// Re-export from stickyip package
type StickyIpDialer = stickyip.StickyIpDialer
type ProxyIpCache = stickyip.ProxyIpCache

var NewProxyIpCache = stickyip.NewProxyIpCache

// globalProxyIpCache is the global cache for proxy server sticky IP entries.
// It ensures that the same proxy domain resolves to the same IP across all dialers.
var globalProxyIpCache = NewProxyIpCache()

// invalidateProxyCache removes the cached IP for a proxy address.
// This should be called when consecutive failures are detected.
func invalidateProxyCache(proxyAddr string) {
	globalProxyIpCache.Invalidate(proxyAddr)
}


// proxyIpHealthTracker tracks consecutive failures for proxy IPs.
type proxyIpHealthTracker struct {
	sync.Mutex
	failures map[string]int32 // proxy address -> consecutive failure count
}

var globalProxyIpHealthTracker = &proxyIpHealthTracker{
	failures: make(map[string]int32),
}

const maxConsecutiveFailures = 3

// recordProxyFailure records a failure for the given proxy address.
// Returns true if the threshold has been reached.
func recordProxyFailure(proxyAddr string) bool {
	globalProxyIpHealthTracker.Lock()
	defer globalProxyIpHealthTracker.Unlock()
	globalProxyIpHealthTracker.failures[proxyAddr]++
	count := globalProxyIpHealthTracker.failures[proxyAddr]
	if count >= maxConsecutiveFailures {
		// Reset counter after reaching threshold to allow retry
		delete(globalProxyIpHealthTracker.failures, proxyAddr)
		// Invalidate the cache to force IP refresh
		invalidateProxyCache(proxyAddr)
		return true
	}
	return false
}

// recordProxySuccess resets the failure counter for a proxy address.
func recordProxySuccess(proxyAddr string) {
	globalProxyIpHealthTracker.Lock()
	defer globalProxyIpHealthTracker.Unlock()
	delete(globalProxyIpHealthTracker.failures, proxyAddr)
}
