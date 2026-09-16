/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/dns"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

type dnsKnowledgeEntry struct {
	expiresAt  int64
	cacheCount int
}

func parseDnsKnowledgeEntry(value any) (dnsKnowledgeEntry, bool) {
	switch value := value.(type) {
	case dnsKnowledgeEntry:
		return value, true
	case int64:
		// Accept legacy/test values written before cache-family counts existed.
		return dnsKnowledgeEntry{expiresAt: value}, true
	default:
		return dnsKnowledgeEntry{}, false
	}
}

// storeDnsCache publishes a cache entry and keeps the base-key index in sync.
// Callers must hold cacheProjectionMu for writing: the index and the size
// counter are only ever mutated under that lock, which is what lets the janitor
// reconciliation read both as one consistent snapshot.
func (c *DnsController) storeDnsCache(cacheKey string, cache *DnsCache) (previous any, loaded bool) {
	previous, loaded = c.dnsCache.Swap(cacheKey, cache)
	if !loaded {
		c.dnsCacheSize.Add(1)
	}
	c.dnsCacheIndexAdd(cacheKey)
	return previous, loaded
}

func (c *DnsController) loadAndDeleteDnsCache(cacheKey string) (value any, loaded bool) {
	value, loaded = c.dnsCache.LoadAndDelete(cacheKey)
	if loaded {
		c.decrementDnsCacheSize()
		c.dnsCacheIndexRemove(cacheKey)
	}
	return value, loaded
}

func (c *DnsController) compareAndDeleteDnsCache(cacheKey string, cache *DnsCache) bool {
	if !c.dnsCache.CompareAndDelete(cacheKey, cache) {
		return false
	}
	c.decrementDnsCacheSize()
	c.dnsCacheIndexRemove(cacheKey)
	return true
}

// deleteDnsCacheEntry drops a cache entry addressed by its raw sync.Map key,
// keeping the entry-removal side effects in one place. The base-key index only
// tracks string keys, so a non-string key (reachable only from corrupted state)
// is dropped from the map and the size counter without an index update.
func (c *DnsController) deleteDnsCacheEntry(key any) {
	cacheKey, ok := key.(string)
	if !ok {
		if _, loaded := c.dnsCache.LoadAndDelete(key); loaded {
			c.decrementDnsCacheSize()
		}
		return
	}
	c.loadAndDeleteDnsCache(cacheKey)
}

// dnsCacheKeySet is the exact set of cache keys stored under one base cache
// key. Each set owns its mutex so stores and deletes for different names never
// serialize on a controller-wide lock.
type dnsCacheKeySet struct {
	mu   sync.Mutex
	keys map[string]struct{}
}

func newDnsCacheKeySet(cacheKey string) *dnsCacheKeySet {
	return &dnsCacheKeySet{keys: map[string]struct{}{cacheKey: {}}}
}

// dnsCacheIndexAdd records cacheKey under its base key. A concurrent
// dnsCacheIndexRemove publishes emptiness while holding the set lock and only
// then drops the set from the index, so an insert either lands in a set that is
// still registered (and therefore non-empty before the remover looks) or it
// observes the drop and retries with a fresh set. Without that re-check under
// the set lock, an insert racing the drop would be lost and family removal
// would silently stop matching the entry.
func (c *DnsController) dnsCacheIndexAdd(cacheKey string) {
	baseKey := dnsCacheBaseKey(cacheKey)
	if baseKey == "" {
		return
	}
	for {
		if actual, ok := c.dnsCacheByBase.Load(baseKey); ok {
			set, ok := actual.(*dnsCacheKeySet)
			if !ok {
				return
			}
			set.mu.Lock()
			if current, ok := c.dnsCacheByBase.Load(baseKey); ok && current == actual {
				set.keys[cacheKey] = struct{}{}
				set.mu.Unlock()
				return
			}
			// The set was dropped between the load and the lock; retry.
			set.mu.Unlock()
			continue
		}
		// The set is published already containing cacheKey, so a concurrent
		// remover can never observe it as empty and drop it.
		if _, loaded := c.dnsCacheByBase.LoadOrStore(baseKey, newDnsCacheKeySet(cacheKey)); !loaded {
			return
		}
	}
}

// dnsCacheIndexRemove drops cacheKey from its base key's set and drops the set
// itself once it becomes empty. Emptiness is decided while holding the set
// lock, and the set is unregistered under that same lock so the check cannot be
// invalidated by a concurrent insert.
func (c *DnsController) dnsCacheIndexRemove(cacheKey string) {
	baseKey := dnsCacheBaseKey(cacheKey)
	if baseKey == "" {
		return
	}
	actual, ok := c.dnsCacheByBase.Load(baseKey)
	if !ok {
		return
	}
	set, ok := actual.(*dnsCacheKeySet)
	if !ok {
		return
	}
	set.mu.Lock()
	delete(set.keys, cacheKey)
	if len(set.keys) == 0 {
		c.dnsCacheByBase.CompareAndDelete(baseKey, set)
	}
	set.mu.Unlock()
}

// dnsCacheIndexSnapshot returns the exact cache keys indexed for baseKey. It is
// lock-free with respect to cacheProjectionMu: callers use it to decide whether
// a family has entries before taking the projection write lock.
func (c *DnsController) dnsCacheIndexSnapshot(baseKey string) []string {
	if baseKey == "" {
		return nil
	}
	actual, ok := c.dnsCacheByBase.Load(baseKey)
	if !ok {
		return nil
	}
	set, ok := actual.(*dnsCacheKeySet)
	if !ok {
		return nil
	}
	set.mu.Lock()
	defer set.mu.Unlock()
	if len(set.keys) == 0 {
		return nil
	}
	keys := make([]string, 0, len(set.keys))
	for cacheKey := range set.keys {
		keys = append(keys, cacheKey)
	}
	return keys
}

func (c *DnsController) dnsCacheIndexLen() int {
	total := 0
	c.dnsCacheByBase.Range(func(_, value any) bool {
		set, ok := value.(*dnsCacheKeySet)
		if !ok {
			return true
		}
		set.mu.Lock()
		total += len(set.keys)
		set.mu.Unlock()
		return true
	})
	return total
}

func (c *DnsController) clearDnsCacheIndex() {
	c.dnsCacheByBase.Range(func(key, _ any) bool {
		c.dnsCacheByBase.Delete(key)
		return true
	})
}

func (c *DnsController) decrementDnsCacheSize() {
	for {
		current := c.dnsCacheSize.Load()
		if current <= 0 || c.dnsCacheSize.CompareAndSwap(current, current-1) {
			return
		}
	}
}

func (c *DnsController) CloneCacheForReload() map[string]*DnsCache {
	if c == nil || c.dnsControllerStore == nil {
		return nil
	}
	result := make(map[string]*DnsCache)
	c.dnsCache.Range(func(key, value any) bool {
		k, ok1 := key.(string)
		v, ok2 := value.(*DnsCache)
		if ok1 && ok2 {
			result[k] = v.CloneForReload()
		} else if c.log != nil {
			c.log.Errorf("CloneCacheForReload: invalid type found in sync.Map: key=%T, value=%T", key, value)
		}
		return true
	})
	return result
}

// RestoreReloadCacheAndProject restores cache entries and synchronously
// applies their BPF side effects. Reload publication uses this variant so an
// inactive routing plan has a complete domain projection before it becomes
// visible to packets. The runtime callback must not attempt to update this
// controller's runtime while it is executing.
func (c *DnsController) RestoreReloadCacheAndProject(entries map[string]*DnsCache, matchDomainBitmap func(string) []uint32, now time.Time) (int, error) {
	return c.restoreReloadCache(entries, matchDomainBitmap, now)
}

func (c *DnsController) restoreReloadCache(entries map[string]*DnsCache, matchDomainBitmap func(string) []uint32, now time.Time) (int, error) {
	if c == nil || len(entries) == 0 {
		return 0, nil
	}
	c.requireStore()
	count := 0
	for k, v := range entries {
		if v == nil {
			continue
		}

		for {
			rt := c.runtime()
			restored := v.CloneForReload()
			ensureDNSCacheRouteOwnerKey(k, restored)
			if rt != nil {
				restored.RouteProjectionEpoch = rt.routeProjectionEpoch
			}
			switch {
			case rt != nil && rt.projectCacheRoute != nil:
				restored.DomainBitmap = rt.projectCacheRoute(restored)
			case matchDomainBitmap != nil:
				restored.DomainBitmap = matchDomainBitmap(restored.GetFqdn())
			case v.DomainBitmap != nil:
				restored.DomainBitmap = append([]uint32(nil), v.DomainBitmap...)
			}

			// Pair the rebuilt bitmap with the runtime that supplied its epoch.
			// A reload can replace the runtime while the matcher is running, in
			// which case retrying avoids publishing an old projection as new.
			c.runtimeMu.RLock()
			if c.runtime() != rt {
				c.runtimeMu.RUnlock()
				continue
			}

			c.cacheProjectionMu.Lock()
			c.enforceDnsCacheCapacityLocked(k)
			_, loaded := c.storeDnsCache(k, restored)
			c.rememberDnsKnowledge(dnsCacheBaseKey(k), restored.OriginalDeadline, !loaded)
			if rt != nil && rt.cacheAccessCallback != nil {
				if err := rt.cacheAccessCallback(restored); err != nil {
					c.cacheProjectionMu.Unlock()
					c.runtimeMu.RUnlock()
					return count, fmt.Errorf("project restored DNS cache %q: %w", k, err)
				}
				restored.MarkBpfUpdated(now)
			} else {
				c.triggerBpfUpdateIfNeededForRuntime(restored, now, rt)
			}
			c.cacheProjectionMu.Unlock()
			c.runtimeMu.RUnlock()

			count++
			break
		}
	}
	return count, nil
}

// cacheEntry represents a DNS cache entry with its access time for LRU eviction.
type cacheEntry struct {
	key        string
	lastAccess int64
}

func (c *DnsController) cacheKey(qname string, qtype uint16) string {
	// To fqdn.
	qname = dnsmessage.CanonicalName(qname)
	// Fast path: use pre-computed string for common qtypes
	if s, ok := qtypeStrCache[qtype]; ok {
		return qname + s
	}
	// Slow path: fallback to strconv for uncommon types
	return qname + strconv.Itoa(int(qtype))
}

func dnsCacheBaseKey(cacheKey string) string {
	if before, _, ok := strings.Cut(cacheKey, "|"); ok {
		return before
	}
	return cacheKey
}

// responseCacheKey scopes a base cache key to the upstream that produced the
// answer, so an as-is answer for one destination cannot be served for another.
func (c *DnsController) responseCacheKey(baseKey string, req *udpRequest, upstreamIndex consts.DnsRequestOutboundIndex, upstream *dns.Upstream) string {
	var scope string
	switch upstreamIndex {
	case consts.DnsRequestOutboundIndex_AsIs:
		scope = "asis"
		if req != nil && req.realDst.IsValid() {
			scope = "asis@" + req.realDst.String()
		}
	case consts.DnsRequestOutboundIndex_Reject:
		scope = "reject"
	default:
		switch {
		case upstream != nil:
			scope = "upstream@" + upstream.String()
		case upstreamIndex != 0:
			scope = "upstream-index@" + strconv.Itoa(int(upstreamIndex))
		}
	}
	if scope == "" {
		return baseKey
	}
	return baseKey + "|" + scope
}

func ensureDNSCacheRouteOwnerKey(cacheKey string, cache *DnsCache) *DnsCache {
	if cache == nil {
		return nil
	}
	if cache.RouteOwnerKey == "" {
		cache.RouteOwnerKey = cacheKey
	}
	return cache
}

// RemoveDnsRespCacheFamily drops every cache entry stored under baseKey.
//
// The lookup is index-driven: a base key that was never cached costs one
// sync.Map load and no lock at all, instead of a table-wide scan under
// cacheProjectionMu (which blocked every cache store and projection callback
// for the full scan). On a match the projection write lock is held only for
// the deletions themselves.
func (c *DnsController) RemoveDnsRespCacheFamily(baseKey string) {
	c.requireStore()
	if baseKey == "" {
		return
	}
	cacheKeys := c.dnsCacheIndexSnapshot(baseKey)
	if len(cacheKeys) == 0 {
		return
	}
	c.cacheProjectionMu.Lock()
	for _, cacheKey := range cacheKeys {
		value, ok := c.dnsCache.Load(cacheKey)
		if !ok {
			continue
		}
		cache, ok := value.(*DnsCache)
		if !ok {
			c.deleteDnsCacheEntry(cacheKey)
			continue
		}
		if c.compareAndDeleteDnsCache(cacheKey, cache) {
			c.invokeCacheDeleteCallback(cacheKey, cache)
		}
	}
	c.cacheProjectionMu.Unlock()
	// Deletions above leave the base-key index holding exactly the surviving
	// keys of this family (normally none), so knowledge is recomputed from the
	// index rather than from a second whole-table scan.
	c.syncDnsKnowledge(baseKey)
}

// counterpartAddressQtype returns the other A/AAAA family.
func counterpartAddressQtype(qtype uint16) (uint16, bool) {
	switch qtype {
	case dnsmessage.TypeA:
		return dnsmessage.TypeAAAA, true
	case dnsmessage.TypeAAAA:
		return dnsmessage.TypeA, true
	default:
		return 0, false
	}
}

// dropCachedAddressFamily removes every cached answer of one address family for
// qname. While the preferred family has records, ipversion_prefer answers the
// other family with an empty reply, and the response-cache fast path releases a
// cached answer without consulting the preference at all, so such an entry must
// not survive. It returns true when entries were dropped.
func (c *DnsController) dropCachedAddressFamily(qname string, qtype uint16) bool {
	if qtype != dnsmessage.TypeA && qtype != dnsmessage.TypeAAAA {
		return false
	}
	baseKey := c.cacheKey(qname, qtype)
	if baseKey == "" || len(c.dnsCacheIndexSnapshot(baseKey)) == 0 {
		return false
	}
	c.RemoveDnsRespCacheFamily(baseKey)
	return true
}

// cachedAddressFamilyHasRecords reports whether the response cache holds at
// least one unexpired answer record of qtype for qname. The scan walks the
// family index instead of a single scoped key, so the answer does not depend on
// which upstream produced it.
func (c *DnsController) cachedAddressFamilyHasRecords(qname string, qtype uint16) bool {
	if qtype != dnsmessage.TypeA && qtype != dnsmessage.TypeAAAA {
		return false
	}
	cacheKeys := c.dnsCacheIndexSnapshot(c.cacheKey(qname, qtype))
	if len(cacheKeys) == 0 {
		return false
	}
	now := time.Now()
	for _, cacheKey := range cacheKeys {
		value, ok := c.dnsCache.Load(cacheKey)
		if !ok {
			continue
		}
		cache, ok := value.(*DnsCache)
		if !ok || cache == nil || !cache.Deadline.After(now) {
			continue
		}
		for _, rr := range cache.Answer {
			if rr != nil && rr.Header().Rrtype == qtype {
				return true
			}
		}
	}
	return false
}

// suppressNonPreferredCacheHit reports whether a cached answer for this query
// must be suppressed because the other address family is preferred and has
// records. The response-cache fast path releases a cached answer without ever
// reaching applyPreferenceWait, and entries can also be stored by paths that do
// not run the delivery filter (the optimistic background refresh and the
// forwarder store), so the preference is enforced here, at the point a cached
// answer is released. The cached non-preferred family is dropped as well, so
// later queries do not pay the check again.
func (c *DnsController) suppressNonPreferredCacheHit(msg *dnsmessage.Msg) bool {
	if msg == nil || len(msg.Question) == 0 {
		return false
	}
	q := msg.Question[0]
	qtypePrefer := c.currentQtypePrefer()
	if qtypePrefer == 0 || isPreferredType(q.Qtype, qtypePrefer) {
		return false
	}
	if q.Qtype != dnsmessage.TypeA && q.Qtype != dnsmessage.TypeAAAA {
		return false
	}
	qname := dnsmessage.CanonicalName(q.Name)
	if !c.cachedAddressFamilyHasRecords(qname, qtypePrefer) {
		return false
	}
	c.dropCachedAddressFamily(qname, q.Qtype)
	c.dnsPreferFiltered.Add(1)
	return true
}

func (c *DnsController) rememberDnsKnowledge(baseKey string, originalDeadline time.Time, newCacheEntry bool) {
	if baseKey == "" {
		return
	}
	expiresAt := originalDeadline.UnixNano()
	c.dnsKnowledgeMu.Lock()
	defer c.dnsKnowledgeMu.Unlock()

	current, loaded := c.dnsKnowledge.Load(baseKey)
	entry, valid := parseDnsKnowledgeEntry(current)
	switch {
	case !loaded || !valid:
		entry = dnsKnowledgeEntry{cacheCount: 1}
	case newCacheEntry:
		entry.cacheCount++
	case entry.cacheCount == 0:
		entry.cacheCount = 1
	}
	if entry.expiresAt < expiresAt {
		entry.expiresAt = expiresAt
	}
	c.dnsKnowledge.Store(baseKey, entry)
}

func (c *DnsController) forgetDnsKnowledge(cacheKey string, cache *DnsCache) {
	baseKey := dnsCacheBaseKey(cacheKey)
	if baseKey == "" || cache == nil {
		return
	}

	deletedExpiresAt := cache.OriginalDeadline.UnixNano()

	c.dnsKnowledgeMu.Lock()
	defer c.dnsKnowledgeMu.Unlock()

	current, ok := c.dnsKnowledge.Load(baseKey)
	if !ok {
		return
	}
	entry, ok := parseDnsKnowledgeEntry(current)
	if !ok || entry.cacheCount <= 0 {
		c.syncDnsKnowledgeLocked(baseKey)
		return
	}
	if entry.cacheCount == 1 {
		c.dnsKnowledge.Delete(baseKey)
		return
	}
	entry.cacheCount--
	if deletedExpiresAt < entry.expiresAt {
		c.dnsKnowledge.Store(baseKey, entry)
		return
	}
	c.syncDnsKnowledgeLocked(baseKey)
}

func (c *DnsController) syncDnsKnowledge(baseKey string) {
	if baseKey == "" {
		return
	}
	c.dnsKnowledgeMu.Lock()
	defer c.dnsKnowledgeMu.Unlock()
	c.syncDnsKnowledgeLocked(baseKey)
}

// syncDnsKnowledgeLocked recomputes the knowledge entry for baseKey from the
// base-key index. The index holds exactly the cache keys stored under baseKey,
// so this touches one family instead of walking the whole cache.
func (c *DnsController) syncDnsKnowledgeLocked(baseKey string) {
	entry := dnsKnowledgeEntry{}

	for _, cacheKey := range c.dnsCacheIndexSnapshot(baseKey) {
		value, ok := c.dnsCache.Load(cacheKey)
		if !ok {
			continue
		}
		cache, ok := value.(*DnsCache)
		if !ok {
			// The index only ever records entries stored as *DnsCache; a
			// different type means the index drifted from the cache, which the
			// janitor reconciliation reports and repairs.
			continue
		}

		expiresAt := cache.OriginalDeadline.UnixNano()
		entry.cacheCount++
		if expiresAt > entry.expiresAt {
			entry.expiresAt = expiresAt
		}
	}

	if entry.cacheCount == 0 {
		c.dnsKnowledge.Delete(baseKey)
		return
	}
	c.dnsKnowledge.Store(baseKey, entry)
}

func (c *DnsController) HasDnsKnowledge(baseKey string) bool {
	c.requireStore()
	if baseKey == "" {
		return false
	}
	value, ok := c.dnsKnowledge.Load(baseKey)
	if !ok {
		return false
	}
	entry, ok := parseDnsKnowledgeEntry(value)
	if !ok {
		c.dnsKnowledge.Delete(baseKey)
		return false
	}
	if entry.expiresAt <= time.Now().UnixNano() {
		return false
	}
	return true
}

func (c *DnsController) invokeCacheDeleteCallback(cacheKey string, cache *DnsCache) {
	rt := c.runtime()
	if cache == nil || rt == nil || rt.cacheDeleteCallback == nil {
		return
	}
	if err := rt.cacheDeleteCallback(cacheKey, ensureDNSCacheRouteOwnerKey(cacheKey, cache)); err != nil {
		if c.log != nil {
			c.log.Warnf("failed to delete exact dns cache side effects: %v", err)
		}
	}
}

// evictDnsCacheLocked removes one cache entry while cacheProjectionMu is held.
func (c *DnsController) evictDnsCacheLocked(cacheKey string, cache *DnsCache) bool {
	if cache == nil || !c.compareAndDeleteDnsCache(cacheKey, cache) {
		return false
	}
	c.forgetDnsKnowledge(cacheKey, cache)
	c.invokeCacheDeleteCallback(cacheKey, cache)
	return true
}

// enforceDnsCacheCapacityLocked keeps a configured maximum as an admission
// bound rather than waiting for the periodic janitor. The normal at-capacity
// case selects the oldest entry from a fixed sample so admission work does not
// grow with cache cardinality.
func (c *DnsController) enforceDnsCacheCapacityLocked(incomingKey string) {
	_, _, _, maxCacheSize := c.currentOptimisticCacheConfig()
	if maxCacheSize <= 0 {
		return
	}
	if _, exists := c.dnsCache.Load(incomingKey); exists {
		return
	}
	c.trimDnsCacheToSizeLocked(maxCacheSize - 1)
}

func (c *DnsController) trimDnsCacheToSizeLocked(targetSize int) {
	if targetSize < 0 {
		targetSize = 0
	}
	count := int(c.dnsCacheSize.Load())
	if count <= targetSize {
		return
	}

	excess := count - targetSize
	if excess == 1 {
		const admissionEvictionSampleSize = 16
		var victimKey string
		var victim *DnsCache
		var oldestAccess int64
		sampled := 0
		c.dnsCache.Range(func(key, value any) bool {
			sampled++
			cacheKey, keyOK := key.(string)
			cache, cacheOK := value.(*DnsCache)
			if !keyOK || !cacheOK || cache == nil {
				return sampled < admissionEvictionSampleSize
			}
			access := cache.lastAccessNano.Load()
			if victim == nil || access < oldestAccess {
				victimKey, victim, oldestAccess = cacheKey, cache, access
			}
			return sampled < admissionEvictionSampleSize
		})
		if victim != nil {
			c.evictDnsCacheLocked(victimKey, victim)
		}
		return
	}

	// A runtime limit reduction can require a bulk trim. Prefer bounded memory
	// over allocating and retaining an O(cache-size) LRU scratch slice here; the
	// janitor continues to provide precise LRU ordering during normal operation.
	c.dnsCache.Range(func(key, value any) bool {
		if excess == 0 {
			return false
		}
		cacheKey, keyOK := key.(string)
		cache, cacheOK := value.(*DnsCache)
		if !keyOK || !cacheOK || cache == nil {
			return true
		}
		if c.evictDnsCacheLocked(cacheKey, cache) {
			excess--
		}
		return true
	})
}

func (c *DnsController) evictDnsRespCacheIfSame(cacheKey string, cache *DnsCache) {
	if cache == nil {
		return
	}
	c.cacheProjectionMu.Lock()
	defer c.cacheProjectionMu.Unlock()
	c.evictDnsCacheLocked(cacheKey, cache)
}

func (c *DnsController) evictExpiredDnsCache(now time.Time) {
	optimisticCacheEnabled, optimisticCacheTtl, _, maxCacheSize := c.currentOptimisticCacheConfig()
	// Step 1: Time-based eviction
	// - When optimistic_cache_ttl > 0: evict entries older than (deadline + stale_window)
	// - When optimistic_cache_ttl == 0 AND maxCacheSize > 0: skip time-based eviction (rely on LRU)
	// - When both are 0 (backward compat / direct struct creation): use deadline-based eviction
	useTimeBasedEviction := optimisticCacheTtl > 0 || (optimisticCacheTtl == 0 && maxCacheSize == 0)

	if useTimeBasedEviction {
		c.dnsCache.Range(func(key, value any) bool {
			cacheKey, ok := key.(string)
			if !ok {
				c.deleteDnsCacheEntry(key)
				return true
			}
			cache, ok := value.(*DnsCache)
			if !ok {
				c.loadAndDeleteDnsCache(cacheKey)
				return true
			}

			// Calculate effective deadline
			// - If optimistic cache is enabled and ttl > 0: use (deadline + optimisticCacheTtl)
			// - Otherwise: use deadline directly
			effectiveDeadline := cache.Deadline
			if optimisticCacheEnabled && optimisticCacheTtl > 0 {
				effectiveDeadline = cache.Deadline.Add(time.Duration(optimisticCacheTtl) * time.Second)
			}

			if effectiveDeadline.After(now) {
				return true // Still valid, keep it
			}

			// Too stale or expired without optimistic cache, evict it
			c.evictDnsRespCacheIfSame(cacheKey, cache)
			return true
		})
	}

	// Step 2: LRU eviction if cache size exceeds limit
	// This is important when optimistic_cache_ttl=0 (never expire)
	if maxCacheSize > 0 {
		c.evictLRUIfFull(maxCacheSize)
	}
}

func (c *DnsController) takeLRUScratch(minCap int) []cacheEntry {
	c.lruScratchMu.Lock()
	defer c.lruScratchMu.Unlock()

	if cap(c.lruScratch) >= minCap {
		entries := c.lruScratch[:0]
		c.lruScratch = nil
		return entries
	}

	c.lruScratch = nil
	return make([]cacheEntry, 0, minCap)
}

func (c *DnsController) putLRUScratch(entries []cacheEntry) {
	if entries == nil {
		return
	}

	clear(entries)
	const maxRetainedLRUScratchEntries = 4096
	if cap(entries) > maxRetainedLRUScratchEntries {
		return
	}

	c.lruScratchMu.Lock()
	if cap(entries) > cap(c.lruScratch) {
		c.lruScratch = entries[:0]
	}
	c.lruScratchMu.Unlock()
}

// evictLRUIfFull evicts least recently used entries if cache size exceeds limit.
// OPTIMIZATION: Uses heap selection algorithm (O(n + k log n)) instead of
// full sort (O(n log n)) or insertion sort (O(n²)) for better performance
// with large caches. For typical cache sizes (<1000), the overhead is negligible.
// For large caches (>5000), this is 10-100x faster than insertion sort.
func (c *DnsController) evictLRUIfFull(maxCacheSize int) {
	if maxCacheSize <= 0 {
		return
	}
	// Count current cache size
	var count int
	c.dnsCache.Range(func(_, _ any) bool {
		count++
		return true
	})

	if count <= maxCacheSize {
		return
	}

	// Find and evict oldest entries
	// Need to evict (count - maxCacheSize) entries
	numToEvict := count - maxCacheSize

	// Collect all cache entries with their access times
	// Reuse a scratch buffer to avoid allocating a new slice on every janitor run.
	entries := c.takeLRUScratch(count)
	scratch := entries
	defer func() {
		c.putLRUScratch(scratch)
	}()
	c.dnsCache.Range(func(key, value any) bool {
		cacheKey, ok := key.(string)
		if !ok {
			return true
		}
		cache, ok := value.(*DnsCache)
		if !ok {
			return true
		}
		entries = append(entries, cacheEntry{
			key:        cacheKey,
			lastAccess: cache.lastAccessNano.Load(),
		})
		return true
	})
	scratch = entries

	// Use heap selection to find the k oldest entries.
	// Build a min-heap and extract k elements: O(n + k log n)
	// This is more efficient than full sort O(n log n) when k << n.
	if numToEvict < len(entries) {
		// Build min-heap based on lastAccess (smallest = oldest)
		buildMinHeap(entries)

		// Extract k oldest entries from heap
		for i := range numToEvict {
			// Swap root (minimum) with last element
			lastIdx := len(entries) - 1 - i
			entries[0], entries[lastIdx] = entries[lastIdx], entries[0]

			// Restore heap property for remaining elements
			heapifyMin(entries, 0, lastIdx)
		}

		// The k oldest are now at the end of entries (indices len-n to len-1)
		entries = entries[len(entries)-numToEvict:]
	}

	// Evict oldest entries
	evicted := 0
	for _, entry := range entries {
		if evicted >= numToEvict {
			break
		}

		// Load cache again to get current reference
		if val, ok := c.dnsCache.Load(entry.key); ok {
			if cache, ok := val.(*DnsCache); ok {
				c.evictDnsRespCacheIfSame(entry.key, cache)
				evicted++
			}
		}
	}
}

// reconcileDnsCacheIndex compares the number of keys held by the base-key index
// with the live cache size. A mismatch means family removal and knowledge
// resync would silently stop matching entries, so it is reported and repaired
// instead of being ignored; the cache table is the source of truth for both the
// rebuilt index and the size counter.
//
// Both counters are read under the projection read lock: every mutation of
// either one happens under the write lock, so reading them separately (without
// the lock) would observe a half-applied store or delete and report drift that
// does not exist.
func (c *DnsController) reconcileDnsCacheIndex() {
	c.requireStore()
	c.cacheProjectionMu.RLock()
	size := c.dnsCacheSize.Load()
	indexed := int64(c.dnsCacheIndexLen())
	c.cacheProjectionMu.RUnlock()
	if indexed == size {
		return
	}
	c.dnsCacheIndexReconciles.Add(1)
	if c.log != nil {
		c.log.Errorf("dns cache base-key index drift detected: indexed keys=%d, cache size=%d; rebuilding index", indexed, size)
	}
	c.rebuildDnsCacheIndex()
}

// rebuildDnsCacheIndex republishes the base-key index from the cache table.
// It runs under cacheProjectionMu because every production cache store holds
// that lock: without it, an entry stored between the scan and the publication
// would be missing from the rebuilt index.
func (c *DnsController) rebuildDnsCacheIndex() {
	c.cacheProjectionMu.Lock()
	defer c.cacheProjectionMu.Unlock()

	live := make(map[string]struct{}, c.dnsCacheSize.Load())
	nonStringKeys := 0
	c.dnsCache.Range(func(key, _ any) bool {
		cacheKey, ok := key.(string)
		if !ok {
			nonStringKeys++
			return true
		}
		live[cacheKey] = struct{}{}
		return true
	})

	// Drop indexed keys that no longer have a cache entry, and unregister the
	// sets that become empty.
	c.dnsCacheByBase.Range(func(baseKey, value any) bool {
		set, ok := value.(*dnsCacheKeySet)
		if !ok {
			return true
		}
		set.mu.Lock()
		for cacheKey := range set.keys {
			if _, ok := live[cacheKey]; !ok {
				delete(set.keys, cacheKey)
			}
		}
		if len(set.keys) == 0 {
			c.dnsCacheByBase.CompareAndDelete(baseKey, set)
		}
		set.mu.Unlock()
		return true
	})

	// Re-register every live key. Keys that were already indexed are a no-op.
	for cacheKey := range live {
		c.dnsCacheIndexAdd(cacheKey)
	}

	// The table is authoritative for the entry count as well: a drifted
	// counter would otherwise keep capacity enforcement skewed.
	c.dnsCacheSize.Store(int64(len(live)))
	if nonStringKeys > 0 && c.log != nil {
		c.log.Errorf("dns cache holds %d non-string keys; they are not indexable and were excluded from the cache size", nonStringKeys)
	}
}

// startDnsCacheJanitor runs a periodic goroutine that evicts expired DNS cache
// entries and retires idle DNS forwarders. It also carries the periodic DNS
// visibility reports (truncation upgrades) on the same cadence, because it is
// the only DNS-owned ticker and the counters it reports live on the same shared
// store.
//
// IMPORTANT: This goroutine intentionally does NOT watch baseContext().Done().
// See bpfUpdateWorker comment for the rationale — the same stale-context problem
// applies here when the DnsController is reused across reload generations.
func (c *DnsController) startDnsCacheJanitor() {
	c.requireStore()
	go func() {
		ticker := time.NewTicker(dnsCacheJanitorInterval)
		defer ticker.Stop()
		defer close(c.janitorDone)

		for {
			select {
			case <-c.janitorStop:
				return
			case now := <-ticker.C:
				c.reconcileDnsCacheIndex()
				c.evictExpiredDnsCache(now)
				c.evictIdleDnsForwarders(now)
				c.reportDnsTruncationSummary()
			}
		}
	}()
}

// LookupDnsRespCache_ will modify the msg in place.

// OPTIMIZED: Uses pre-packed response with approximate TTL for near-zero latency.
// TTL is refreshed when difference exceeds ttlRefreshThresholdSeconds (15 seconds by default).
// OPTIMISTIC CACHE (RFC 8767): Returns stale response while background refresh is in progress.
// Falls back to an owned in-place TTL-aware pack if pre-packed response is not available.
func (c *DnsController) LookupDnsRespCache_(msg *dnsmessage.Msg, cacheKey string, ignoreFixedTtl bool) (resp []byte, needRefresh bool) {
	c.requireStore()
	// Load cache directly without expiry check (to support optimistic cache)
	val, ok := c.dnsCache.Load(cacheKey)
	if !ok {
		return nil, false
	}
	cache := val.(*DnsCache)

	now := time.Now()

	// Update last access time for LRU eviction (atomic operation)
	cache.lastAccessNano.Store(now.UnixNano())

	// Determine deadline based on ignoreFixedTtl
	var deadline time.Time
	if !ignoreFixedTtl {
		deadline = cache.Deadline
	} else {
		deadline = cache.OriginalDeadline
	}

	// Fast path: use pre-packed response with approximate TTL (fresh response)
	if deadline.After(now) {
		// Extract qname and qtype from the message for TTL refresh
		var qname string
		var qtype uint16
		if len(msg.Question) > 0 {
			qname = msg.Question[0].Name
			qtype = msg.Question[0].Qtype
		}

		if resp := cache.GetPackedResponseWithApproximateTTL(qname, qtype, now); resp != nil {
			// Fresh cache hit - return immediately
			// Trigger async BPF update if needed
			c.triggerBpfUpdateIfNeeded(cache, now)
			return resp, false
		}

		// Fallback: pre-packed response not available, use the owned in-place path.
		// LookupDnsRespCache_ already owns dnsMessage exclusively and is documented
		// to mutate it in place, so this avoids the extra request copy on the
		// remaining TTL-aware cache-hit fallback. A pack failure degrades into an
		// upstream lookup, so it must be visible instead of silent.
		resp, packErr := cache.fillIntoWithTTLInPlace(msg, now)
		if packErr != nil {
			if c.log != nil {
				c.log.Warnf("failed to pack cached DNS response for %q, falling back to an upstream lookup: %v", cacheKey, packErr)
			}
			return nil, false
		}
		if resp != nil {
			return resp, false
		}
		return nil, false
	}

	// Cache expired - check if optimistic cache is enabled
	optimisticCacheEnabled, optimisticCacheTtl, staleReplyTtl, _ := c.currentOptimisticCacheConfig()
	if optimisticCacheEnabled {
		// Try stale response (RFC 8767)
		// Use optimisticCacheTtl (0 means never expire)
		if resp = cache.GetStaleResponse(now, optimisticCacheTtl); resp != nil {
			// Within stale window - return stale response and trigger background refresh
			// Use CAS to ensure only one goroutine triggers refresh
			if cache.refreshing.CompareAndSwap(false, true) {
				needRefresh = true
			}
			// Bound the TTL advertised for the stale answer: replaying the
			// original long TTL would make downstream clients cache the stale
			// data long after dae stopped serving it (RFC 8767 §4 recommends a
			// short reply TTL). Zero-TTL (dae-managed A/AAAA) records and the
			// OPT pseudo-record are left untouched. On a malformed wire the
			// original bytes are served unchanged rather than failing the query.
			if staleReplyTtl > 0 {
				if bounded := clampWireRecordTtls(resp, uint32(staleReplyTtl)); bounded != nil {
					resp = bounded
				}
			}
			return resp, needRefresh
		}
	}

	// Cache expired and beyond stale window (or optimistic cache disabled)
	// Evict the cache
	c.evictDnsRespCacheIfSame(cacheKey, cache)
	return nil, false
}

// dnsMaxCacheableTtl clamps entry lifetimes to one year (integer-overflow
// guard for 32-bit platforms and an upper bound consistent with cache sanity).
const dnsMaxCacheableTtl = 31536000

// dnsNegativeCacheMaxTtl caps the negative-cache lifetime derived from the
// authority SOA. RFC 2308 §5 suggests one to three hours as a tunable default
// cap; one hour matches common resolver defaults (e.g. Unbound's
// cache-max-negative-ttl=3600).
const dnsNegativeCacheMaxTtl = 3600

// minRealRecordTtl returns the minimum TTL over all non-OPT resource records
// in the message. With whole-message caching, the entry may only outlive its
// shortest-lived record (RFC 4035 §4.5: an atomic response entry is discarded
// when any contained RR expires), so this bounds the entry deadline instead of
// trusting the first answer record.
func minRealRecordTtl(msg *dnsmessage.Msg) uint32 {
	var minTtl uint32
	first := true
	consider := func(rrs []dnsmessage.RR) {
		for _, rr := range rrs {
			if rr.Header().Rrtype == dnsmessage.TypeOPT {
				continue
			}
			ttl := rr.Header().Ttl
			if first || ttl < minTtl {
				minTtl = ttl
				first = false
			}
		}
	}
	consider(msg.Answer)
	consider(msg.Ns)
	consider(msg.Extra)
	if first {
		return 0
	}
	return minTtl
}

// findAuthoritySoa returns the authority SOA of a negative response, if any.
func findAuthoritySoa(msg *dnsmessage.Msg) *dnsmessage.SOA {
	for _, rr := range msg.Ns {
		if soa, ok := rr.(*dnsmessage.SOA); ok {
			return soa
		}
	}
	return nil
}

// authorityHasNs reports whether the authority section carries an NS record,
// which (without an SOA) marks the response as a referral rather than an
// answer (RFC 2308 §2.2).
func authorityHasNs(msg *dnsmessage.Msg) bool {
	for _, rr := range msg.Ns {
		if rr.Header().Rrtype == dnsmessage.TypeNS {
			return true
		}
	}
	return false
}

// hasRelevantAnswer reports whether msg carries an answer of the question's
// requested type (RFC 2308 §2.2: NODATA is the absence of a *relevant*
// answer, so a CNAME-only answer for an A/AAAA question is still a negative).
func hasRelevantAnswer(msg *dnsmessage.Msg, q dnsmessage.Question) bool {
	for _, rr := range msg.Answer {
		if typeMatchesQuestion(rr.Header().Rrtype, q.Qtype) {
			return true
		}
	}
	return false
}

// typeMatchesQuestion reports whether an answer record type satisfies the
// question's QTYPE. QTYPE=ANY matches any record: a well-formed ANY response
// carries concrete RRsets such as A, MX or HINFO, never type-ANY records
// (RFC 8482 §3). QTYPE=MAILB (253) requests MB, MG or MR records (RFC 1035
// §3.2.3). QTYPE=MAILA (254) requests the obsolete MD or MF records, which
// the wire decoder still represents and can return as answer records.
func typeMatchesQuestion(rrtype, qtype uint16) bool {
	if qtype == dnsmessage.TypeANY || rrtype == qtype {
		return true
	}
	if qtype == dnsmessage.TypeMAILB {
		return rrtype == dnsmessage.TypeMB || rrtype == dnsmessage.TypeMG || rrtype == dnsmessage.TypeMR
	}
	return qtype == dnsmessage.TypeMAILA &&
		(rrtype == dnsmessage.TypeMD || rrtype == dnsmessage.TypeMF)
}

// NormalizeAndCacheDnsResp_ handle DNS resp in place.
func (c *DnsController) NormalizeAndCacheDnsResp_(msg *dnsmessage.Msg, responseCacheKey string) (err error) {
	if !msg.Response || len(msg.Question) == 0 {
		return nil
	}

	q := msg.Question[0]

	// Negative responses (RFC 2308 §2.2): NODATA is NOERROR without an answer
	// of the requested type - the answer section may still carry CNAME
	// records aliasing to the empty target. A response is therefore negative
	// on non-success RCODE or when no answer record matches the question's
	// QTYPE. It is only a terminal, cacheable negative when the authority
	// section carries an SOA: NS-only responses are referrals, not answers,
	// and no-SOA negatives SHOULD NOT be cached (§5). NXDOMAIN itself is
	// never stored: the packed cache can only replay success responses, so a
	// stored NXDOMAIN could not be reproduced faithfully.
	if msg.Rcode != dnsmessage.RcodeSuccess || !hasRelevantAnswer(msg, q) {
		if msg.Rcode == dnsmessage.RcodeSuccess {
			soa := findAuthoritySoa(msg)
			if soa == nil {
				// Referral or SOA-less NODATA: not a cacheable negative.
				return nil
			}
			// RFC 2308 negative lifetime is bounded by SOA TTL and MINIMUM.
			// Whole-message replay must also respect every retained record's TTL.
			ttl := min(soa.Hdr.Ttl, soa.Minttl, minRealRecordTtl(msg), uint32(dnsNegativeCacheMaxTtl))
			if ttl == 0 {
				return nil
			}
			// Store the SOA in the authority section so replayed NODATA
			// responses carry the negative proof with a decreasing TTL.
			return c.updateDnsCache(msg, responseCacheKey, ttl, &q)
		}
		// NXDOMAIN (and other non-success RCODEs) are not stored; see above.
		// Background refresh treats an accepted NXDOMAIN as superseding an
		// expired positive instead (RFC 8767 §4).
		return nil
	}

	// Positive response. Entry lifetime is the minimum over all retained real
	// records (answers, authority and additional sections). Fixed-domain
	// operator overrides still apply downstream in the deadline functions.
	//
	// A zero minimum is still cached with a now-deadline: an upstream that
	// answers with TTL 0 asks for exactly that, and dae keeps its own freshness
	// bookkeeping through the entry deadline and the stale window instead of
	// treating the record as uncacheable.
	ttl := min(
		// Clamp TTL to 1 year max to prevent integer overflow when casting to int
		// on 32-bit platforms.
		minRealRecordTtl(msg), dnsMaxCacheableTtl)

	// Answers are forwarded with their real TTL, both on the first response and
	// on a cache hit (where it is the remaining lifetime). dae used to rewrite
	// A/AAAA TTLs to zero to keep resolvers from caching, but that made the
	// answer a client saw depend on whether the entry happened to be cached:
	// the first response carried 0 and every later one the remaining lifetime.
	// Freshness of dae-managed address answers is tracked by the entry deadline
	// and the stale window, not by suppressing downstream caching.

	// Update DnsCache.
	return c.updateDnsCache(msg, responseCacheKey, ttl, &q)
}

// dnsCacheStoreFailureLogInterval paces the failed-cache-store warning. A
// response that cannot be stored is offered again by the client on its next
// query, so the condition repeats for as long as the response stays
// unstorable; an unpaced warning would be one line per query for the whole
// cache lifetime of the affected name.
const dnsCacheStoreFailureLogInterval = time.Minute

// noteDnsCacheStoreFailure reports a DNS response that could not be stored in
// the cache. Storing is a latency optimization: the response itself is already
// on its way to the client, so a failure is not an outage and does not belong
// on the per-query path at warning level. Every path that stores a response
// (sync, async, and the controller's own writer) reports through here, so one
// failed store stays one line at most and one shared count, instead of the
// same event being reported at two different levels by two callers.
func (c *DnsController) noteDnsCacheStoreFailure(site string, err error) {
	if c == nil || c.dnsControllerStore == nil || c.log == nil || err == nil {
		return
	}
	entry := c.log.WithField("cache_site", site)
	if c.log.IsLevelEnabled(logrus.DebugLevel) {
		entry.WithError(err).Debug("failed to cache DNS response")
	}
	if failures, emit := c.dnsCacheStoreFailureAlert.observe(time.Now(), dnsCacheStoreFailureLogInterval); emit {
		entry.Warnf("failed to cache DNS response (%s): %v; failures=%d, reporting at most one line per %v",
			site, err, failures, dnsCacheStoreFailureLogInterval)
	}
}

func (c *DnsController) updateDnsCache(msg *dnsmessage.Msg, responseCacheKey string, ttl uint32, q *dnsmessage.Question) error {
	// Update DnsCache.
	if c.log.IsLevelEnabled(logrus.TraceLevel) {
		c.log.WithFields(logrus.Fields{
			"_qname": q.Name,
			"rcode":  msg.Rcode,
			"ans":    FormatDnsRsc(msg.Answer),
		}).Tracef("Update DNS record cache")
	}

	if err := c.UpdateDnsCacheTtlWithKey(responseCacheKey, q.Name, q.Qtype, msg.Answer, msg.Ns, msg.Extra, int(ttl)); err != nil {
		return err
	}
	return nil
}

type deadlineFunc func(now time.Time, host string) (deadline time.Time, originalDeadline time.Time)

func (c *DnsController) updateDnsCacheDeadline(cacheKey string, host string, dnsTyp uint16, answers, ns, extra []dnsmessage.RR, deadlineFunc deadlineFunc) (err error) {
	var fqdn string
	if strings.HasSuffix(host, ".") {
		fqdn = strings.ToLower(host)
		host = host[:len(host)-1]
	} else {
		fqdn = dnsmessage.CanonicalName(host)
	}
	// Bypass pure IP.
	if _, err = netip.ParseAddr(host); err == nil {
		return nil
	}

	now := time.Now()
	deadline, originalDeadline := deadlineFunc(now, host)

	if cacheKey == "" {
		cacheKey = c.cacheKey(fqdn, dnsTyp)
	}
	baseKey := dnsCacheBaseKey(cacheKey)

	for {
		rt := c.runtime()
		if rt == nil || rt.newCache == nil {
			return fmt.Errorf("dns controller runtime newCache is not configured")
		}
		newCache, err := rt.newCache(fqdn, answers, ns, extra, deadline, originalDeadline)
		if err != nil {
			return err
		}
		newCache.RouteProjectionEpoch = rt.routeProjectionEpoch

		// Pre-pack before publication so cache readers only observe a complete
		// entry. The cache/runtime locks below make the entry, its projection,
		// and reload epoch one atomic publication unit.
		if err = newCache.prepackResponseBeforeStore(fqdn, dnsTyp, ttlFromDeadline(deadline, now), now); err != nil {
			if c.log != nil {
				c.log.Warnf("failed to prepack DNS response: %v", err)
			}
		}

		c.runtimeMu.RLock()
		if c.runtime() != rt {
			c.runtimeMu.RUnlock()
			continue
		}
		c.cacheProjectionMu.Lock()
		if c.runtime() != rt {
			c.cacheProjectionMu.Unlock()
			c.runtimeMu.RUnlock()
			continue
		}

		newCache.RouteOwnerKey = cacheKey
		c.enforceDnsCacheCapacityLocked(cacheKey)
		_, loaded := c.storeDnsCache(cacheKey, newCache)
		c.rememberDnsKnowledge(baseKey, originalDeadline, !loaded)

		projectionErr := error(nil)
		if rt.cacheAccessCallback != nil {
			projectionErr = rt.cacheAccessCallback(newCache)
		}
		if projectionErr == nil {
			newCache.MarkBpfUpdated(now)
		}
		c.cacheProjectionMu.Unlock()
		c.runtimeMu.RUnlock()

		if projectionErr != nil {
			c.startBpfUpdateWorker()
			c.scheduleBpfProjectionRetry(&bpfUpdateTask{
				cache:                newCache,
				routeProjectionEpoch: rt.routeProjectionEpoch,
			})
			return projectionErr
		}
		return nil
	}
}

func (c *DnsController) UpdateDnsCacheTtl(host string, dnsTyp uint16, answers, ns, extra []dnsmessage.RR, ttl int) (err error) {
	return c.UpdateDnsCacheTtlWithKey("", host, dnsTyp, answers, ns, extra, ttl)
}

// fixedTtlDeadlineFunc applies the fixed-domain TTL override to the response
// TTL before the cache deadline is computed.
func (c *DnsController) fixedTtlDeadlineFunc(ttl int) deadlineFunc {
	return func(now time.Time, host string) (deadline time.Time, originalDeadline time.Time) {
		originalDeadline = now.Add(time.Duration(ttl) * time.Second)
		if rt := c.runtime(); rt != nil {
			if fixedTtl, ok := rt.fixedDomainTtl[host]; ok {
				return now.Add(time.Duration(fixedTtl) * time.Second), originalDeadline
			}
		}
		return originalDeadline, originalDeadline
	}
}

func (c *DnsController) UpdateDnsCacheTtlWithKey(cacheKey string, host string, dnsTyp uint16, answers, ns, extra []dnsmessage.RR, ttl int) (err error) {
	c.requireStore()
	return c.updateDnsCacheDeadline(cacheKey, host, dnsTyp, answers, ns, extra, c.fixedTtlDeadlineFunc(ttl))
}

// buildMinHeap constructs a min-heap from the cache entries slice.
// The heap property: parent <= children (root is minimum, i.e., oldest access).
// Time complexity: O(n)
func buildMinHeap(entries []cacheEntry) {
	n := len(entries)
	// Start from the last non-leaf node and heapify down
	for i := n/2 - 1; i >= 0; i-- {
		heapifyMin(entries, i, n)
	}
}

// heapifyMin restores the min-heap property for the subtree rooted at index i.
// The heap size is limited to n elements.
// Time complexity: O(log n)
func heapifyMin(entries []cacheEntry, i, n int) {
	for {
		smallest := i
		left := 2*i + 1
		right := 2*i + 2

		// Find smallest (oldest) among root, left child, and right child
		if left < n && entries[left].lastAccess < entries[smallest].lastAccess {
			smallest = left
		}
		if right < n && entries[right].lastAccess < entries[smallest].lastAccess {
			smallest = right
		}

		// If root is already smallest, heap property is satisfied
		if smallest == i {
			break
		}

		// Swap and continue heapifying
		entries[i], entries[smallest] = entries[smallest], entries[i]
		i = smallest
	}
}
