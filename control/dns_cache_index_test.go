/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"fmt"
	"testing"
	"time"

	"github.com/daeuniverse/dae/config"
)

// These tests pin the base-key index that RemoveDnsRespCacheFamily and the
// knowledge resync rely on. The index is what turns a reject verdict from
// a table-wide scan under cacheProjectionMu into a keyed lookup; if it silently
// drifts, family removal would stop matching entries without any visible
// failure, which is why drift must be both repairable and reported.

func indexTestCache(deadline time.Time) *DnsCache {
	return &DnsCache{Deadline: deadline, OriginalDeadline: deadline}
}

// TestRemoveDnsRespCacheFamilyRemovesOnlyIndexedFamily checks the deletion
// scope: every key of the requested base key goes, nothing else does, and the
// index and knowledge bookkeeping follow.
func TestRemoveDnsRespCacheFamilyRemovesOnlyIndexedFamily(t *testing.T) {
	c := newSemanticsController(t)
	deadline := time.Now().Add(time.Minute)

	familyKeys := []string{
		"fam.example.:1|asis",
		"fam.example.:1|upstream@1.1.1.1:53",
	}
	otherKeys := []string{
		"fam.example.:28|asis", // same name, different qtype: a different base key
		"other.example.:1|asis",
	}
	for _, key := range append(append([]string{}, familyKeys...), otherKeys...) {
		c.storeDnsCache(key, indexTestCache(deadline))
	}
	c.rememberDnsKnowledge("fam.example.:1", deadline, true)
	c.rememberDnsKnowledge("fam.example.:28", deadline, true)

	c.RemoveDnsRespCacheFamily("fam.example.:1")

	for _, key := range familyKeys {
		if _, ok := c.dnsCache.Load(key); ok {
			t.Fatalf("cache entry %q must be removed with its family", key)
		}
		if got := c.dnsCacheIndexSnapshot(dnsCacheBaseKey(key)); len(got) != 0 {
			t.Fatalf("index for %q still holds %v after family removal", dnsCacheBaseKey(key), got)
		}
	}
	for _, key := range otherKeys {
		if _, ok := c.dnsCache.Load(key); !ok {
			t.Fatalf("cache entry %q belongs to another family and must survive", key)
		}
	}
	if got, want := c.dnsCacheSize.Load(), int64(len(otherKeys)); got != want {
		t.Fatalf("dnsCacheSize = %d, want %d", got, want)
	}
	if got, want := c.dnsCacheIndexLen(), len(otherKeys); got != want {
		t.Fatalf("indexed keys = %d, want %d", got, want)
	}
	if c.HasDnsKnowledge("fam.example.:1") {
		t.Fatal("knowledge for the removed family must be dropped")
	}
	if !c.HasDnsKnowledge("fam.example.:28") {
		t.Fatal("knowledge for an unrelated base key must survive")
	}
}

// TestRemoveDnsRespCacheFamilyMissDoesNotTakeProjectionWriteLock pins the
// property itself: a base key with no indexed entries must return without
// the projection write lock. The test holds the read lock, so a write lock
// attempt cannot complete; the call is given a bounded budget to return inside.
func TestRemoveDnsRespCacheFamilyMissDoesNotTakeProjectionWriteLock(t *testing.T) {
	c := newSemanticsController(t)
	c.storeDnsCache("present.example.:1|asis", indexTestCache(time.Now().Add(time.Minute)))

	c.cacheProjectionMu.RLock()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c.RemoveDnsRespCacheFamily("absent.example.:1")
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		c.cacheProjectionMu.RUnlock()
		t.Fatal("RemoveDnsRespCacheFamily blocked on the projection write lock for a base key with no indexed entries")
	}
	c.cacheProjectionMu.RUnlock()

	if _, ok := c.dnsCache.Load("present.example.:1|asis"); !ok {
		t.Fatal("an unrelated entry must survive a no-match family removal")
	}
}

// TestDnsCacheIndexReconcileRepairsDrift checks both drift directions and that
// the repair leaves the index usable again.
func TestDnsCacheIndexReconcileRepairsDrift(t *testing.T) {
	deadline := time.Now().Add(time.Minute)

	t.Run("missing entry", func(t *testing.T) {
		c := newSemanticsController(t)
		for i := range 3 {
			c.storeDnsCache(fmt.Sprintf("drift%d.example.:1|asis", i), indexTestCache(deadline))
		}
		// Simulate a store that bypassed the controller helpers.
		c.dnsCacheIndexRemove("drift1.example.:1|asis")
		if got, want := c.dnsCacheIndexLen(), 2; got != want {
			t.Fatalf("indexed keys = %d, want %d before reconcile", got, want)
		}

		before := c.dnsCacheIndexReconciles.Load()
		c.reconcileDnsCacheIndex()
		if got, want := c.dnsCacheIndexReconciles.Load(), before+1; got != want {
			t.Fatalf("reconcile counter = %d, want %d", got, want)
		}
		if got, want := c.dnsCacheIndexLen(), 3; got != want {
			t.Fatalf("indexed keys = %d, want %d after reconcile", got, want)
		}
		if got, want := c.dnsCacheSize.Load(), int64(3); got != want {
			t.Fatalf("dnsCacheSize = %d, want %d after reconcile", got, want)
		}

		// A repaired index must restore family removal for the dropped key.
		c.RemoveDnsRespCacheFamily("drift1.example.:1")
		if _, ok := c.dnsCache.Load("drift1.example.:1|asis"); ok {
			t.Fatal("family removal must work again after the index was repaired")
		}
	})

	t.Run("ghost index entry and drifted size", func(t *testing.T) {
		c := newSemanticsController(t)
		for i := range 2 {
			c.storeDnsCache(fmt.Sprintf("ghost%d.example.:1|asis", i), indexTestCache(deadline))
		}
		c.dnsCacheIndexAdd("ghost-vanished.example.:1|asis")
		c.dnsCacheSize.Add(5)

		before := c.dnsCacheIndexReconciles.Load()
		c.reconcileDnsCacheIndex()
		if got, want := c.dnsCacheIndexReconciles.Load(), before+1; got != want {
			t.Fatalf("reconcile counter = %d, want %d", got, want)
		}
		if got, want := c.dnsCacheIndexLen(), 2; got != want {
			t.Fatalf("indexed keys = %d, want %d after reconcile", got, want)
		}
		if got, want := c.dnsCacheSize.Load(), int64(2); got != want {
			t.Fatalf("dnsCacheSize = %d, want %d after reconcile", got, want)
		}
		if got := c.dnsCacheIndexSnapshot("ghost-vanished.example.:1"); len(got) != 0 {
			t.Fatalf("a key without a cache entry must be dropped from the index, got %v", got)
		}
	})

	t.Run("consistent index is left alone", func(t *testing.T) {
		c := newSemanticsController(t)
		c.storeDnsCache("steady.example.:1|asis", indexTestCache(deadline))
		before := c.dnsCacheIndexReconciles.Load()
		c.reconcileDnsCacheIndex()
		if got := c.dnsCacheIndexReconciles.Load(); got != before {
			t.Fatalf("reconcile counter = %d, want %d for an already consistent index", got, before)
		}
	})
}

// TestCloseClearsDnsCacheIndex keeps the index from outliving the cache it
// describes: a closed controller must not report indexed keys.
func TestCloseClearsDnsCacheIndex(t *testing.T) {
	c := newCorpusDnsController(t, &config.Dns{
		Routing: config.DnsRouting{
			Request:  config.DnsRequestRouting{Fallback: config.FunctionOrString("asis")},
			Response: config.DnsResponseRouting{Fallback: config.FunctionOrString("accept")},
		},
	})
	c.storeDnsCache("closing.example.:1|asis", indexTestCache(time.Now().Add(time.Minute)))
	if got := c.dnsCacheIndexLen(); got != 1 {
		t.Fatalf("indexed keys = %d, want 1 before Close", got)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := c.dnsCacheIndexLen(); got != 0 {
		t.Fatalf("indexed keys = %d, want 0 after Close", got)
	}
}

// TestDnsCacheIndexStaysConsistentUnderFamilyRemoval is the invariant the
// janitor reconciliation relies on: repeated store/remove cycles through the
// controller helpers must leave the index and the size counter equal. A drift
// here would make family removal silently stop matching entries.
func TestDnsCacheIndexStaysConsistentUnderFamilyRemoval(t *testing.T) {
	c := newSemanticsController(t)
	deadline := time.Now().Add(time.Hour)
	for i := range 1024 {
		c.storeDnsCache(fmt.Sprintf("steady%d.example.:1|asis", i), indexTestCache(deadline))
	}
	keys := []string{
		"churn.example.:1|asis",
		"churn.example.:1|upstream@1.1.1.1:53",
	}
	for i := range 20000 {
		c.cacheProjectionMu.Lock()
		c.storeDnsCache(keys[0], indexTestCache(deadline))
		c.storeDnsCache(keys[1], indexTestCache(deadline))
		c.cacheProjectionMu.Unlock()
		c.RemoveDnsRespCacheFamily("churn.example.:1")
		if got, want := int64(c.dnsCacheIndexLen()), c.dnsCacheSize.Load(); got != want {
			t.Fatalf("iteration %d: indexed keys = %d, cache size = %d", i, got, want)
		}
	}
	if got, want := c.dnsCacheIndexLen(), 1024; got != want {
		t.Fatalf("indexed keys = %d, want %d after the churn", got, want)
	}
}

// TestReconcileDoesNotReportDriftForConsistentMutations runs the reconciliation
// concurrently with the store/remove cycle. The counters must be read as one
// consistent snapshot, otherwise a half-applied store is mistaken for drift and
// the janitor rebuilds (and reports an error) for a healthy cache.
func TestReconcileDoesNotReportDriftForConsistentMutations(t *testing.T) {
	c := newSemanticsController(t)
	deadline := time.Now().Add(time.Hour)
	for i := range 256 {
		c.storeDnsCache(fmt.Sprintf("steady%d.example.:1|asis", i), indexTestCache(deadline))
	}

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
				c.reconcileDnsCacheIndex()
			}
		}
	}()

	keys := []string{
		"churn.example.:1|asis",
		"churn.example.:1|upstream@1.1.1.1:53",
	}
	for range 5000 {
		// Production stores always run under the projection write lock; the
		// reconciliation snapshot is only meaningful if they do.
		c.cacheProjectionMu.Lock()
		c.storeDnsCache(keys[0], indexTestCache(deadline))
		c.storeDnsCache(keys[1], indexTestCache(deadline))
		c.cacheProjectionMu.Unlock()
		c.RemoveDnsRespCacheFamily("churn.example.:1")
	}
	close(stop)
	<-done

	if got := c.dnsCacheIndexReconciles.Load(); got != 0 {
		t.Fatalf("reconciliations = %d, want 0 for a consistent cache", got)
	}
	if got, want := int64(c.dnsCacheIndexLen()), c.dnsCacheSize.Load(); got != want {
		t.Fatalf("indexed keys = %d, cache size = %d", got, want)
	}
}
