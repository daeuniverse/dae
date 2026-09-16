/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/daeuniverse/dae/config"
)

// benchDnsCacheEntry builds the minimal cache entry the family-removal path
// touches: only the deadlines are read during deletion.
func benchDnsCacheEntry(deadline time.Time) *DnsCache {
	return &DnsCache{Deadline: deadline, OriginalDeadline: deadline}
}

// benchFillDnsCache plants size entries with distinct base keys and returns the
// controller. Entries are inserted through the controller helpers so the index
// is populated exactly as it is in production.
func benchFillDnsCache(b *testing.B, size int) *DnsController {
	b.Helper()
	c := newCorpusDnsController(b, &config.Dns{
		Routing: config.DnsRouting{
			Request:  config.DnsRequestRouting{Fallback: config.FunctionOrString("asis")},
			Response: config.DnsResponseRouting{Fallback: config.FunctionOrString("accept")},
		},
	})
	deadline := time.Now().Add(time.Hour)
	// Plant exactly as production does: every storeDnsCache caller holds the
	// projection write lock, which is also what keeps the janitor's index
	// reconciliation from observing (or publishing) a half-updated state.
	c.cacheProjectionMu.Lock()
	for i := range size {
		c.storeDnsCache(fmt.Sprintf("bench%d.example.:1|asis", i), benchDnsCacheEntry(deadline))
	}
	c.cacheProjectionMu.Unlock()
	return c
}

// BenchmarkRemoveDnsRespCacheFamily measures the reject-path family removal
// against a cache of 1k/16k/64k entries, for the common no-match case and for a
// single-family match. The match is re-planted outside the timed region so every
// iteration measures the removal itself.
func BenchmarkRemoveDnsRespCacheFamily(b *testing.B) {
	for _, size := range []int{1024, 16384, 65536} {
		b.Run("NoMatch", func(b *testing.B) {
			b.Run(strconv.Itoa(size), func(b *testing.B) {
				c := benchFillDnsCache(b, size)
				b.ReportAllocs()
				b.ResetTimer()
				for range b.N {
					c.RemoveDnsRespCacheFamily("absent.example.:1")
				}
			})
		})
		b.Run("OneMatch", func(b *testing.B) {
			b.Run(strconv.Itoa(size), func(b *testing.B) {
				c := benchFillDnsCache(b, size)
				deadline := time.Now().Add(time.Hour)
				keys := []string{
					"benchmatch.example.:1|asis",
					"benchmatch.example.:1|upstream@1.1.1.1:53",
				}
				b.ReportAllocs()
				b.ResetTimer()
				for range b.N {
					b.StopTimer()
					c.cacheProjectionMu.Lock()
					for _, key := range keys {
						c.storeDnsCache(key, benchDnsCacheEntry(deadline))
					}
					c.cacheProjectionMu.Unlock()
					b.StartTimer()
					c.RemoveDnsRespCacheFamily("benchmatch.example.:1")
				}
			})
		})
	}
}
