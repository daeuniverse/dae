/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@daeuniverse.org>
 */

package control

import (
	"fmt"
	"sort"
	"sync"
	"testing"
	"time"
)

// BenchmarkInsertionSort benchmarks insertion sort performance
func BenchmarkInsertionSort(b *testing.B) {
	type cacheEntry struct {
		key        string
		lastAccess int64
	}
	
	now := time.Now()
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		// Create 1000 entries with random-ish timestamps
		entries := make([]cacheEntry, 1000)
		for j := 0; j < 1000; j++ {
			entries[j] = cacheEntry{
				key:        fmt.Sprintf("domain%d", j),
				lastAccess: now.Add(time.Duration(j*17) * time.Microsecond).UnixNano(),
			}
		}
		
		// Insertion sort
		for i := 1; i < len(entries); i++ {
			for j := i; j > 0 && entries[j].lastAccess < entries[j-1].lastAccess; j-- {
				entries[j], entries[j-1] = entries[j-1], entries[j]
			}
		}
	}
}

// BenchmarkStdlibSort benchmarks stdlib sort performance
func BenchmarkStdlibSort(b *testing.B) {
	type cacheEntry struct {
		key        string
		lastAccess int64
	}
	
	now := time.Now()
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		// Create 1000 entries with random-ish timestamps
		entries := make([]cacheEntry, 1000)
		for j := 0; j < 1000; j++ {
			entries[j] = cacheEntry{
				key:        fmt.Sprintf("domain%d", j),
				lastAccess: now.Add(time.Duration(j*17) * time.Microsecond).UnixNano(),
			}
		}
		
		// Stdlib sort
		sort.Slice(entries, func(i, j int) bool {
			return entries[i].lastAccess < entries[j].lastAccess
		})
	}
}

// BenchmarkPartialSort benchmarks finding top-N oldest entries
// This simulates the common case where we only need to evict a few entries
func BenchmarkPartialSort_Top10(b *testing.B) {
	type cacheEntry struct {
		key        string
		lastAccess int64
	}
	
	now := time.Now()
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		// Create 1000 entries with random-ish timestamps
		entries := make([]cacheEntry, 1000)
		for j := 0; j < 1000; j++ {
			entries[j] = cacheEntry{
				key:        fmt.Sprintf("domain%d", j),
				lastAccess: now.Add(time.Duration(j*17) * time.Microsecond).UnixNano(),
			}
		}
		
		// Find top 10 oldest using partial selection (like quickselect)
		// For simplicity, we'll just sort the first 10 elements
		for i := 0; i < 10; i++ {
			minIdx := i
			for j := i + 1; j < len(entries); j++ {
				if entries[j].lastAccess < entries[minIdx].lastAccess {
					minIdx = j
				}
			}
			entries[i], entries[minIdx] = entries[minIdx], entries[i]
		}
	}
}

// BenchmarkSyncMapLoadDelete benchmarks Load + Delete pattern
func BenchmarkSyncMapLoadDelete(b *testing.B) {
	var m sync.Map
	
	// Pre-populate with 100 entries
	for i := 0; i < 100; i++ {
		m.Store(fmt.Sprintf("key%d", i), i)
	}
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		key := fmt.Sprintf("key%d", i%100)
		if val, ok := m.Load(key); ok {
			// Simulate eviction check
			_ = val
			m.Delete(key)
		}
		// Re-add for next iteration
		m.Store(key, i%100)
	}
}

// BenchmarkSyncMapCompareAndDelete benchmarks CompareAndDelete
func BenchmarkSyncMapCompareAndDelete(b *testing.B) {
	var m sync.Map
	
	// Pre-populate with 100 entries
	for i := 0; i < 100; i++ {
		m.Store(fmt.Sprintf("key%d", i), i)
	}
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		key := fmt.Sprintf("key%d", i%100)
		if val, ok := m.Load(key); ok {
			// Simulate eviction with CAS
			m.CompareAndDelete(key, val)
		}
		// Re-add for next iteration
		m.Store(key, i%100)
	}
}

// BenchmarkSyncMapRangeDelete benchmarks Range + Delete pattern
func BenchmarkSyncMapRangeDelete(b *testing.B) {
	var m sync.Map
	
	// Pre-populate with 1000 entries
	for i := 0; i < 1000; i++ {
		m.Store(fmt.Sprintf("key%d", i), i)
	}
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		// Delete oldest 100 entries
		count := 0
		m.Range(func(key, value interface{}) bool {
			if count >= 100 {
				return false
			}
			m.Delete(key)
			count++
			return true
		})
		
		// Re-add 100 entries
		for j := 0; j < 100; j++ {
			m.Store(fmt.Sprintf("key%d", j), j)
		}
	}
}
