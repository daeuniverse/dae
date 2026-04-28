/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"sync"
	"testing"
	"time"
)

func BenchmarkRuntimeStatsRecord(b *testing.B) {
	s := newRuntimeStats()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.record(1280, 640)
	}
}

func BenchmarkRuntimeStatsRecordParallel(b *testing.B) {
	s := newRuntimeStats()
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			if i%2 == 0 {
				s.record(1280, 0)
			} else {
				s.record(0, 640)
			}
			i++
		}
	})
}

func BenchmarkRuntimeStatsSnapshot(b *testing.B) {
	s := newRuntimeStats()
	now := time.Unix(1_700_000_000, 0)
	for i := 0; i < 3600*4; i++ {
		s.record(1000, 500)
		s.roll(now.Add(time.Duration(i) * 250 * time.Millisecond))
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.snapshot(100, 50, 60, 100, now.Add(15*time.Minute))
	}
}

func BenchmarkRuntimeStatsSnapshotWithRoll(b *testing.B) {
	s := newRuntimeStats()
	base := time.Unix(1_700_000_000, 0)
	for i := 0; i < 100; i++ {
		s.record(1000, 500)
		s.roll(base.Add(time.Duration(i) * 250 * time.Millisecond))
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		now := base.Add(30 * time.Second).Add(time.Duration(i) * 250 * time.Millisecond)
		s.record(1000, 500)
		s.roll(now)
		_ = s.snapshot(100, 50, 60, 10, now)
	}
}

func BenchmarkRuntimeStatsRecordContended(b *testing.B) {
	s := newRuntimeStats()
	var wg sync.WaitGroup
	ready := make(chan struct{})
	numWriters := 32
	wg.Add(numWriters)
	for g := 0; g < numWriters; g++ {
		go func() {
			defer wg.Done()
			<-ready
			for i := 0; i < b.N/numWriters; i++ {
				s.record(1280, 640)
			}
		}()
	}
	b.ReportAllocs()
	b.ResetTimer()
	close(ready)
	wg.Wait()
}
