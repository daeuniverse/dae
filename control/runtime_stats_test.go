/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"testing"
	"time"
)

// A dashboard polls at its own cadence, which never lines up with the 250ms
// bucket grid. The reported one-second rate must still match the traffic that
// actually flowed, no matter when snapshots happen.
func TestRuntimeStatsRateMatchesTrafficAtPollingCadence(t *testing.T) {
	for _, pollInterval := range []time.Duration{
		100 * time.Millisecond,
		300 * time.Millisecond,
		1 * time.Second,
		1300 * time.Millisecond,
		2 * time.Second,
		5 * time.Second,
	} {
		t.Run(pollInterval.String(), func(t *testing.T) {
			store := newRuntimeStats()
			start := time.Unix(1_700_000_000, 0)
			current := start
			store.now = func() time.Time { return current }
			const bytesPerSecond = 1_000_000
			const step = 10 * time.Millisecond

			store.snapshot(0, 0, 3600, 180, start)

			var nextPoll time.Duration
			checked := 0
			for elapsed := time.Duration(0); elapsed <= 6*time.Second; elapsed += step {
				current = start.Add(elapsed)
				store.record(uint64(bytesPerSecond*step/time.Second), 0)
				if elapsed < nextPoll {
					continue
				}
				nextPoll = elapsed + pollInterval
				snapshot := store.snapshot(0, 0, 3600, 180, current)
				if elapsed < time.Second {
					continue
				}
				checked++
				got := float64(snapshot.UploadRate)
				want := float64(bytesPerSecond)
				if got < want*0.85 || got > want*1.15 {
					t.Fatalf("upload rate at %v = %.0f B/s, want ~%.0f B/s", elapsed, got, want)
				}
			}
			if checked == 0 {
				t.Fatal("no rate samples were checked")
			}
		})
	}
}

// record runs on the relay hot path; the bucket rotation must stay cheap.
func BenchmarkRuntimeStatsRecord(b *testing.B) {
	store := newRuntimeStats()
	store.record(1, 0)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		store.record(1024, 1024)
	}
}

func TestThinRuntimeSamplesDecimatesWithoutAggregating(t *testing.T) {
	samples := make([]RuntimeTrafficSample, 1000)
	base := time.Unix(1_700_000_000, 0)
	for i := range samples {
		samples[i] = RuntimeTrafficSample{
			Timestamp:  base.Add(time.Duration(i) * runtimeBucketDuration),
			UploadRate: uint64(1000 + i),
		}
	}
	samples[500].UploadRate = 999_999 // a real spike that must be preserved as-is

	thinned := thinRuntimeSamples(samples, 180)
	if len(thinned) > 180 {
		t.Fatalf("thinned length = %d, want <= 180", len(thinned))
	}
	// stride = ceil(1000/180) = 6
	if want := (1000 + 5) / 6; len(thinned) != want {
		t.Fatalf("thinned length = %d, want %d", len(thinned), want)
	}
	for i := 1; i < len(thinned); i++ {
		if !thinned[i].Timestamp.After(thinned[i-1].Timestamp) {
			t.Fatalf("timestamps are not increasing at %d", i)
		}
	}
	if last := thinned[len(thinned)-1]; last.Timestamp != samples[len(samples)-1].Timestamp {
		t.Fatalf("newest sample missing: got %v want %v", last.Timestamp, samples[len(samples)-1].Timestamp)
	}
	// No synthetic value may appear: every rate must be one the recorder saw.
	original := make(map[uint64]struct{}, len(samples))
	for _, sample := range samples {
		original[sample.UploadRate] = struct{}{}
	}
	for _, sample := range thinned {
		if _, ok := original[sample.UploadRate]; !ok {
			t.Fatalf("thinned sample carries a fabricated rate %d", sample.UploadRate)
		}
	}

	// Short series pass through untouched.
	short := samples[:50]
	if got := thinRuntimeSamples(short, 180); len(got) != 50 {
		t.Fatalf("short series length = %d", len(got))
	}
}
