/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"io"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/pkg/fastrand"
	"github.com/daeuniverse/outbound/protocol/direct"
	"github.com/sirupsen/logrus"
)

func benchmarkLegacyGetRandExcluded(a *AliveDialerSet, excluded *Dialer) *Dialer {
	a.mu.RLock()
	defer a.mu.RUnlock()

	var chosen *Dialer
	var candidateCount int
	for i := range a.aliveEntries {
		d := a.aliveEntries[i].dialer
		if d == excluded {
			continue
		}
		candidateCount++
		if fastrand.Intn(candidateCount) == 0 {
			chosen = d
		}
	}
	return chosen
}

func benchmarkLegacyGetMinLatency(a *AliveDialerSet, excluded *Dialer) (*Dialer, time.Duration) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	var nextBest *Dialer
	var nextBestSortingLatency = time.Hour
	for i := range a.aliveEntries {
		entry := &a.aliveEntries[i]
		if entry.dialer == excluded {
			continue
		}
		if entry.sortingLatency < nextBestSortingLatency {
			nextBestSortingLatency = entry.sortingLatency
			nextBest = entry.dialer
		}
	}
	if nextBest != nil {
		return nextBest, nextBestSortingLatency
	}
	return nil, time.Hour
}

func newNamedBenchmarkDialer(b *testing.B, name string) *Dialer {
	b.Helper()

	log := logrus.New()
	log.SetOutput(io.Discard)

	d := NewDialer(
		direct.SymmetricDirect,
		&GlobalOption{
			Log:            log,
			CheckInterval:  time.Minute,
			CheckTolerance: 0,
		},
		InstanceOption{},
		&Property{
			Property: D.Property{Name: name},
		},
	)
	b.Cleanup(func() {
		_ = d.Close()
	})
	return d
}

func newBenchmarkAliveDialerSet(b *testing.B, policy consts.DialerSelectionPolicy, size int) (*AliveDialerSet, []*Dialer, *NetworkType) {
	b.Helper()

	networkType := newTestNetworkType()
	dialers := make([]*Dialer, 0, size)
	annotations := make([]*Annotation, 0, size)
	for i := 0; i < size; i++ {
		d := newNamedBenchmarkDialer(b, "bench-dialer")
		dialers = append(dialers, d)
		annotations = append(annotations, &Annotation{})
	}

	set := NewAliveDialerSet(
		dialers[0].Log,
		"bench-group",
		networkType,
		0,
		policy,
		dialers,
		annotations,
		func(bool) {},
		true,
	)
	for i, d := range dialers {
		if policy != consts.DialerSelectionPolicy_Random {
			d.MustGetLatencies10(networkType).AppendLatency(time.Duration(i+1) * time.Millisecond)
			set.NotifyLatencyChange(d, true)
		}
		d.RegisterAliveDialerSet(set)
	}
	b.Cleanup(func() {
		for _, d := range dialers {
			d.UnregisterAliveDialerSet(set)
		}
	})

	return set, dialers, networkType
}

func BenchmarkAliveDialerSetGetMinLatency(b *testing.B) {
	set, dialers, _ := newBenchmarkAliveDialerSet(b, consts.DialerSelectionPolicy_MinLastLatency, 64)
	excludedBest := dialers[0]
	excludedOther := dialers[len(dialers)-1]

	b.Run("Current_NoExclusion", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, _ = set.GetMinLatency(nil)
		}
	})

	b.Run("Legacy_NoExclusion", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, _ = benchmarkLegacyGetMinLatency(set, nil)
		}
	})

	b.Run("Current_ExcludeNonBest", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, _ = set.GetMinLatency(excludedOther)
		}
	})

	b.Run("Legacy_ExcludeNonBest", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, _ = benchmarkLegacyGetMinLatency(set, excludedOther)
		}
	})

	b.Run("Current_ExcludeBest", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, _ = set.GetMinLatency(excludedBest)
		}
	})

	b.Run("Legacy_ExcludeBest", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, _ = benchmarkLegacyGetMinLatency(set, excludedBest)
		}
	})
}

func BenchmarkAliveDialerSetGetRandExcluded(b *testing.B) {
	set, dialers, _ := newBenchmarkAliveDialerSet(b, consts.DialerSelectionPolicy_Random, 64)
	excluded := dialers[0]

	b.Run("Current_NoExclusion", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = set.GetRandExcluded(nil)
		}
	})

	b.Run("Legacy_NoExclusion", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = benchmarkLegacyGetRandExcluded(set, nil)
		}
	})

	b.Run("Current_WithExclusion", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = set.GetRandExcluded(excluded)
		}
	})

	b.Run("Legacy_WithExclusion", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = benchmarkLegacyGetRandExcluded(set, excluded)
		}
	})
}
