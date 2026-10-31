/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"testing"
	"time"

	ob "github.com/daeuniverse/dae/component/outbound"
)

// useRuntimeStatsStore swaps the process-wide traffic store for a test one and
// restores every package-level pointer the accounting path touches.
func useRuntimeStatsStore(t *testing.T, store *runtimeStats) {
	t.Helper()
	prevActive := activeRuntimeStats.Swap(store)
	prevLast := lastPublishedRuntimeStats.Swap(store)
	t.Cleanup(func() {
		activeRuntimeStats.Store(prevActive)
		lastPublishedRuntimeStats.Store(prevLast)
		setDirectTrafficCounters(nil)
	})
}

// TestDirectTrafficFeedsBuiltinDirectRow pins the fix for the two symptoms that
// made the API look wrong: the builtin direct row stayed at zero forever, so
// sum(runtime/outbounds) could never match runtime.traffic.bytes.
func TestDirectTrafficFeedsBuiltinDirectRow(t *testing.T) {
	registry := ob.NewCounterRegistry()
	plane := &ControlPlane{}
	plane.outbounds = []*ob.DialerGroup{{Name: "direct"}, {Name: "block"}, {Name: "proxy"}}
	plane.attachOutboundCounters(registry)

	store := newRuntimeStats()
	useRuntimeStatsStore(t, store)

	if got := directTrafficCounters.Load(); got != registry.Lookup("direct") {
		t.Fatalf("direct counters = %p, want the registry entry for %q", got, "direct")
	}

	store.record(10, 20)
	var accountant directTrafficAccountant
	accountant.publish(100, 200)

	snapshot := plane.SnapshotOutboundCounters()
	if snapshot.Outbounds[0].Name != "direct" || snapshot.Outbounds[0].Kind != "builtin" {
		t.Fatalf("first outbound = %q/%q, want direct/builtin", snapshot.Outbounds[0].Name, snapshot.Outbounds[0].Kind)
	}
	if got := snapshot.Outbounds[0]; got.UploadBytes != 100 || got.DownloadBytes != 200 {
		t.Fatalf("direct row bytes = %d/%d, want 100/200", got.UploadBytes, got.DownloadBytes)
	}
	if !snapshot.CounterSince.Equal(registry.Since()) {
		t.Fatalf("counter_since = %v, want the registry boundary %v", snapshot.CounterSince, registry.Since())
	}
	if got := plane.OutboundCountersSince(); !got.Equal(registry.Since()) {
		t.Fatalf("OutboundCountersSince = %v, want %v", got, registry.Since())
	}

	stats := store.snapshot(0, 0, 60, 60, time.Now())
	if stats.UploadTotal != 110 || stats.DownloadTotal != 220 {
		t.Fatalf("totals = %d/%d, want 110/220", stats.UploadTotal, stats.DownloadTotal)
	}
	if stats.UserspaceUploadTotal != 10 || stats.UserspaceDownloadTotal != 20 {
		t.Fatalf("userspace plane = %d/%d, want 10/20", stats.UserspaceUploadTotal, stats.UserspaceDownloadTotal)
	}
	if stats.DirectUploadTotal != 100 || stats.DirectDownloadTotal != 200 {
		t.Fatalf("kernel_direct plane = %d/%d, want 100/200", stats.DirectUploadTotal, stats.DirectDownloadTotal)
	}
	// The planes must partition the total: a reader picking one plane must not
	// silently lose or duplicate bytes.
	if stats.UserspaceUploadTotal+stats.DirectUploadTotal != stats.UploadTotal ||
		stats.UserspaceDownloadTotal+stats.DirectDownloadTotal != stats.DownloadTotal {
		t.Fatalf("planes do not partition the total: %+v", stats)
	}
}

// TestPublishInheritsTrafficTotals pins the reload fix: a new generation used
// to start from zero while runtime/outbounds kept its process-level totals.
func TestPublishInheritsTrafficTotals(t *testing.T) {
	prev := newRuntimeStats()
	prev.record(100, 200)
	prev.recordDirect(7, 9)

	prevActive := activeRuntimeStats.Swap(nil)
	prevLast := lastPublishedRuntimeStats.Swap(prev)
	t.Cleanup(func() {
		activeRuntimeStats.Store(prevActive)
		lastPublishedRuntimeStats.Store(prevLast)
	})

	next := newRuntimeStats()
	publishRuntimeStatsStore(next)

	if got := next.uploadTotal.Load(); got != 107 {
		t.Fatalf("inherited upload total = %d, want 107", got)
	}
	if got := next.downloadTotal.Load(); got != 209 {
		t.Fatalf("inherited download total = %d, want 209", got)
	}
	if got := next.userspaceUploadBytes.Load(); got != 100 {
		t.Fatalf("inherited userspace upload = %d, want 100", got)
	}
	if got := next.directDownloadBytes.Load(); got != 9 {
		t.Fatalf("inherited kernel_direct download = %d, want 9", got)
	}

	// Publishing the same store twice must not double the totals.
	publishRuntimeStatsStore(next)
	if got := next.uploadTotal.Load(); got != 107 {
		t.Fatalf("re-publish doubled the total: %d, want 107", got)
	}
}
