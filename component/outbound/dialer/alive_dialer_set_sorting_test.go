/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
)

// TestSortingSnapshotReportsEngineOrder pins the numbers the API reports as
// sorting_latency_ms: the policy metric plus the manual offset, ranked exactly
// like the selection decision - not the bare metric, which is what the API used
// to re-derive and why it disagreed with the log's latency table.
func TestSortingSnapshotReportsEngineOrder(t *testing.T) {
	networkType := newTestNetworkType()
	fast := newNamedTestDialer(t, "fast")
	slow := newNamedTestDialer(t, "slow")
	unprobed := newNamedTestDialer(t, "unprobed")

	set := NewAliveDialerSet(
		fast.Log, "test-group", networkType, 0,
		consts.DialerSelectionPolicy_MinLastLatency,
		[]*Dialer{fast, slow, unprobed},
		[]*Annotation{{}, {AddLatency: 20 * time.Millisecond}, {}},
		func(bool) {}, false,
	)
	// No teardown: the set is not registered on the dialers.

	fast.collectionFineMu.Lock()
	fastCollection := fast.mustGetCollection(networkType)
	fastCollection.Latencies10.AppendLatency(30 * time.Millisecond)
	fast.collectionFineMu.Unlock()
	slow.collectionFineMu.Lock()
	slowCollection := slow.mustGetCollection(networkType)
	slowCollection.Latencies10.AppendLatency(40 * time.Millisecond)
	slow.collectionFineMu.Unlock()

	set.NotifyLatencyChange(fast, true)
	set.NotifyLatencyChange(slow, true)
	// unprobed is alive but has no latency: the selection cannot rank it, so the
	// snapshot must omit it instead of sorting a zero to the front.
	set.NotifyLatencyChange(unprobed, true)

	ranks := set.SortingSnapshot()
	if len(ranks) != 2 {
		t.Fatalf("ranks = %d, want 2 (dialers without latency are omitted)", len(ranks))
	}

	// fast: 30ms + 0 = 30ms; slow: 40ms + 20ms offset = 60ms.
	if ranks[0].Dialer != fast || ranks[0].Rank != 1 {
		t.Fatalf("rank 1 = %v/%d, want fast/1", ranks[0].Dialer, ranks[0].Rank)
	}
	if got := ranks[0].Sorting; got != 30*time.Millisecond {
		t.Fatalf("fast sorting = %v, want 30ms", got)
	}
	if ranks[1].Dialer != slow || ranks[1].Rank != 2 {
		t.Fatalf("rank 2 = %v/%d, want slow/2", ranks[1].Dialer, ranks[1].Rank)
	}
	if got := ranks[1].Offset; got != 20*time.Millisecond {
		t.Fatalf("slow offset = %v, want 20ms", got)
	}
	if got := ranks[1].Sorting; got != 60*time.Millisecond {
		t.Fatalf("slow sorting = %v, want 60ms (metric + offset)", got)
	}
}
