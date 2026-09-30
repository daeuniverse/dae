/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
)

// TestColdStartUnprobedDialerDoesNotOutrankProbed pins that a dialer with no
// latency sample yet cannot win selection over a probed peer through a strong
// negative add_latency, while cold start still returns a dialer (no dropped
// first connection).
func TestColdStartUnprobedDialerDoesNotOutrankProbed(t *testing.T) {
	networkType := newTestNetworkType()
	d1 := newNamedTestDialer(t, "cold-1")
	d2 := newNamedTestDialer(t, "cold-2")

	set := NewAliveDialerSet(
		d1.Log,
		"cold-group",
		networkType,
		0,
		consts.DialerSelectionPolicy_MinLastLatency,
		[]*Dialer{d1, d2},
		[]*Annotation{{AddLatency: -500 * time.Millisecond}, {}},
		func(bool) {},
		false,
	)
	d1.RegisterAliveDialerSet(set)
	d2.RegisterAliveDialerSet(set)
	t.Cleanup(func() {
		d1.UnregisterAliveDialerSet(set)
		d2.UnregisterAliveDialerSet(set)
	})

	// Cold start: no samples yet, selection must still yield a dialer.
	if d, _ := set.GetMinLatency(nil); d == nil {
		t.Fatal("cold start returned no dialer; the first connection would be dropped")
	}

	// Once d2 has a sample it must win, even though unprobed d1 carries a
	// large negative offset.
	d2.collectionFineMu.Lock()
	d2.mustGetCollection(networkType).Latencies10.AppendLatency(80 * time.Millisecond)
	d2.collectionFineMu.Unlock()
	set.NotifyLatencyChange(d2, true)

	if d, _ := set.GetMinLatency(nil); d != d2 {
		t.Fatalf("selected %v, want the probed dialer d2", d)
	}
}
