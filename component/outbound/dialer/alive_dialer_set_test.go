/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"math"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
)

func TestAliveDialerSet_GetRand_WithLargeAggregateWeights(t *testing.T) {
	dialers := []*Dialer{{}, {}, {}}
	annotations := []*Annotation{
		{AddWeight: math.MaxInt64 - 1},
		{AddWeight: math.MaxInt64 - 1},
		{AddWeight: math.MaxInt64 - 1},
	}
	set := NewAliveDialerSet(
		nil,
		"test-group",
		nil,
		0,
		consts.DialerSelectionPolicy_Random,
		dialers,
		annotations,
		func(bool) {},
		true,
	)
	count := make([]int, len(dialers))
	for i := 0; i < 300; i++ {
		d := set.GetRand()
		if d == nil {
			t.Fatal("expected a dialer, got nil")
		}
		for j, dd := range dialers {
			if d == dd {
				count[j]++
				break
			}
		}
	}
	for i, c := range count {
		if c == 0 {
			t.Fatalf("dialer %d was never selected: counts=%v", i, count)
		}
	}
	if got := set.dialerToWeight[dialers[0]]; got != math.MaxInt64 {
		t.Fatalf("unexpected effective weight: %v", got)
	}
}
