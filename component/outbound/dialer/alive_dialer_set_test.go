/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"fmt"
	"math"
	"sync"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
)

func TestAliveDialerSet_GetRandExcludedConcurrent(t *testing.T) {
	networkType := newTestNetworkType()
	dialers := []*Dialer{
		newNamedTestDialer(t, "dialer-1"),
		newNamedTestDialer(t, "dialer-2"),
		newNamedTestDialer(t, "dialer-3"),
	}

	set := NewAliveDialerSet(
		dialers[0].Log,
		"test-group",
		networkType,
		0,
		consts.DialerSelectionPolicy_Random,
		dialers,
		[]*Annotation{{}, {}, {}},
		func(bool) {},
		true,
	)
	for _, d := range dialers {
		d.RegisterAliveDialerSet(set)
	}
	t.Cleanup(func() {
		for _, d := range dialers {
			d.UnregisterAliveDialerSet(set)
		}
	})

	excluded := dialers[0]
	errCh := make(chan error, 32)
	var wg sync.WaitGroup

	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				selected := set.GetRandExcluded(excluded)
				if selected == nil {
					errCh <- fmt.Errorf("GetRandExcluded returned nil")
					return
				}
				if selected == excluded {
					errCh <- fmt.Errorf("GetRandExcluded returned the excluded dialer")
					return
				}
			}
		}()
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Fatal(err)
	}
}

func TestAliveDialerSet_GetRandExcludedWithAddWeight(t *testing.T) {
	networkType := newTestNetworkType()
	dialers := []*Dialer{
		newNamedTestDialer(t, "dialer-1"),
		newNamedTestDialer(t, "dialer-2"),
		newNamedTestDialer(t, "dialer-3"),
	}
	set := NewAliveDialerSet(
		dialers[0].Log,
		"test-group",
		networkType,
		0,
		consts.DialerSelectionPolicy_Random,
		dialers,
		[]*Annotation{{}, {AddWeight: 99}, {}},
		func(bool) {},
		true,
	)

	count := make([]int, len(dialers))
	for range 500 {
		selected := set.GetRandExcluded(nil)
		if selected == nil {
			t.Fatal("expected a dialer, got nil")
		}
		for i, d := range dialers {
			if selected == d {
				count[i]++
				break
			}
		}
	}
	if count[1] <= count[0] || count[1] <= count[2] {
		t.Fatalf("weighted dialer was not preferred enough: counts=%v", count)
	}
}

func TestAliveDialerSet_GetRandExcludedWithAddWeightSkipsExcluded(t *testing.T) {
	networkType := newTestNetworkType()
	dialers := []*Dialer{
		newNamedTestDialer(t, "dialer-1"),
		newNamedTestDialer(t, "dialer-2"),
		newNamedTestDialer(t, "dialer-3"),
	}
	set := NewAliveDialerSet(
		dialers[0].Log,
		"test-group",
		networkType,
		0,
		consts.DialerSelectionPolicy_Random,
		dialers,
		[]*Annotation{{}, {AddWeight: 99}, {}},
		func(bool) {},
		true,
	)

	for range 100 {
		selected := set.GetRandExcluded(dialers[1])
		if selected == nil {
			t.Fatal("expected a dialer, got nil")
		}
		if selected == dialers[1] {
			t.Fatal("excluded weighted dialer should never be selected")
		}
	}
}

func TestAliveDialerSet_GetRandExcludedWithLargeAggregateWeights(t *testing.T) {
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
	for range 300 {
		d := set.GetRandExcluded(nil)
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
