/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"fmt"
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
