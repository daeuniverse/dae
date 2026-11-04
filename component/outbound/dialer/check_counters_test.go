/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"context"
	"fmt"
	"testing"
)

// TestCheck_CountersCountOnlyVerdicts pins the health-check counters exported
// as dae_health_check_total / dae_health_check_failure_total: a skip or a
// probe-infrastructure failure carries no node evidence and must not dilute
// the failure ratio.
func TestCheck_CountersCountOnlyVerdicts(t *testing.T) {
	d := newNamedTestDialer(t, "counter-node")
	typ := newTestNetworkType()

	steps := []struct {
		name        string
		result      func() (bool, error)
		wantTotal   uint64
		wantFailure uint64
	}{
		{"success", func() (bool, error) { return true, nil }, 1, 0},
		{"node failure", func() (bool, error) { return false, fmt.Errorf("connection refused") }, 2, 1},
		{"check option unavailable", func() (bool, error) {
			return false, wrapCheckOptionError(fmt.Errorf("resolve refused"))
		}, 2, 1},
		{"plain skip", func() (bool, error) { return false, nil }, 2, 1},
	}
	for _, step := range steps {
		result := step.result
		opts := &CheckOption{
			networkType: typ,
			CheckFunc: func(context.Context, *NetworkType) (bool, error) {
				return result()
			},
		}
		_, _ = d.check(opts, false, nil)
		total, failure := d.GetCollectionCounters(typ)
		if total != step.wantTotal || failure != step.wantFailure {
			t.Fatalf("after %s: total=%d failure=%d, want %d and %d", step.name, total, failure, step.wantTotal, step.wantFailure)
		}
	}
}
