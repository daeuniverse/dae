/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package routing

import (
	"testing"

	"github.com/daeuniverse/dae/pkg/config_parser"
)

// TestMergeAndSortRulesKeepsAllOutboundParams is the regression for the
// rule-merge identity site: the merge decision compared Outbound.String, whose
// display form ellipsizes params from index 5 on, so two rules whose outbounds
// differ only in a late param were treated as the same outbound and merged.
func TestMergeAndSortRulesKeepsAllOutboundParams(t *testing.T) {
	params := func(last string) []*config_parser.Param {
		return []*config_parser.Param{
			{Key: "k1", Val: "1"},
			{Key: "k2", Val: "2"},
			{Key: "k3", Val: "3"},
			{Key: "k4", Val: "4"},
			{Key: "k5", Val: "5"},
			{Key: "k6", Val: last},
		}
	}
	mkRule := func(domain, last string) *config_parser.RoutingRule {
		return &config_parser.RoutingRule{
			AndFunctions: []*config_parser.Function{
				{Name: "domain", Params: []*config_parser.Param{{Key: "suffix", Val: domain}}},
			},
			Outbound: config_parser.Function{Name: "proxy", Params: params(last)},
		}
	}

	// Fixture guard: the two outbounds are indistinguishable through the
	// display form but differ through the lossless form.
	a := mkRule("a.com", "aaa").Outbound
	b := mkRule("b.com", "bbb").Outbound
	if a.String(true, false, true) != b.String(true, false, true) {
		t.Fatal("fixture is stale: the display form stopped truncating params")
	}

	merged, err := (&MergeAndSortRulesOptimizer{}).Optimize([]*config_parser.RoutingRule{
		mkRule("a.com", "aaa"),
		mkRule("b.com", "bbb"),
	})
	if err != nil {
		t.Fatalf("Optimize: %v", err)
	}
	if len(merged) != 2 {
		t.Fatalf("rules merged across distinct outbound params: got %d rules, want 2", len(merged))
	}

	// Identical outbounds must still merge.
	merged, err = (&MergeAndSortRulesOptimizer{}).Optimize([]*config_parser.RoutingRule{
		mkRule("a.com", "aaa"),
		mkRule("b.com", "aaa"),
	})
	if err != nil {
		t.Fatalf("Optimize: %v", err)
	}
	if len(merged) != 1 {
		t.Fatalf("identical-outbound singleton rules did not merge: got %d rules, want 1", len(merged))
	}
}
