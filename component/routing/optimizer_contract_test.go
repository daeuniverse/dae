/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package routing

import (
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

func TestCloneParamsCopiesSliceButSharesParamObjects(t *testing.T) {
	p0 := &config_parser.Param{Key: "k0", Val: "v0"}
	params := []*config_parser.Param{p0, nil}
	cloned := cloneParams(params)

	if len(cloned) != len(params) {
		t.Fatalf("unexpected len: %d", len(cloned))
	}
	if cloned[0] != p0 {
		t.Fatalf("expected shared param pointer")
	}

	cloned[0] = nil
	if params[0] == nil {
		t.Fatalf("expected independent slice container")
	}
}

func TestPostDatReaderOptimizersDoNotMutateCachedParams(t *testing.T) {
	originKey := string(consts.RoutingDomainKey_Suffix)
	originVal := "example.com"
	cached := []*config_parser.Param{
		{Key: originKey, Val: originVal},
	}

	hit1 := cloneParams(cached)
	hit2 := cloneParams(cached)

	rules := []*config_parser.RoutingRule{
		{
			AndFunctions: []*config_parser.Function{
				{
					Name: consts.Function_Domain,
					Params: []*config_parser.Param{
						hit1[0],
						{Key: string(consts.RoutingDomainKey_Keyword), Val: "example"},
					},
				},
			},
			Outbound: config_parser.Function{Name: "out"},
		},
		{
			AndFunctions: []*config_parser.Function{
				{
					Name:   consts.Function_Domain,
					Params: []*config_parser.Param{hit2[0]},
				},
			},
			Outbound: config_parser.Function{Name: "out"},
		},
	}

	var err error
	rules, err = (&MergeAndSortRulesOptimizer{}).Optimize(rules)
	if err != nil {
		t.Fatalf("MergeAndSortRulesOptimizer failed: %v", err)
	}
	_, err = (&DeduplicateParamsOptimizer{}).Optimize(rules)
	if err != nil {
		t.Fatalf("DeduplicateParamsOptimizer failed: %v", err)
	}

	if cached[0].Key != originKey || cached[0].Val != originVal {
		t.Fatalf("cached param mutated: got %q:%q", cached[0].Key, cached[0].Val)
	}
}
