/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dns

import (
	"testing"

	"github.com/daeuniverse/dae/pkg/config_parser"
)

func TestNewNormalizedRequestRoutingProgramSplitsInternalSelectors(t *testing.T) {
	program, err := NewNormalizedRequestRoutingProgram([]*config_parser.RoutingRule{
		{
			AndFunctions: []*config_parser.Function{{Name: "qname"}},
		},
		{
			AndFunctions: []*config_parser.Function{{Name: "sub"}},
		},
		{
			AndFunctions: []*config_parser.Function{{Name: "node"}},
		},
		{
			AndFunctions: []*config_parser.Function{{Name: "subnode"}},
		},
	}, "asis")
	if err != nil {
		t.Fatalf("NewNormalizedRequestRoutingProgram() error = %v", err)
	}
	if got := len(program.Rules); got != 1 {
		t.Fatalf("len(program.Rules) = %d, want 1", got)
	}
	if got := len(program.SubscriptionRules); got != 1 {
		t.Fatalf("len(program.SubscriptionRules) = %d, want 1", got)
	}
	if got := len(program.NodeRules); got != 1 {
		t.Fatalf("len(program.NodeRules) = %d, want 1", got)
	}
	if got := len(program.SubNodeRules); got != 1 {
		t.Fatalf("len(program.SubNodeRules) = %d, want 1", got)
	}
}
