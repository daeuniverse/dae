/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

// must_rules only raises the must flag: the real matcher keeps evaluating and
// takes the outbound from the next matching rule. The trace used to stop at the
// must_rules line and report it as the outbound.
func TestTraceRoutingContinuesPastMustRules(t *testing.T) {
	matcher, rules := newRoutingTraceMatcher(t,
		traceRule([]*config_parser.Function{traceFunction(consts.Function_Port, false, "443")}, consts.OutboundMustRules.String()),
		traceRule([]*config_parser.Function{traceFunction(consts.Function_Port, false, "443")}, "proxy"),
	)
	if len(rules) != 2 || rules[0].Outbound != consts.OutboundMustRules.String() {
		t.Fatalf("rule snapshots = %#v", rules)
	}

	input := RoutingTraceInput{Network: consts.L4ProtoType_TCP, DstPort: 443}
	evaluation, err := matcher.TraceRouting(context.Background(), input, rules, "direct")
	if err != nil {
		t.Fatalf("TraceRouting: %v", err)
	}
	if evaluation.Decision != "determinate" || evaluation.Outbound == nil || *evaluation.Outbound != "proxy" {
		t.Fatalf("decision/outbound = %q/%v, want proxy", evaluation.Decision, evaluation.Outbound)
	}
	if evaluation.Rules[0].Result != "matched" || evaluation.Rules[1].Result != "matched" {
		t.Fatalf("rule results = %#v", evaluation.Rules)
	}
}
