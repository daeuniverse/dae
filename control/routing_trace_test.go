/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"net/netip"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/sirupsen/logrus"
)

func newRoutingTraceMatcher(t *testing.T, rules ...*config_parser.RoutingRule) (*RoutingMatcher, []RoutingRuleSnapshot) {
	t.Helper()
	program, err := routing.NewNormalizedProgram(rules, config.FunctionOrString("direct"))
	if err != nil {
		t.Fatalf("create normalized program: %v", err)
	}
	builder, err := NewRoutingMatcherBuilderFromProgram(logrus.New(), program, map[string]uint8{
		"direct": uint8(consts.OutboundDirect),
		"proxy":  uint8(consts.OutboundUserDefinedMin),
	}, nil)
	if err != nil {
		t.Fatalf("create routing matcher builder: %v", err)
	}
	matcher, err := builder.BuildUserspace()
	if err != nil {
		t.Fatalf("build routing matcher: %v", err)
	}
	snapshots := make([]RoutingRuleSnapshot, len(rules))
	for i, rule := range rules {
		snapshots[i] = RoutingRuleSnapshot{
			Expression: rule.String(false, false, false),
			Outbound:   rule.Outbound.Name,
		}
	}
	return matcher, snapshots
}

func traceRule(functions []*config_parser.Function, outbound string) *config_parser.RoutingRule {
	return &config_parser.RoutingRule{
		AndFunctions: functions,
		Outbound:     config_parser.Function{Name: outbound},
	}
}

func traceFunction(name string, not bool, values ...string) *config_parser.Function {
	params := make([]*config_parser.Param, 0, len(values))
	for _, value := range values {
		params = append(params, &config_parser.Param{Val: value})
	}
	return &config_parser.Function{Name: name, Not: not, Params: params}
}

func TestTraceRoutingMatchesOrderedRulesAndSkipsTail(t *testing.T) {
	matcher, rules := newRoutingTraceMatcher(t,
		traceRule([]*config_parser.Function{traceFunction(consts.Function_Port, false, "80", "443")}, "proxy"),
		traceRule([]*config_parser.Function{traceFunction(consts.Function_Port, false, "8080")}, "direct"),
	)
	input := RoutingTraceInput{Network: consts.L4ProtoType_TCP, DstPort: 443}
	evaluation, err := matcher.TraceRouting(context.Background(), input, rules, "direct")
	if err != nil {
		t.Fatalf("TraceRouting: %v", err)
	}
	if evaluation.Decision != "determinate" || evaluation.Outbound == nil || *evaluation.Outbound != "proxy" {
		t.Fatalf("decision/outbound = %q/%v", evaluation.Decision, evaluation.Outbound)
	}
	if evaluation.Rules[0].Result != "matched" ||
		evaluation.Rules[1].Result != "skipped" ||
		evaluation.Rules[2].Result != "skipped" {
		t.Fatalf("rule results = %#v", evaluation.Rules)
	}
}

func TestTraceRoutingReportsMissingInputsAsIndeterminate(t *testing.T) {
	matcher, rules := newRoutingTraceMatcher(t,
		traceRule([]*config_parser.Function{traceFunction(consts.Function_SourcePort, false, "1000")}, "proxy"),
	)
	input := RoutingTraceInput{
		Network: consts.L4ProtoType_TCP,
		DstIP:   addrPointer(netip.MustParseAddr("198.51.100.10")),
		DstPort: 443,
	}
	evaluation, err := matcher.TraceRouting(context.Background(), input, rules, "direct")
	if err != nil {
		t.Fatalf("TraceRouting: %v", err)
	}
	if evaluation.Decision != "indeterminate" || evaluation.Outbound != nil {
		t.Fatalf("decision/outbound = %q/%v", evaluation.Decision, evaluation.Outbound)
	}
	if evaluation.Rules[0].Result != "indeterminate" ||
		len(evaluation.Rules[0].MissingInputs) != 1 ||
		evaluation.Rules[0].MissingInputs[0] != "src_port" ||
		evaluation.Rules[1].Result != "skipped" {
		t.Fatalf("rule results = %#v", evaluation.Rules)
	}
}

func TestTraceRoutingNegationAndFallback(t *testing.T) {
	matcher, rules := newRoutingTraceMatcher(t,
		traceRule([]*config_parser.Function{traceFunction(consts.Function_Port, true, "80", "443")}, "proxy"),
	)

	input := RoutingTraceInput{Network: consts.L4ProtoType_TCP, DstPort: 80}
	evaluation, err := matcher.TraceRouting(context.Background(), input, rules, "direct")
	if err != nil {
		t.Fatalf("TraceRouting matching negated values: %v", err)
	}
	if evaluation.Decision != "determinate" || evaluation.Outbound == nil || *evaluation.Outbound != "direct" ||
		evaluation.Rules[0].Result != "not_matched" || evaluation.Rules[1].Result != "matched" {
		t.Fatalf("negated match result = %#v", evaluation)
	}

	input.DstPort = 8080
	evaluation, err = matcher.TraceRouting(context.Background(), input, rules, "direct")
	if err != nil {
		t.Fatalf("TraceRouting matching negated rule: %v", err)
	}
	if evaluation.Decision != "determinate" || evaluation.Outbound == nil || *evaluation.Outbound != "proxy" ||
		evaluation.Rules[0].Result != "matched" || evaluation.Rules[1].Result != "skipped" {
		t.Fatalf("negated non-match result = %#v", evaluation)
	}
}

func TestTraceRoutingCombinesRuleConditionsWithAnd(t *testing.T) {
	matcher, rules := newRoutingTraceMatcher(t,
		traceRule([]*config_parser.Function{
			traceFunction(consts.Function_SourcePort, false, "1000"),
			traceFunction(consts.Function_Port, false, "80"),
		}, "proxy"),
	)
	input := RoutingTraceInput{Network: consts.L4ProtoType_TCP, DstPort: 81}
	evaluation, err := matcher.TraceRouting(context.Background(), input, rules, "direct")
	if err != nil {
		t.Fatalf("TraceRouting: %v", err)
	}
	if evaluation.Decision != "determinate" || evaluation.Outbound == nil || *evaluation.Outbound != "direct" ||
		evaluation.Rules[0].Result != "not_matched" || evaluation.Rules[1].Result != "matched" {
		t.Fatalf("known false condition should settle the conjunction: %#v", evaluation)
	}

	input.DstPort = 80
	evaluation, err = matcher.TraceRouting(context.Background(), input, rules, "direct")
	if err != nil {
		t.Fatalf("TraceRouting: %v", err)
	}
	if evaluation.Decision != "indeterminate" || evaluation.Rules[0].Result != "indeterminate" ||
		len(evaluation.Rules[0].MissingInputs) != 1 || evaluation.Rules[0].MissingInputs[0] != "src_port" {
		t.Fatalf("unknown condition should keep the conjunction indeterminate: %#v", evaluation)
	}
}

func TestTraceRoutingHonorsCanceledContext(t *testing.T) {
	matcher, rules := newRoutingTraceMatcher(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := matcher.TraceRouting(ctx, RoutingTraceInput{}, rules, "direct"); err != context.Canceled {
		t.Fatalf("TraceRouting error = %v, want context.Canceled", err)
	}
}

func addrPointer(value netip.Addr) *netip.Addr {
	return &value
}
