/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"fmt"
	"net/netip"
	"sort"

	"github.com/daeuniverse/dae/common/consts"
)

const MaxRoutingTraceRuleSteps = 4096

type RoutingTraceInput struct {
	Network consts.L4ProtoType
	Domain  *string
	DstIP   *netip.Addr
	DstPort uint16
	SrcIP   *netip.Addr
	SrcPort *uint16
	Pname   *string
	Dscp    *uint8
}

type RoutingTraceCondition struct {
	ID            string
	Expression    *string
	Result        string
	MissingInputs []string
}

type RoutingTraceRule struct {
	RuleID        string
	Expression    *string
	Result        string
	MissingInputs []string
	Conditions    []RoutingTraceCondition
}

type RoutingTraceEvaluation struct {
	DstIP         *string
	Decision      string
	Outbound      *string
	MissingInputs []string
	Rules         []RoutingTraceRule
}

type traceConditionResult struct {
	result  string
	missing []string
}

func (m *RoutingMatcher) TraceRouting(
	ctx context.Context,
	input RoutingTraceInput,
	rules []RoutingRuleSnapshot,
	fallback string,
) (RoutingTraceEvaluation, error) {
	if m == nil {
		return RoutingTraceEvaluation{}, fmt.Errorf("routing trace matcher is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return RoutingTraceEvaluation{}, err
	}
	if len(m.ruleSpans) != len(rules) {
		return RoutingTraceEvaluation{}, fmt.Errorf(
			"routing trace rule mapping is inconsistent: matcher has %d rules, snapshot has %d",
			len(m.ruleSpans), len(rules),
		)
	}

	var sourceAddr, destAddr [16]uint8
	var sourcePort uint16
	var ipVersion consts.IpVersionType
	var domain string
	var pname [16]uint8
	var dscp uint8
	if input.SrcIP != nil {
		sourceAddr = input.SrcIP.As16()
	}
	if input.DstIP != nil {
		destAddr = input.DstIP.As16()
		if input.DstIP.Is4() || input.DstIP.Is4In6() {
			ipVersion = consts.IpVersion_4
		} else {
			ipVersion = consts.IpVersion_6
		}
	}
	if input.SrcPort != nil {
		sourcePort = *input.SrcPort
	}
	if input.Domain != nil {
		domain = *input.Domain
	}
	if input.Pname != nil {
		copy(pname[:], *input.Pname)
	}
	if input.Dscp != nil {
		dscp = *input.Dscp
	}
	facts, err := m.newFacts(
		sourceAddr, destAddr, sourcePort, input.DstPort,
		ipVersion, input.Network, domain, pname, dscp, [16]uint8{},
	)
	if err != nil {
		return RoutingTraceEvaluation{}, err
	}

	evaluation := RoutingTraceEvaluation{
		Decision:      "indeterminate",
		MissingInputs: []string{},
		Rules:         make([]RoutingTraceRule, 0, len(rules)+1),
	}
	if input.DstIP != nil {
		dstIP := input.DstIP.String()
		evaluation.DstIP = &dstIP
	}

	uncertain := map[string]struct{}{}
	stopped := false
	for index, rule := range rules {
		if err := ctx.Err(); err != nil {
			return RoutingTraceEvaluation{}, err
		}
		ruleID := fmt.Sprintf("traffic:%d", index)
		expression := rule.Expression
		outcome := RoutingTraceRule{
			RuleID:        ruleID,
			Expression:    &expression,
			Result:        "skipped",
			MissingInputs: []string{},
			Conditions:    []RoutingTraceCondition{},
		}
		if !stopped {
			span := m.ruleSpans[index]
			outcome.Result, outcome.MissingInputs, outcome.Conditions, err =
				m.evaluateTraceRule(ctx, ruleID, span, &facts, input)
			if err != nil {
				return RoutingTraceEvaluation{}, err
			}
			if outcome.Result == "indeterminate" {
				for _, missing := range outcome.MissingInputs {
					uncertain[missing] = struct{}{}
				}
			}
			if outcome.Result == "matched" {
				// must_rules only raises the must flag; the real matcher keeps
				// evaluating and takes the outbound from the next matching
				// rule, so the trace must not stop here. Use the parsed
				// outbound name: must_rules(mark:1) is still must_rules.
				if !rule.MustRules && rule.Outbound != consts.OutboundMustRules.String() {
					stopped = true
					if len(uncertain) == 0 {
						evaluation.Decision = "determinate"
						outbound := rule.Outbound
						evaluation.Outbound = &outbound
					}
				}
			}
		}
		evaluation.Rules = append(evaluation.Rules, outcome)
	}

	fallbackResult := "skipped"
	if len(uncertain) > 0 {
		evaluation.Decision = "indeterminate"
		evaluation.MissingInputs = sortedSet(uncertain)
	} else if !stopped {
		fallbackResult = "matched"
		evaluation.Decision = "determinate"
		outbound := fallback
		evaluation.Outbound = &outbound
	}
	fallbackExpression := "fallback: " + fallback
	evaluation.Rules = append(evaluation.Rules, RoutingTraceRule{
		RuleID:        "traffic:fallback",
		Expression:    &fallbackExpression,
		Result:        fallbackResult,
		MissingInputs: []string{},
		Conditions:    []RoutingTraceCondition{},
	})
	return evaluation, nil
}

func (m *RoutingMatcher) evaluateTraceRule(
	ctx context.Context,
	ruleID string,
	span routingMatcherRuleSpan,
	facts *routingMatcherFacts,
	input RoutingTraceInput,
) (string, []string, []RoutingTraceCondition, error) {
	conditions := make([]RoutingTraceCondition, 0, span.conditionTo-span.conditionFrom)
	unknown := map[string]struct{}{}
	hasNotMatched := false
	nameCount := map[string]int{}
	for _, group := range m.predicateGroups[span.conditionFrom:span.conditionTo] {
		condition, err := m.evaluateTraceCondition(ctx, group, facts, input)
		if err != nil {
			return "", nil, nil, err
		}
		nameCount[group.name]++
		id := ruleID + "/" + group.name
		if nameCount[group.name] > 1 {
			id = fmt.Sprintf("%s/%s#%d", ruleID, group.name, nameCount[group.name])
		}
		expression := group.expression
		conditions = append(conditions, RoutingTraceCondition{
			ID:            id,
			Expression:    &expression,
			Result:        condition.result,
			MissingInputs: condition.missing,
		})
		switch condition.result {
		case "not_matched":
			hasNotMatched = true
		case "indeterminate":
			for _, missing := range condition.missing {
				unknown[missing] = struct{}{}
			}
		}
	}
	if hasNotMatched {
		return "not_matched", []string{}, conditions, nil
	}
	if len(unknown) > 0 {
		return "indeterminate", sortedSet(unknown), conditions, nil
	}
	return "matched", []string{}, conditions, nil
}

func (m *RoutingMatcher) evaluateTraceCondition(
	ctx context.Context,
	group routingMatcherPredicateGroupSpan,
	facts *routingMatcherFacts,
	input RoutingTraceInput,
) (traceConditionResult, error) {
	missing := map[string]struct{}{}
	matched := false
	for index := group.start; index < group.end; index++ {
		if index&63 == 0 {
			if err := ctx.Err(); err != nil {
				return traceConditionResult{}, err
			}
		}
		match := m.compiledMatches[index]
		if name := missingTraceInput(match.matchType, input); name != "" {
			missing[name] = struct{}{}
			continue
		}
		result, err := m.matchCompiledMatch(index, match, facts)
		if err != nil {
			return traceConditionResult{}, err
		}
		if result {
			matched = true
			break
		}
	}
	if matched {
		if group.not {
			return traceConditionResult{result: "not_matched", missing: []string{}}, nil
		}
		return traceConditionResult{result: "matched", missing: []string{}}, nil
	}
	if len(missing) > 0 {
		return traceConditionResult{result: "indeterminate", missing: sortedSet(missing)}, nil
	}
	if group.not {
		return traceConditionResult{result: "matched", missing: []string{}}, nil
	}
	return traceConditionResult{result: "not_matched", missing: []string{}}, nil
}

func missingTraceInput(matchType consts.MatchType, input RoutingTraceInput) string {
	switch matchType {
	case consts.MatchType_IpSet, consts.MatchType_IpVersion:
		if input.DstIP == nil {
			return "dst_ip"
		}
	case consts.MatchType_SourceIpSet:
		if input.SrcIP == nil {
			return "src_ip"
		}
	case consts.MatchType_Mac:
		return "src_mac"
	case consts.MatchType_DomainSet:
		if input.Domain == nil {
			return "domain"
		}
	case consts.MatchType_SourcePort:
		if input.SrcPort == nil {
			return "src_port"
		}
	case consts.MatchType_ProcessName:
		if input.Pname == nil {
			return "pname"
		}
	case consts.MatchType_Dscp:
		if input.Dscp == nil {
			return "dscp"
		}
	}
	return ""
}

func sortedSet(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func (c *ControlPlane) TraceRouting(ctx context.Context, input RoutingTraceInput) (RoutingTraceEvaluation, error) {
	if c == nil || c.routingTraceMatcher == nil {
		return RoutingTraceEvaluation{}, fmt.Errorf("routing trace snapshot is unavailable")
	}
	return c.routingTraceMatcher.TraceRouting(ctx, input, c.routingRules, c.routingFallback)
}

func (c *ControlPlane) RoutingTraceAvailable() bool {
	return c != nil && c.routingTraceMatcher != nil
}
