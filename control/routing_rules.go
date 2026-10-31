/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"strconv"

	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/config"
)

// RoutingRuleSnapshot is one rendered rule of a running routing generation.
type RoutingRuleSnapshot struct {
	Expression string
	Outbound   string
	Must       bool
}

// RoutingRulesSnapshot is the complete rule dictionary of one generation.
type RoutingRulesSnapshot struct {
	GenerationID     string
	Rules            []RoutingRuleSnapshot
	FallbackOutbound string
}

// snapshotRoutingProgram renders the optimized evaluation order so the API can
// export it without retaining the mutable rule tree.
func snapshotRoutingProgram(program *routing.NormalizedProgram) ([]RoutingRuleSnapshot, string) {
	if program == nil {
		return nil, ""
	}
	rules := make([]RoutingRuleSnapshot, 0, len(program.Rules))
	for _, rule := range program.Rules {
		if rule == nil {
			continue
		}
		// DisplayString, not String: the shipped rule tree is geosite-expanded,
		// so the lossless form turns a single config line into thousands of
		// suffixes. That made /api/v1/rules an 8.5 MB response the dashboard had
		// to download and parse before it could render anything.
		rules = append(rules, RoutingRuleSnapshot{
			Expression: rule.DisplayString(false, false),
			Outbound:   rule.Outbound.MarshalString(false, true, true),
		})
	}
	fallback, err := config.ParseFunctionOrString(program.Fallback)
	if err != nil || fallback == nil {
		return rules, ""
	}
	return rules, fallback.MarshalString(false, true, true)
}

func routingGenerationID(epoch routing.PolicyEpoch) string {
	return strconv.FormatUint(uint64(epoch), 10)
}

// SnapshotRoutingRules projects this generation's routing dictionary.
func (c *ControlPlane) SnapshotRoutingRules() RoutingRulesSnapshot {
	if c == nil {
		return RoutingRulesSnapshot{}
	}
	return RoutingRulesSnapshot{
		GenerationID:     c.routingGeneration,
		Rules:            append([]RoutingRuleSnapshot(nil), c.routingRules...),
		FallbackOutbound: c.routingFallback,
	}
}

// RoutingRuleExpressionByIndex returns the display expression for a rule index
// of this generation, for flow evidence.
func (c *ControlPlane) RoutingRuleExpressionByIndex(index int) (string, bool) {
	if c == nil || index < 0 || index >= len(c.routingRules) {
		return "", false
	}
	return c.routingRules[index].Expression, true
}
