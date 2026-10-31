/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"strconv"

	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
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

// snapshotConfiguredRules renders the rules exactly as the operator wrote them.
//
// It must be handed the parsed configuration, never the optimized program: the
// optimizers expand geosite/geoip data into hundreds of thousands of parameters
// and rewrite selector names, so exporting the evaluation order produced an
// 8.5 MB response describing rules nobody wrote. The configured form is both the
// truthful answer and orders of magnitude smaller.
func snapshotConfiguredRules(rules []*config_parser.RoutingRule, fallback config.FunctionOrString) ([]RoutingRuleSnapshot, string) {
	snapshots := make([]RoutingRuleSnapshot, 0, len(rules))
	for _, rule := range rules {
		if rule == nil {
			continue
		}
		snapshots = append(snapshots, RoutingRuleSnapshot{
			Expression: rule.String(false, false, false),
			Outbound:   rule.Outbound.MarshalString(false, true, true),
		})
	}
	parsed, err := config.ParseFunctionOrString(fallback)
	if err != nil || parsed == nil {
		return snapshots, ""
	}
	return snapshots, parsed.MarshalString(false, true, true)
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
