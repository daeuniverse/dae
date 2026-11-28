/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

// flowRuleEvidence is immutable. A flow can retain it after its matcher is drained.
type flowRuleEvidence struct {
	id         string
	generation string
	expression string
}

func flowRuleOrigins(enabled bool) (*routing.MergeAndSortRulesOptimizer, map[*config_parser.RoutingRule]int) {
	optimizer := &routing.MergeAndSortRulesOptimizer{}
	if !enabled {
		return optimizer, nil
	}
	origins := make(map[*config_parser.RoutingRule]int)
	optimizer.OnRuleGroup = func(rule *config_parser.RoutingRule, first, end int) {
		// A merged predicate has lost the identity of each contributing rule.
		if end-first == 1 {
			origins[rule] = first
		}
	}
	return optimizer, origins
}

func (m *RoutingMatcher) bindFlowRules(program *routing.NormalizedProgram, origins map[*config_parser.RoutingRule]int, configured []RoutingRuleSnapshot, fallback, generation string) {
	if origins == nil || generation == "" {
		return
	}
	last := len(m.compiledMatches) - 1
	if last < 0 || m.compiledMatches[last].matchType != consts.MatchType_Fallback {
		return
	}
	m.flowRules = make(map[int]*flowRuleEvidence, len(origins)+1)
	m.flowRules[last] = &flowRuleEvidence{TrafficFallbackRuleID, generation, "fallback: " + fallback}
	if len(m.ruleSpans) != len(program.Rules) {
		return
	}
	for i, span := range m.ruleSpans {
		index, ok := origins[program.Rules[i]]
		if !ok || index >= len(configured) || span.end <= span.start || span.end > last {
			continue
		}
		m.flowRules[span.end-1] = &flowRuleEvidence{TrafficRuleID(index), generation, configured[index].Expression}
	}
}
