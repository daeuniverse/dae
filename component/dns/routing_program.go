/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dns

import (
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

// NormalizedRequestRoutingProgram is the DNS request routing IR after
// optimizer application and internal-selector classification.
type NormalizedRequestRoutingProgram struct {
	routing.NormalizedProgram
	SubscriptionRules []*config_parser.RoutingRule
	NodeRules         []*config_parser.RoutingRule
	SubNodeRules      []*config_parser.RoutingRule
}

func NewNormalizedRequestRoutingProgram(
	rules []*config_parser.RoutingRule,
	fallback config.FunctionOrString,
	optimizers ...routing.RulesOptimizer,
) (*NormalizedRequestRoutingProgram, error) {
	var (
		normalizedRules []*config_parser.RoutingRule
		err             error
	)
	if len(optimizers) > 0 {
		normalizedRules, err = routing.ApplyRulesOptimizers(rules, optimizers...)
		if err != nil {
			return nil, err
		}
	} else {
		normalizedRules = routing.DeepCloneRules(rules)
	}
	dnsRules, subRules, nodeRules, subNodeRules, err := SplitRequestRules(normalizedRules)
	if err != nil {
		return nil, err
	}
	return &NormalizedRequestRoutingProgram{
		NormalizedProgram: routing.NormalizedProgram{
			Rules:    dnsRules,
			Fallback: fallback,
		},
		SubscriptionRules: subRules,
		NodeRules:         nodeRules,
		SubNodeRules:      subNodeRules,
	}, nil
}
