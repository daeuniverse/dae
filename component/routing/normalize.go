/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package routing

import (
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/sirupsen/logrus"
)

func NewNormalizedProgram(
	rules []*config_parser.RoutingRule,
	fallback config.FunctionOrString,
	optimizers ...RulesOptimizer,
) (*NormalizedProgram, error) {
	var (
		normalized []*config_parser.RoutingRule
		err        error
	)
	if len(optimizers) > 0 {
		normalized, err = ApplyRulesOptimizers(rules, optimizers...)
		if err != nil {
			return nil, err
		}
	} else {
		normalized = DeepCloneRules(rules)
	}
	return &NormalizedProgram{
		Rules:    normalized,
		Fallback: fallback,
	}, nil
}

func (p *NormalizedProgram) Lower(
	log *logrus.Logger,
	registerParsers func(*RulesBuilder),
	addFallback func(config.FunctionOrString) error,
) error {
	if p == nil {
		return nil
	}
	builder := NewRulesBuilder(log)
	if registerParsers != nil {
		registerParsers(builder)
	}
	if err := builder.Apply(p.Rules); err != nil {
		return err
	}
	if addFallback != nil {
		return addFallback(p.Fallback)
	}
	return nil
}
