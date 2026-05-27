/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package routing

import (
	stderrors "errors"
	"testing"

	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/sirupsen/logrus"
)

func TestNewNormalizedProgramClonesRulesWithoutOptimizers(t *testing.T) {
	orig := []*config_parser.RoutingRule{
		{
			AndFunctions: []*config_parser.Function{{Name: "domain"}},
		},
	}

	program, err := NewNormalizedProgram(orig, "direct")
	if err != nil {
		t.Fatalf("NewNormalizedProgram() error = %v", err)
	}
	if len(program.Rules) != 1 {
		t.Fatalf("len(program.Rules) = %d, want 1", len(program.Rules))
	}
	program.Rules[0].AndFunctions[0].Name = "mutated"
	if got := orig[0].AndFunctions[0].Name; got != "domain" {
		t.Fatalf("source rules mutated, got %q", got)
	}
}

func TestNormalizedProgramLowerHandlesEmptyRulesAndFallback(t *testing.T) {
	program, err := NewNormalizedProgram(nil, config.FunctionOrString("direct"))
	if err != nil {
		t.Fatalf("NewNormalizedProgram() error = %v", err)
	}

	var fallback string
	err = program.Lower(logrus.New(), nil, func(fs config.FunctionOrString) error {
		fn, err := config.ParseFunctionOrString(fs)
		if err != nil {
			return err
		}
		fallback = fn.Name
		return nil
	})
	if err != nil {
		t.Fatalf("Lower() error = %v", err)
	}
	if fallback != "direct" {
		t.Fatalf("fallback = %q, want %q", fallback, "direct")
	}
}

func TestNormalizedProgramLowerReturnsApplyErrorWhenParserMissing(t *testing.T) {
	program, err := NewNormalizedProgram([]*config_parser.RoutingRule{
		{
			AndFunctions: []*config_parser.Function{{
				Name: "domain",
				Params: []*config_parser.Param{{
					Key: "suffix",
					Val: "example.com",
				}},
			}},
		},
	}, config.FunctionOrString("direct"))
	if err != nil {
		t.Fatalf("NewNormalizedProgram() error = %v", err)
	}

	err = program.Lower(logrus.New(), nil, nil)
	if err == nil {
		t.Fatal("Lower() error = nil, want parser error")
	}
}

func TestNormalizedProgramLowerPropagatesFallbackError(t *testing.T) {
	program, err := NewNormalizedProgram(nil, config.FunctionOrString(123))
	if err != nil {
		t.Fatalf("NewNormalizedProgram() error = %v", err)
	}

	wantErr := stderrors.New("fallback failed")
	err = program.Lower(logrus.New(), nil, func(fs config.FunctionOrString) error {
		if _, parseErr := config.ParseFunctionOrString(fs); parseErr == nil {
			t.Fatal("ParseFunctionOrString() error = nil, want invalid fallback")
		}
		return wantErr
	})
	if !stderrors.Is(err, wantErr) {
		t.Fatalf("Lower() error = %v, want %v", err, wantErr)
	}
}

func TestNormalizedProgramLowerRunsRegisteredParsersAndFallback(t *testing.T) {
	program, err := NewNormalizedProgram([]*config_parser.RoutingRule{
		{
			AndFunctions: []*config_parser.Function{{
				Name: "domain",
				Params: []*config_parser.Param{{
					Key: "suffix",
					Val: "example.com",
				}},
			}},
		},
	}, config.FunctionOrString("direct"))
	if err != nil {
		t.Fatalf("NewNormalizedProgram() error = %v", err)
	}

	var (
		parsed   bool
		fallback string
	)
	err = program.Lower(logrus.New(), func(builder *RulesBuilder) {
		builder.RegisterFunctionParser("domain", func(_ *logrus.Logger, _ *config_parser.Function, _ string, _ []string, _ *Outbound) error {
			parsed = true
			return nil
		})
	}, func(fs config.FunctionOrString) error {
		fn, err := config.ParseFunctionOrString(fs)
		if err != nil {
			return err
		}
		fallback = fn.Name
		return nil
	})
	if err != nil {
		t.Fatalf("Lower() error = %v", err)
	}
	if !parsed {
		t.Fatal("expected rules to be lowered through registered parsers")
	}
	if fallback != "direct" {
		t.Fatalf("fallback = %q, want %q", fallback, "direct")
	}
}
