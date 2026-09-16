/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"io"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/sirupsen/logrus"
)

// routingProgramFunctionNames is the complete set of routing rule functions the
// shared registry must cover. It is the list the run path registers today; the
// equality assertion below fails if either path gains or loses one.
var routingProgramFunctionNames = []string{
	consts.Function_Domain,
	consts.Function_Ip,
	consts.Function_SourceIp,
	consts.Function_Port,
	consts.Function_SourcePort,
	consts.Function_L4Proto,
	consts.Function_IpVersion,
	consts.Function_Mac,
	consts.Function_ProcessName,
	consts.Function_Dscp,
}

// routingRegistryRejectsAsUnknown reports whether the builder treats the given
// function name as unregistered. Parameter values are deliberately invalid so
// both paths fail early; only the "unknown function" classification is read.
func routingRegistryRejectsAsUnknown(t *testing.T, rb *routing.RulesBuilder, name string) bool {
	t.Helper()
	rule := &config_parser.RoutingRule{
		AndFunctions: []*config_parser.Function{{
			Name:   name,
			Params: []*config_parser.Param{{Key: "dae_probe_key", Val: "dae_probe_val"}},
		}},
		Outbound: config_parser.Function{Name: "proxy"},
	}
	err := rb.Apply([]*config_parser.RoutingRule{rule})
	return err != nil && strings.Contains(err.Error(), "unknown function")
}

// TestRoutingProgramParserRegistryIsShared pins the follow-up: `dae
// validate` and `dae run` must reach the same function registry through
// control.RegisterRoutingProgramParsers, so a routing function added to the run
// path can never be silently accepted... or rather silently rejected... by the
// dry-run. The two builders are built independently and compared function by
// function through the "unknown function" oracle.
func TestRoutingProgramParserRegistryIsShared(t *testing.T) {
	log := logrus.New()
	log.SetOutput(io.Discard)

	// The run path: the matcher builder installs the registry itself while
	// lowering the program.
	runBuilder, err := NewRoutingMatcherBuilderFromProgram(log,
		&routing.NormalizedProgram{Fallback: "proxy"},
		map[string]uint8{"proxy": 0}, nil)
	if err != nil {
		t.Fatalf("build run-path matcher builder: %v", err)
	}
	runRegistry := routing.NewRulesBuilder(log)
	runBuilder.registerProgramParsers(runRegistry)

	// The validate path: the exported entry point, exactly as cmd/validate.go
	// calls it.
	validateRegistry := routing.NewRulesBuilder(log)
	RegisterRoutingProgramParsers(validateRegistry, func(string) error { return nil })

	// Positive control: the oracle really can see an unregistered function.
	if !routingRegistryRejectsAsUnknown(t, runRegistry, "dae_no_such_routing_function") ||
		!routingRegistryRejectsAsUnknown(t, validateRegistry, "dae_no_such_routing_function") {
		t.Fatal("oracle is blind: an unregistered function was not classified as unknown")
	}

	for _, name := range routingProgramFunctionNames {
		runUnknown := routingRegistryRejectsAsUnknown(t, runRegistry, name)
		validateUnknown := routingRegistryRejectsAsUnknown(t, validateRegistry, name)
		if runUnknown {
			t.Fatalf("run path does not register routing function %q", name)
		}
		if runUnknown != validateUnknown {
			t.Fatalf("registry drift for %q: run registers it=%v, validate=%v", name, !runUnknown, !validateUnknown)
		}
	}
}

// TestValidateRegistrySharesDomainKeyCheck pins that the domain key validation
// lives in the shared registry rather than in one path's sink: both paths must
// reject the same illegal key with the same error.
func TestValidateRegistrySharesDomainKeyCheck(t *testing.T) {
	log := logrus.New()
	log.SetOutput(io.Discard)

	errFor := func(rb *routing.RulesBuilder) error {
		rule := &config_parser.RoutingRule{
			AndFunctions: []*config_parser.Function{{
				Name:   consts.Function_Domain,
				Params: []*config_parser.Param{{Key: "dae_probe_key", Val: "example.com"}},
			}},
			Outbound: config_parser.Function{Name: "proxy"},
		}
		return rb.Apply([]*config_parser.RoutingRule{rule})
	}

	runBuilder, err := NewRoutingMatcherBuilderFromProgram(log,
		&routing.NormalizedProgram{Fallback: "proxy"},
		map[string]uint8{"proxy": 0}, nil)
	if err != nil {
		t.Fatalf("build run-path matcher builder: %v", err)
	}
	runRegistry := routing.NewRulesBuilder(log)
	runBuilder.registerProgramParsers(runRegistry)

	validateRegistry := routing.NewRulesBuilder(log)
	RegisterRoutingProgramParsers(validateRegistry, func(string) error { return nil })

	runErr := errFor(runRegistry)
	validateErr := errFor(validateRegistry)
	if runErr == nil || validateErr == nil {
		t.Fatalf("illegal domain key must be rejected on both paths (run=%v validate=%v)", runErr, validateErr)
	}
	if !strings.Contains(runErr.Error(), "unsupported key") || !strings.Contains(validateErr.Error(), "unsupported key") {
		t.Fatalf("unexpected domain key errors: run=%v validate=%v", runErr, validateErr)
	}
}
