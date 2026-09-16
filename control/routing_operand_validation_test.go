/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"io"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/sirupsen/logrus"
)

// Audit regression: l4proto()/ipversion() used to ignore unrecognised operands
// and compile the rule with a zero match mask, which matches no packet at all.
// The rule then silently disappeared from the routing program while
// `dae validate` reported success.
func TestRoutingRuleRejectsUnknownL4ProtoAndIPVersion(t *testing.T) {
	log := logrus.New()
	log.SetOutput(io.Discard)

	validateRegistry := routing.NewRulesBuilder(log)
	RegisterRoutingProgramParsers(validateRegistry, func(string) error { return nil })

	apply := func(name, value string) error {
		rule := &config_parser.RoutingRule{
			AndFunctions: []*config_parser.Function{{
				Name:   name,
				Params: []*config_parser.Param{{Val: value}},
			}},
			Outbound: config_parser.Function{Name: "proxy"},
		}
		return validateRegistry.Apply([]*config_parser.RoutingRule{rule})
	}

	for _, tc := range []struct{ name, value string }{
		{consts.Function_L4Proto, "icmp"},
		{consts.Function_L4Proto, "tcp6"},
		{consts.Function_IpVersion, "ipv6"},
		{consts.Function_IpVersion, "4,6"},
	} {
		if err := apply(tc.name, tc.value); err == nil {
			t.Errorf("%v(%v) was accepted; an unknown operand must be rejected instead of compiling a never-matching rule", tc.name, tc.value)
		} else {
			t.Logf("%v(%v) rejected: %v", tc.name, tc.value, err)
		}
	}

	// Positive control: the supported spellings must keep working.
	for _, tc := range []struct{ name, value string }{
		{consts.Function_L4Proto, "tcp"},
		{consts.Function_L4Proto, "udp"},
		{consts.Function_IpVersion, "4"},
		{consts.Function_IpVersion, "6"},
	} {
		if err := apply(tc.name, tc.value); err != nil {
			t.Errorf("positive control: %v(%v) must be accepted, got %v", tc.name, tc.value, err)
		}
	}
}
