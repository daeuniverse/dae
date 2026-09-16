/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"io"
	"testing"

	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/sirupsen/logrus"
)

// Audit regression at the CLI seam: a routing rule with an unsupported operand
// used to pass `dae validate` and then compile into a never-matching rule.
func TestValidateRoutingRulesRejectsUnknownOperands(t *testing.T) {
	log := logrus.New()
	log.SetOutput(io.Discard)

	parse := func(rule string) (*config.Config, error) {
		sections, err := config_parser.Parse("global {\n    tproxy_port: 12345\n}\nrouting {\n" + rule + "\n}\n")
		if err != nil {
			return nil, err
		}
		return config.New(sections)
	}

	for _, rule := range []string{
		"l4proto(icmp) -> block",
		"ipversion(ipv6) -> block",
	} {
		conf, err := parse(rule)
		if err != nil {
			t.Fatalf("parse %q: %v", rule, err)
		}
		err = validateRoutingRules(log, conf, nil)
		if err == nil {
			t.Errorf("validate accepted %q; it must be reported as an invalid rule", rule)
			continue
		}
		t.Logf("%q rejected by validate: %v", rule, err)
	}

	// Positive control: a supported rule still validates.
	conf, err := parse("l4proto(tcp) && ipversion(4) -> block")
	if err != nil {
		t.Fatalf("parse supported rule: %v", err)
	}
	if err := validateRoutingRules(log, conf, nil); err != nil {
		t.Errorf("supported rule must validate, got %v", err)
	}
}
