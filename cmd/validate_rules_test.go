/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"strings"
	"testing"

	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

// TestValidateRoutingRulesRejectsIllegalRules is a regression guard: `dae
// validate` used to accept any config that parsed, so an illegal rule set (a
// rule the daemon refuses at startup) exited 0. It now dry-runs the run-time
// rule validation chain.
func TestValidateRoutingRulesRejectsIllegalRules(t *testing.T) {
	parse := func(t *testing.T, src string) *config.Config {
		t.Helper()
		sections, err := config_parser.Parse(src)
		require.NoError(t, err)
		conf, err := config.New(sections)
		require.NoError(t, err)
		return conf
	}

	t.Run("unknown function", func(t *testing.T) {
		conf := parse(t, `
global {}
routing {
  domainx(suffix: a.com) -> direct
}
`)
		err := validateRoutingRules(logrus.New(), conf, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unknown function")
	})

	t.Run("unsupported domain key", func(t *testing.T) {
		conf := parse(t, `
global {}
routing {
  domain(bogus: a.com) -> direct
}
`)
		err := validateRoutingRules(logrus.New(), conf, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported key")
	})

	t.Run("malformed cidr", func(t *testing.T) {
		conf := parse(t, `
global {}
routing {
  ip(1.2.3.4/999) -> direct
}
`)
		err := validateRoutingRules(logrus.New(), conf, nil)
		require.Error(t, err)
	})

	t.Run("unknown outbound group", func(t *testing.T) {
		conf := parse(t, `
global {}
routing {
  domain(suffix: a.com) -> missing_group
}
`)
		err := validateRoutingRules(logrus.New(), conf, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "not found")
	})

	t.Run("unknown fallback outbound param", func(t *testing.T) {
		conf := parse(t, `
global {}
routing {
  fallback: direct(bogus: 1)
}
`)
		err := validateRoutingRules(logrus.New(), conf, nil)
		require.Error(t, err)
	})

	t.Run("valid config passes", func(t *testing.T) {
		conf := parse(t, `
global {}
group {
  proxy {
    policy: fixed(0)
    filter: name(keyword: hk)
  }
}
node {
  "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ@127.0.0.1:8388"
}
routing {
  domain(suffix: a.com) -> proxy
  pname(curl) -> direct
  fallback: direct
}
`)
		require.NoError(t, validateRoutingRules(logrus.New(), conf, nil))
	})
}

// TestValidateRoutingRulesRejectsNamedParametersOnValueOnlyFunctions is the
// validate-path half of the empty-key contract: `dae validate` dry-runs the
// same rule lowering as `dae run`, and the functions whose operands are bare
// values must reject a named parameter there too. Before the fix these configs
// exited 0 while `port(bogus_param: 443)` built the same match set as
// `port(443)` - a typo became a different, effective rule.
func TestValidateRoutingRulesRejectsNamedParametersOnValueOnlyFunctions(t *testing.T) {
	parse := func(t *testing.T, rules string) *config.Config {
		t.Helper()
		sections, err := config_parser.Parse("global {}\nrouting {\n" + rules + "\n  fallback: direct\n}\n")
		require.NoError(t, err)
		conf, err := config.New(sections)
		require.NoError(t, err)
		return conf
	}

	bogusRules := map[string]string{
		"pname":     "pname(bogus_param: 1) -> direct",
		"port":      "port(bogus_param: 443) -> direct",
		"sport":     "sport(bogus_param: 443) -> direct",
		"dport":     "dport(bogus_param: 443) -> direct",
		"dscp":      "dscp(bogus_param: 1) -> direct",
		"ip":        "ip(bogus_param: 1.2.3.4) -> direct",
		"dip":       "dip(bogus_param: 1.2.3.4) -> direct",
		"sip":       "sip(bogus_param: 1.2.3.4) -> direct",
		"ipversion": "ipversion(bogus_param: 4) -> direct",
		"l4proto":   "l4proto(bogus_param: tcp) -> direct",
		"mac":       "mac(bogus_param: 'aa:bb:cc:dd:ee:ff') -> direct",
	}
	for name, rule := range bogusRules {
		t.Run(name, func(t *testing.T) {
			err := validateRoutingRules(logrus.New(), parse(t, rule), nil)
			require.Error(t, err)
			require.Contains(t, err.Error(), "unsupported parameter key")
			require.Contains(t, err.Error(), `"bogus_param"`)
			require.Contains(t, err.Error(), "<value>")
		})
	}

	// The documented short form keeps working on the same path.
	bareRules := map[string]string{
		"pname":     "pname(NetworkManager) -> direct",
		"port":      "port(443) -> direct",
		"sport":     "sport(443) -> direct",
		"dport":     "dport(443) -> direct",
		"dscp":      "dscp(0x4) -> direct",
		"ip":        "ip(1.2.3.4) -> direct",
		"dip":       "dip(224.0.0.0/3, 'ff00::/8') -> direct",
		"sip":       "sip(1.2.3.4) -> direct",
		"ipversion": "ipversion(4) -> direct",
		"l4proto":   "l4proto(tcp) -> direct",
		"mac":       "mac('aa:bb:cc:dd:ee:ff') -> direct",
	}
	for name, rule := range bareRules {
		t.Run(name+"/bare", func(t *testing.T) {
			require.NoError(t, validateRoutingRules(logrus.New(), parse(t, rule), nil))
		})
	}
}

// TestValidateRoutingRulesUsesConfigGroups pins that the dry-run resolves rule
// outbounds against the configured groups (like the matcher builder), not
// against node names or an empty namespace.
func TestValidateRoutingRulesUsesConfigGroups(t *testing.T) {
	sections, err := config_parser.Parse(`
global {}
group {
  proxy {
    policy: fixed(0)
    filter: name(keyword: hk)
  }
}
routing {
  domain(suffix: a.com) -> proxy
  fallback: direct
}
`)
	require.NoError(t, err)
	conf, err := config.New(sections)
	require.NoError(t, err)
	require.NoError(t, validateRoutingRules(logrus.New(), conf, nil))
	// A node-only name is not an outbound: the matcher builder resolves rule
	// outbounds against groups, so it must be rejected.
	sections, err = config_parser.Parse(`
global {}
node {
  "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ@127.0.0.1:8388"
}
routing {
  domain(suffix: a.com) -> some_tag
  fallback: direct
}
`)
	require.NoError(t, err)
	confWithNode, err := config.New(sections)
	require.NoError(t, err)
	err = validateRoutingRules(logrus.New(), confWithNode, nil)
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "some_tag"), err)
}
