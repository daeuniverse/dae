/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package config

import (
	"strings"
	"testing"

	"github.com/daeuniverse/dae/pkg/config_parser"
)

func parseGroupChainConfig(t *testing.T, node, groups string) error {
	t.Helper()
	sections, err := config_parser.Parse(`
global {}
node {
  ` + node + `
}
group {
  ` + groups + `
}
routing { fallback: direct }
`)
	if err != nil {
		return err
	}
	_, err = New(sections)
	return err
}

func TestConfigAcceptsGroupChain(t *testing.T) {
	err := parseGroupChainConfig(t,
		`hk_to_us: 'group(HK) -> vmess://exit'`,
		`HK { policy: min filter: name(HK1) }`,
	)
	if err != nil {
		t.Fatal(err)
	}
}

func TestConfigRejectsUnknownGroupChainEntry(t *testing.T) {
	err := parseGroupChainConfig(t, `hk_to_us: 'group(HK) -> vmess://exit'`, "")
	if err == nil || !strings.Contains(err.Error(), `unknown group "HK"`) {
		t.Fatalf("err = %v, want unknown group", err)
	}
}

func TestConfigRejectsNestedGroupChain(t *testing.T) {
	err := parseGroupChainConfig(t,
		`bad: 'group(HK) -> vmess://middle -> vmess://exit'`,
		`HK { policy: min }`,
	)
	if err == nil || !strings.Contains(err.Error(), "exactly two nodes") {
		t.Fatalf("err = %v, want group chain shape error", err)
	}
}

func TestConfigRejectsThreeNodeChain(t *testing.T) {
	err := parseGroupChainConfig(t,
		`bad: 'tuic://entry -> vmess://middle -> vless://exit'`,
		`HK { policy: min }`,
	)
	if err == nil || !strings.Contains(err.Error(), "exactly two nodes") {
		t.Fatalf("err = %v, want two-node chain error", err)
	}
}
