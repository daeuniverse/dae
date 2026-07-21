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
		`hk_to_us: 'vmess://endpoint -> group(HK)'`,
		`HK { policy: min filter: name(HK1) }`,
	)
	if err != nil {
		t.Fatal(err)
	}
}

func TestConfigRejectsUnknownGroupChainEntry(t *testing.T) {
	err := parseGroupChainConfig(t, `hk_to_us: 'vmess://endpoint -> group(HK)'`, "")
	if err == nil || !strings.Contains(err.Error(), `unknown group "HK"`) {
		t.Fatalf("err = %v, want unknown group", err)
	}
}

func TestConfigRejectsNestedGroupChain(t *testing.T) {
	err := parseGroupChainConfig(t,
		`bad: 'vmess://endpoint -> vmess://relay -> group(HK)'`,
		`HK { policy: min }`,
	)
	if err == nil || !strings.Contains(err.Error(), "endpoint -> group(NAME)") {
		t.Fatalf("err = %v, want group chain shape error", err)
	}
}

func TestConfigAcceptsOrdinaryThreeNodeChain(t *testing.T) {
	err := parseGroupChainConfig(t,
		`chain: 'vmess://endpoint -> tuic://relay-1 -> vless://relay-2'`,
		`HK { policy: min }`,
	)
	if err != nil {
		t.Fatal(err)
	}
}
