/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package routing

import (
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

func sniffPuntValues(fn *config_parser.Function) []string {
	vals := make([]string, 0, len(fn.Params))
	for _, p := range fn.Params {
		vals = append(vals, p.Val)
	}
	return vals
}

func sniffPuntRule(outbound string, funcs ...*config_parser.Function) *config_parser.RoutingRule {
	return &config_parser.RoutingRule{
		AndFunctions: funcs,
		Outbound:     config_parser.Function{Name: outbound},
	}
}

func sniffPuntParam(key, val string) *config_parser.Param {
	return &config_parser.Param{Key: key, Val: val}
}

func sniffPuntMac(values ...string) *config_parser.Function {
	fn := &config_parser.Function{Name: consts.Function_Mac}
	for _, v := range values {
		fn.Params = append(fn.Params, sniffPuntParam("", v))
	}
	return fn
}

func sniffPuntSip(values ...string) *config_parser.Function {
	fn := &config_parser.Function{Name: consts.Function_SourceIp}
	for _, v := range values {
		fn.Params = append(fn.Params, sniffPuntParam("", v))
	}
	return fn
}

func sniffPuntDomain(keyValues ...[2]string) *config_parser.Function {
	fn := &config_parser.Function{Name: consts.Function_Domain}
	for _, kv := range keyValues {
		fn.Params = append(fn.Params, sniffPuntParam(kv[0], kv[1]))
	}
	return fn
}

func TestInferSniffPuntInjectsBeforeDirectFallback(t *testing.T) {
	rules := []*config_parser.RoutingRule{
		sniffPuntRule("my_group", sniffPuntMac("AA:BB:CC:DD:EE:FF"), sniffPuntDomain([2]string{"geosite", "docker"}, [2]string{"suffix", "quay.io"})),
		sniffPuntRule("direct", sniffPuntMac("aa:bb:cc:dd:ee:ff")),
		sniffPuntRule("direct", sniffPuntDomain([2]string{"geosite", "cn"})),
		sniffPuntRule("my_group", sniffPuntMac("11:22:33:44:55:66")),
	}
	out, inj := InferSniffPunt(rules)
	if len(inj) != 1 {
		t.Fatalf("injections = %d, want 1", len(inj))
	}
	if inj[0].Selector != `mac("aa:bb:cc:dd:ee:ff")` {
		t.Errorf("Selector = %q", inj[0].Selector)
	}
	if inj[0].FallbackRuleIndex != 2 {
		t.Errorf("FallbackRuleIndex = %d, want 2 (1-based)", inj[0].FallbackRuleIndex)
	}
	if len(out) != len(rules)+1 {
		t.Fatalf("rules = %d, want %d", len(out), len(rules)+1)
	}
	punt := out[1]
	if len(punt.AndFunctions) != 1 || punt.AndFunctions[0].Name != consts.Function_Mac {
		t.Fatalf("injected rule = %v, want a single mac function", punt.String(true, false, false))
	}
	if got := sniffPuntValues(punt.AndFunctions[0]); len(got) != 1 || got[0] != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("injected selector values = %v, want lowercased intersection", got)
	}
	if punt.Outbound.Name != consts.OutboundControlPlaneRouting.String() {
		t.Errorf("injected outbound = %q", punt.Outbound.Name)
	}
	// Original rules keep their order around the insertion.
	wantOrder := []*config_parser.RoutingRule{rules[0], out[1], rules[1], rules[2], rules[3]}
	for i, want := range wantOrder {
		if out[i] != want {
			t.Errorf("out[%d] does not preserve original order", i)
		}
	}
}

func TestInferSniffPuntNegativeShapes(t *testing.T) {
	tests := []struct {
		name  string
		rules []*config_parser.RoutingRule
	}{
		{
			name:  "no direct fallback",
			rules: []*config_parser.RoutingRule{sniffPuntRule("my_group", sniffPuntMac("aa:bb:cc:dd:ee:ff"), sniffPuntDomain([2]string{"geosite", "docker"}))},
		},
		{
			name: "fallback before whitelist",
			rules: []*config_parser.RoutingRule{
				sniffPuntRule("direct", sniffPuntMac("aa:bb:cc:dd:ee:ff")),
				sniffPuntRule("my_group", sniffPuntMac("aa:bb:cc:dd:ee:ff"), sniffPuntDomain([2]string{"geosite", "docker"})),
			},
		},
		{
			name: "negated domain",
			rules: []*config_parser.RoutingRule{
				{AndFunctions: []*config_parser.Function{sniffPuntMac("aa:bb:cc:dd:ee:ff"), {Name: consts.Function_Domain, Not: true, Params: []*config_parser.Param{sniffPuntParam("geosite", "cn")}}}, Outbound: config_parser.Function{Name: "my_group"}},
				sniffPuntRule("direct", sniffPuntMac("aa:bb:cc:dd:ee:ff")),
			},
		},
		{
			name: "negated selector",
			rules: []*config_parser.RoutingRule{
				{AndFunctions: []*config_parser.Function{{Name: consts.Function_Mac, Not: true, Params: []*config_parser.Param{sniffPuntParam("", "aa:bb:cc:dd:ee:ff")}}, sniffPuntDomain([2]string{"geosite", "docker"})}, Outbound: config_parser.Function{Name: "my_group"}},
				sniffPuntRule("direct", sniffPuntMac("aa:bb:cc:dd:ee:ff")),
			},
		},
		{
			name: "subnet sip selector",
			rules: []*config_parser.RoutingRule{
				sniffPuntRule("my_group", sniffPuntSip("192.168.1.0/24"), sniffPuntDomain([2]string{"geosite", "docker"})),
				sniffPuntRule("direct", sniffPuntSip("192.168.1.0/24")),
			},
		},
		{
			name: "proxy fallback instead of direct",
			rules: []*config_parser.RoutingRule{
				sniffPuntRule("my_group", sniffPuntMac("aa:bb:cc:dd:ee:ff"), sniffPuntDomain([2]string{"geosite", "docker"})),
				sniffPuntRule("other_group", sniffPuntMac("aa:bb:cc:dd:ee:ff")),
			},
		},
		{
			name: "extra condition beyond selector and domain",
			rules: []*config_parser.RoutingRule{
				{AndFunctions: []*config_parser.Function{sniffPuntMac("aa:bb:cc:dd:ee:ff"), sniffPuntDomain([2]string{"geosite", "docker"}), {Name: consts.Function_Port, Params: []*config_parser.Param{sniffPuntParam("", "443")}}}, Outbound: config_parser.Function{Name: "my_group"}},
				sniffPuntRule("direct", sniffPuntMac("aa:bb:cc:dd:ee:ff")),
			},
		},
		{
			name: "disjoint selectors",
			rules: []*config_parser.RoutingRule{
				sniffPuntRule("my_group", sniffPuntMac("aa:bb:cc:dd:ee:ff"), sniffPuntDomain([2]string{"geosite", "docker"})),
				sniffPuntRule("direct", sniffPuntMac("11:22:33:44:55:66")),
			},
		},
		{
			name: "whitelist outbound is direct",
			rules: []*config_parser.RoutingRule{
				sniffPuntRule("direct", sniffPuntMac("aa:bb:cc:dd:ee:ff"), sniffPuntDomain([2]string{"geosite", "docker"})),
				sniffPuntRule("direct", sniffPuntMac("aa:bb:cc:dd:ee:ff")),
			},
		},
		{
			name: "domain-only rule without selector",
			rules: []*config_parser.RoutingRule{
				sniffPuntRule("my_group", sniffPuntDomain([2]string{"geosite", "docker"})),
				sniffPuntRule("direct", sniffPuntMac("aa:bb:cc:dd:ee:ff")),
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			out, inj := InferSniffPunt(test.rules)
			if len(inj) != 0 {
				t.Fatalf("injections = %v, want none", inj)
			}
			if len(out) != len(test.rules) {
				t.Fatalf("rules = %d, want unchanged %d", len(out), len(test.rules))
			}
		})
	}
}

func TestInferSniffPuntBlockFallbackAndSip(t *testing.T) {
	rules := []*config_parser.RoutingRule{
		sniffPuntRule("my_group", sniffPuntSip("192.168.1.5"), sniffPuntDomain([2]string{"suffix", "example.com"})),
		sniffPuntRule("block", sniffPuntSip("192.168.1.5/32")),
	}
	out, inj := InferSniffPunt(rules)
	if len(inj) != 1 {
		t.Fatalf("injections = %d, want 1", len(inj))
	}
	got := sniffPuntValues(out[1].AndFunctions[0])
	if len(got) != 1 || got[0] != "192.168.1.5" {
		t.Errorf("injected sip values = %v, want bare host form of the /32 intersection", got)
	}
}

func TestInferSniffPuntDeduplicatesSharedSelector(t *testing.T) {
	whitelist := func() *config_parser.RoutingRule {
		return sniffPuntRule("my_group", sniffPuntMac("aa:bb:cc:dd:ee:ff"), sniffPuntDomain([2]string{"geosite", "docker"}))
	}
	rules := []*config_parser.RoutingRule{
		whitelist(),
		sniffPuntRule("direct", sniffPuntMac("aa:bb:cc:dd:ee:ff")),
		whitelist(),
	}
	out, inj := InferSniffPunt(rules)
	if len(inj) != 1 {
		t.Fatalf("injections = %d, want 1 deduplicated punt", len(inj))
	}
	if len(out) != 4 {
		t.Fatalf("rules = %d, want 4", len(out))
	}
}
