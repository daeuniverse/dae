/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/sirupsen/logrus"
)

// buildSniffPuntMatcher runs the real injection pass over the whitelist+
// fallback shape and lowers the result through the production builder, so the
// test exercises the exact dual projection (kernel + userspace) that reload
// would produce.
func buildSniffPuntMatcher(t *testing.T) *RoutingMatcher {
	t.Helper()
	params := func(keyValues ...[2]string) []*config_parser.Param {
		out := make([]*config_parser.Param, 0, len(keyValues))
		for _, kv := range keyValues {
			out = append(out, &config_parser.Param{Key: kv[0], Val: kv[1]})
		}
		return out
	}
	rules := []*config_parser.RoutingRule{
		{
			AndFunctions: []*config_parser.Function{
				{Name: consts.Function_Mac, Params: params([2]string{"", "AA:BB:CC:DD:EE:FF"})},
				{Name: consts.Function_Domain, Params: params([2]string{"suffix", "example.com"})},
			},
			Outbound: config_parser.Function{Name: "proxy"},
		},
		{
			AndFunctions: []*config_parser.Function{
				{Name: consts.Function_Mac, Params: params([2]string{"", "aa:bb:cc:dd:ee:ff"})},
			},
			Outbound: config_parser.Function{Name: "direct"},
		},
	}
	rules, injections := routing.InferSniffPunt(rules)
	if len(injections) != 1 {
		t.Fatalf("InferSniffPunt injections = %d, want 1", len(injections))
	}
	program, err := routing.NewNormalizedProgram(rules, config.FunctionOrString("block"))
	if err != nil {
		t.Fatalf("NewNormalizedProgram: %v", err)
	}
	builder, err := NewRoutingMatcherBuilderFromProgram(
		logrus.New(),
		program,
		map[string]uint8{
			"direct": uint8(consts.OutboundDirect),
			"block":  uint8(consts.OutboundBlock),
			"proxy":  uint8(consts.OutboundUserDefinedMin),
		},
		nil,
	)
	if err != nil {
		t.Fatalf("NewRoutingMatcherBuilderFromProgram: %v", err)
	}
	// Kernel-space projection must carry the punt line (4 match sets:
	// whitelist subrules, punt, direct fallback line, built-in fallback).
	snapshot := builder.KernspaceSnapshot()
	if len(snapshot.rules) != 5 {
		t.Fatalf("kernel-space match sets = %d, want 5", len(snapshot.rules))
	}
	if got := snapshot.rules[2].Outbound; got != uint8(consts.OutboundControlPlaneRouting) {
		t.Fatalf("kernel-space match set #2 outbound = %d, want control-plane punt (%d)",
			got, consts.OutboundControlPlaneRouting)
	}
	matcher, err := builder.BuildUserspace()
	if err != nil {
		t.Fatalf("BuildUserspace: %v", err)
	}
	return matcher
}

func TestSniffPuntUserspaceProjectionIsTransparent(t *testing.T) {
	matcher := buildSniffPuntMatcher(t)

	var deviceMac, otherMac [16]uint8
	copy(deviceMac[10:], []uint8{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF})
	copy(otherMac[10:], []uint8{0x11, 0x22, 0x33, 0x44, 0x55, 0x66})

	tests := []struct {
		name   string
		mac    [16]uint8
		domain string
		want   consts.OutboundIndex
	}{
		{
			name:   "whitelisted device hits whitelist via sniffed domain",
			mac:    deviceMac,
			domain: "www.example.com",
			want:   consts.OutboundUserDefinedMin,
		},
		{
			name:   "whitelisted device without domain knowledge lands on direct, not the punt outbound",
			mac:    deviceMac,
			domain: "",
			want:   consts.OutboundDirect,
		},
		{
			name:   "whitelisted device on non-whitelisted domain lands on direct",
			mac:    deviceMac,
			domain: "other.org",
			want:   consts.OutboundDirect,
		},
		{
			name:   "other devices are not whitelisted",
			mac:    otherMac,
			domain: "www.example.com",
			want:   consts.OutboundBlock,
		},
		{
			name:   "other devices without domain hit the fallback",
			mac:    otherMac,
			domain: "",
			want:   consts.OutboundBlock,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			outbound, _, _, err := matcher.Match(
				[16]uint8{}, [16]uint8{}, 0, 443,
				consts.IpVersion_4, consts.L4ProtoType_TCP,
				test.domain, [16]uint8{}, 0, test.mac,
			)
			if err != nil {
				t.Fatalf("Match(domain=%q): %v", test.domain, err)
			}
			if outbound != test.want {
				t.Fatalf("Match(domain=%q) outbound = %v, want %v", test.domain, outbound, test.want)
			}
		})
	}
}
