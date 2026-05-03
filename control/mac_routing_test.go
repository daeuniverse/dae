/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net/netip"
	"testing"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/sirupsen/logrus"
)

func newTestControlPlaneWithMacRule(t *testing.T, literal string, not bool) *ControlPlane {
	t.Helper()

	rules := []*config_parser.RoutingRule{
		{
			AndFunctions: []*config_parser.Function{
				{
					Name: consts.Function_Mac,
					Not:  not,
					Params: []*config_parser.Param{
						{Val: literal},
					},
				},
			},
			Outbound: config_parser.Function{Name: "proxy"},
		},
	}

	builder, err := NewRoutingMatcherBuilder(
		logrus.New(),
		rules,
		map[string]uint8{
			"direct": uint8(consts.OutboundDirect),
			"proxy":  uint8(consts.OutboundUserDefinedMin),
		},
		nil,
		config.FunctionOrString("direct"),
	)
	if err != nil {
		t.Fatalf("NewRoutingMatcherBuilder(%q, not=%v): %v", literal, not, err)
	}

	matcher, err := builder.BuildUserspace()
	if err != nil {
		t.Fatalf("BuildUserspace(%q, not=%v): %v", literal, not, err)
	}

	return &ControlPlane{controlPlaneGenerationState: controlPlaneGenerationState{routingMatcher: matcher}}
}

func routeWithMac(t *testing.T, plane *ControlPlane, mac [6]uint8) (consts.OutboundIndex, uint32, bool, error) {
	t.Helper()

	src := netip.MustParseAddrPort("192.0.2.10:12345")
	dst := netip.MustParseAddrPort("198.51.100.20:443")

	return plane.Route(src, dst, "", consts.L4ProtoType_TCP, &bpfRoutingResult{Mac: mac})
}

func TestControlPlaneRoute_NegativeMacRuleSkipsZeroMac(t *testing.T) {
	plane := newTestControlPlaneWithMacRule(t, "02:42:ac:11:00:02", true)
	otherMac, err := common.ParseMac("02:42:ac:11:00:03")
	if err != nil {
		t.Fatalf("ParseMac(other): %v", err)
	}
	blockedMac, err := common.ParseMac("02:42:ac:11:00:02")
	if err != nil {
		t.Fatalf("ParseMac(blocked): %v", err)
	}

	tests := []struct {
		name         string
		mac          [6]uint8
		wantOutbound consts.OutboundIndex
	}{
		{
			name:         "zero_mac_falls_back_to_direct",
			mac:          [6]uint8{},
			wantOutbound: consts.OutboundDirect,
		},
		{
			name:         "different_mac_matches_negative_rule",
			mac:          otherMac,
			wantOutbound: consts.OutboundUserDefinedMin,
		},
		{
			name:         "listed_mac_does_not_match_negative_rule",
			mac:          blockedMac,
			wantOutbound: consts.OutboundDirect,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			outbound, _, _, err := routeWithMac(t, plane, tt.mac)
			if err != nil {
				t.Fatalf("Route(mac=%v): %v", tt.mac, err)
			}
			if outbound != tt.wantOutbound {
				t.Fatalf("Route(mac=%v) outbound = %v, want %v", tt.mac, outbound, tt.wantOutbound)
			}
		})
	}
}
