/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net/netip"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/sirupsen/logrus"
)

func newTestControlPlaneWithDscpRule(t *testing.T, literal string) *ControlPlane {
	t.Helper()

	rules := []*config_parser.RoutingRule{
		{
			AndFunctions: []*config_parser.Function{
				{
					Name: consts.Function_Dscp,
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
		t.Fatalf("NewRoutingMatcherBuilder(%q): %v", literal, err)
	}

	matcher, err := builder.BuildUserspace()
	if err != nil {
		t.Fatalf("BuildUserspace(%q): %v", literal, err)
	}

	return &ControlPlane{controlPlaneGenerationState: controlPlaneGenerationState{routingMatcher: matcher}}
}

func routeWithDscp(t *testing.T, plane *ControlPlane, dscp uint8, l4proto consts.L4ProtoType) (consts.OutboundIndex, uint32, bool, error) {
	t.Helper()

	src := netip.MustParseAddrPort("192.0.2.10:12345")
	dst := netip.MustParseAddrPort("198.51.100.20:443")

	return plane.Route(src, dst, "", l4proto, &bpfRoutingResult{Dscp: dscp})
}

func TestControlPlaneRoute_DscpDecimalLiteralMatchesUserspaceFallback(t *testing.T) {
	plane := newTestControlPlaneWithDscpRule(t, "10")

	for _, proto := range []consts.L4ProtoType{consts.L4ProtoType_TCP, consts.L4ProtoType_UDP} {
		outbound, _, _, err := routeWithDscp(t, plane, 10, proto)
		if err != nil {
			t.Fatalf("Route(dscp=10, proto=%v): %v", proto, err)
		}
		if outbound != consts.OutboundUserDefinedMin {
			t.Fatalf("Route(dscp=10, proto=%v) outbound = %v, want %v", proto, outbound, consts.OutboundUserDefinedMin)
		}
	}
}

func TestControlPlaneRoute_DscpHexLiteralUsesExactDscpValue(t *testing.T) {
	plane := newTestControlPlaneWithDscpRule(t, "0x28")

	tests := []struct {
		name         string
		dscp         uint8
		wantOutbound consts.OutboundIndex
	}{
		{
			name:         "reported_dscp_10_does_not_match_hex_tos_literal",
			dscp:         10,
			wantOutbound: consts.OutboundDirect,
		},
		{
			name:         "hex_literal_matches_dscp_40",
			dscp:         0x28,
			wantOutbound: consts.OutboundUserDefinedMin,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			outbound, _, _, err := routeWithDscp(t, plane, tt.dscp, consts.L4ProtoType_TCP)
			if err != nil {
				t.Fatalf("Route(dscp=%d): %v", tt.dscp, err)
			}
			if outbound != tt.wantOutbound {
				t.Fatalf("Route(dscp=%d) outbound = %v, want %v", tt.dscp, outbound, tt.wantOutbound)
			}
		})
	}
}

func TestNewRoutingMatcherBuilder_DscpKeepsLegacyLiteralCompatibility(t *testing.T) {
	tests := []string{"64", "0xb8", "255"}

	for _, literal := range tests {
		t.Run(literal, func(t *testing.T) {
			rules := []*config_parser.RoutingRule{
				{
					AndFunctions: []*config_parser.Function{
						{
							Name: consts.Function_Dscp,
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
				t.Fatalf("NewRoutingMatcherBuilder(%q): %v", literal, err)
			}

			if _, err := builder.BuildUserspace(); err != nil {
				t.Fatalf("BuildUserspace(%q): %v", literal, err)
			}
		})
	}
}
