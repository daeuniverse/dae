/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

func newTestControlPlaneWithSingleMetadataRule(t *testing.T, functionName, literal string) *ControlPlane {
	t.Helper()

	rules := []*config_parser.RoutingRule{
		{
			AndFunctions: []*config_parser.Function{
				{
					Name: functionName,
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
		t.Fatalf("NewRoutingMatcherBuilder(%q=%q): %v", functionName, literal, err)
	}

	matcher, err := builder.BuildUserspace()
	if err != nil {
		t.Fatalf("BuildUserspace(%q=%q): %v", functionName, literal, err)
	}

	return &ControlPlane{controlPlaneGenerationState: controlPlaneGenerationState{routingMatcher: matcher}}
}

func retrieveRoutingResultForMetadataRuleTest(t *testing.T, l4proto uint8, dscp uint8, mac [6]uint8, pname string) (*bpfRoutingResult, netip.AddrPort, netip.AddrPort) {
	t.Helper()

	src := common.ConvergeAddrPort(netip.MustParseAddrPort("192.0.2.10:12345"))
	dst := common.ConvergeAddrPort(netip.MustParseAddrPort("198.51.100.20:443"))
	key := tuplesKeyFromAddrPorts(src, dst, l4proto)

	var core *controlPlaneCore
	switch l4proto {
	case unix.IPPROTO_TCP:
		tcpMap := newJanitorTestMap(t, "conn_state_map")
		state := bpfConnState{}
		state.LastSeenNs = 1
		state.Meta.Data.Outbound = uint8(consts.OutboundDirect)
		state.Meta.Data.Dscp = dscp
		state.Meta.Data.HasRouting = 1
		state.Pid = 1234
		state.Mac = mac
		copy(state.Pname[:], pname)
		if err := tcpMap.Update(key, &state, ebpf.UpdateAny); err != nil {
			t.Fatalf("update tcp conn-state: %v", err)
		}
		core = &controlPlaneCore{
			bpf: &bpfObjects{bpfMaps: bpfMaps{ConnStateMap: tcpMap}},
		}
	case unix.IPPROTO_UDP:
		udpMap := newJanitorTestMap(t, "conn_state_map")
		state := bpfConnState{}
		state.LastSeenNs = 1
		state.Meta.Data.Outbound = uint8(consts.OutboundDirect)
		state.Meta.Data.Dscp = dscp
		state.Meta.Data.HasRouting = 1
		state.Pid = 1234
		state.Mac = mac
		copy(state.Pname[:], pname)
		if err := udpMap.Update(key, &state, ebpf.UpdateAny); err != nil {
			t.Fatalf("update udp conn-state: %v", err)
		}
		core = &controlPlaneCore{
			bpf: &bpfObjects{bpfMaps: bpfMaps{ConnStateMap: udpMap}},
		}
	default:
		t.Fatalf("unsupported l4proto %d", l4proto)
	}

	rr, err := core.RetrieveRoutingResult(src, dst, l4proto)
	if err != nil {
		t.Fatalf("RetrieveRoutingResult(%d): %v", l4proto, err)
	}
	return rr, src, dst
}

func retrieveRoutingHandoffResultForMetadataRuleTest(t *testing.T, l4proto uint8, dscp uint8, mac [6]uint8, pname string) (*bpfRoutingResult, netip.AddrPort, netip.AddrPort) {
	t.Helper()

	src := common.ConvergeAddrPort(netip.MustParseAddrPort("192.0.2.10:12345"))
	dst := common.ConvergeAddrPort(netip.MustParseAddrPort("198.51.100.20:443"))
	key := tuplesKeyFromAddrPorts(src, dst, l4proto)
	now := monotonicNowNs(t)

	handoffMap := newJanitorTestMap(t, "routing_handoff_map")
	var pnameBuf [16]uint8
	copy(pnameBuf[:], pname)
	entry := newRoutingHandoffEntryForTest(now, bpfRoutingResult{
		Outbound: uint8(consts.OutboundDirect),
		Dscp:     dscp,
		Pid:      1234,
		Mac:      mac,
		Pname:    pnameBuf,
	})
	if err := handoffMap.Update(key, &entry, ebpf.UpdateAny); err != nil {
		t.Fatalf("update routing_handoff_map: %v", err)
	}

	core := &controlPlaneCore{
		bpf: &bpfObjects{bpfMaps: bpfMaps{RoutingHandoffMap: handoffMap}},
	}

	rr, err := core.RetrieveRoutingResult(src, dst, l4proto)
	if err != nil {
		t.Fatalf("RetrieveRoutingResult handoff(%d): %v", l4proto, err)
	}
	return rr, src, dst
}

func TestRetrievedRoutingResultStillMatchesMetadataSensitiveRules(t *testing.T) {
	matchMac, err := common.ParseMac("02:42:ac:11:00:02")
	if err != nil {
		t.Fatalf("ParseMac(matchMac): %v", err)
	}

	tests := []struct {
		name         string
		l4proto      uint8
		source       string
		functionName string
		literal      string
		dscp         uint8
		mac          [6]uint8
		pname        string
	}{
		{
			name:         "tcp_dscp",
			l4proto:      unix.IPPROTO_TCP,
			source:       "embedded",
			functionName: consts.Function_Dscp,
			literal:      "10",
			dscp:         10,
		},
		{
			name:         "udp_dscp",
			l4proto:      unix.IPPROTO_UDP,
			source:       "embedded",
			functionName: consts.Function_Dscp,
			literal:      "10",
			dscp:         10,
		},
		{
			name:         "tcp_mac",
			l4proto:      unix.IPPROTO_TCP,
			source:       "embedded",
			functionName: consts.Function_Mac,
			literal:      "02:42:ac:11:00:02",
			mac:          matchMac,
		},
		{
			name:         "udp_mac",
			l4proto:      unix.IPPROTO_UDP,
			source:       "embedded",
			functionName: consts.Function_Mac,
			literal:      "02:42:ac:11:00:02",
			mac:          matchMac,
		},
		{
			name:         "tcp_pname",
			l4proto:      unix.IPPROTO_TCP,
			source:       "embedded",
			functionName: consts.Function_ProcessName,
			literal:      "curl",
			pname:        "curl",
		},
		{
			name:         "udp_pname",
			l4proto:      unix.IPPROTO_UDP,
			source:       "embedded",
			functionName: consts.Function_ProcessName,
			literal:      "curl",
			pname:        "curl",
		},
		{
			name:         "tcp_dscp_handoff",
			l4proto:      unix.IPPROTO_TCP,
			source:       "handoff",
			functionName: consts.Function_Dscp,
			literal:      "10",
			dscp:         10,
		},
		{
			name:         "udp_dscp_handoff",
			l4proto:      unix.IPPROTO_UDP,
			source:       "handoff",
			functionName: consts.Function_Dscp,
			literal:      "10",
			dscp:         10,
		},
		{
			name:         "tcp_mac_handoff",
			l4proto:      unix.IPPROTO_TCP,
			source:       "handoff",
			functionName: consts.Function_Mac,
			literal:      "02:42:ac:11:00:02",
			mac:          matchMac,
		},
		{
			name:         "udp_mac_handoff",
			l4proto:      unix.IPPROTO_UDP,
			source:       "handoff",
			functionName: consts.Function_Mac,
			literal:      "02:42:ac:11:00:02",
			mac:          matchMac,
		},
		{
			name:         "tcp_pname_handoff",
			l4proto:      unix.IPPROTO_TCP,
			source:       "handoff",
			functionName: consts.Function_ProcessName,
			literal:      "curl",
			pname:        "curl",
		},
		{
			name:         "udp_pname_handoff",
			l4proto:      unix.IPPROTO_UDP,
			source:       "handoff",
			functionName: consts.Function_ProcessName,
			literal:      "curl",
			pname:        "curl",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var rr *bpfRoutingResult
			var src, dst netip.AddrPort
			switch tt.source {
			case "embedded":
				rr, src, dst = retrieveRoutingResultForMetadataRuleTest(t, tt.l4proto, tt.dscp, tt.mac, tt.pname)
			case "handoff":
				rr, src, dst = retrieveRoutingHandoffResultForMetadataRuleTest(t, tt.l4proto, tt.dscp, tt.mac, tt.pname)
			default:
				t.Fatalf("unknown metadata source %q", tt.source)
			}
			plane := newTestControlPlaneWithSingleMetadataRule(t, tt.functionName, tt.literal)

			outbound, _, _, err := plane.Route(src, dst, "", consts.L4ProtoType(tt.l4proto), rr)
			if err != nil {
				t.Fatalf("Route(%s): %v", tt.name, err)
			}
			if outbound != consts.OutboundUserDefinedMin {
				t.Fatalf("Route(%s) outbound = %v, want %v", tt.name, outbound, consts.OutboundUserDefinedMin)
			}
		})
	}
}
