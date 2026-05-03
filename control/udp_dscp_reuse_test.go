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
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/sirupsen/logrus"
)

func newTestRoutingMatcherWithDscpRules(t *testing.T, literals ...string) *RoutingMatcher {
	t.Helper()

	rules := make([]*config_parser.RoutingRule, 0, len(literals))
	for _, literal := range literals {
		rules = append(rules, &config_parser.RoutingRule{
			AndFunctions: []*config_parser.Function{
				{
					Name: consts.Function_Dscp,
					Params: []*config_parser.Param{
						{Val: literal},
					},
				},
			},
			Outbound: config_parser.Function{Name: "proxy"},
		})
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
		t.Fatalf("NewRoutingMatcherBuilder(%v): %v", literals, err)
	}

	matcher, err := builder.BuildUserspace()
	if err != nil {
		t.Fatalf("BuildUserspace(%v): %v", literals, err)
	}
	return matcher
}

func TestHandlePkt_DscpControlPlaneRoutingReusesEndpointForSameFlow(t *testing.T) {
	oldPool := DefaultUdpEndpointPool
	DefaultUdpEndpointPool = NewUdpEndpointPool()
	defer func() {
		DefaultUdpEndpointPool.Reset()
		DefaultUdpEndpointPool = oldPool
	}()

	conn := &udpReuseSimulationConn{
		reads:   make(chan scriptedPacketRead),
		closeCh: make(chan struct{}),
	}
	d, underlay := newCountingProxyEndpointDialer("hysteria2", "proxy.example:443", conn)
	cp := newUdpReuseSimulationControlPlane(newTestFixedOutboundGroup(d))
	cp.routingMatcher = newTestRoutingMatcherWithDscpRules(t, "46")
	cp.udpRouteScopeSensitive = true

	src := mustParseAddrPort("192.168.89.3:42687")
	dst := mustParseAddrPort("52.199.194.44:23002")
	payload := []byte{0x51, 0x52, 0x53, 0x54}
	flowDecision := ClassifyUdpFlow(src, dst, payload)
	routingResult := &bpfRoutingResult{
		Outbound: uint8(consts.OutboundControlPlaneRouting),
		Dscp:     46,
	}
	scope := newUdpEndpointRouteScope(routingResult)
	key := flowDecision.EndpointKeyForDialWithScope("", scope, true)

	if err := cp.handlePkt(nil, payload, src, dst, routingResult, flowDecision, false); err != nil {
		t.Fatalf("first handlePkt: %v", err)
	}
	if got := underlay.calls.Load(); got != 1 {
		t.Fatalf("DialContext calls after first packet = %d, want 1", got)
	}
	if got := countPooledUdpEndpoints(DefaultUdpEndpointPool); got != 1 {
		t.Fatalf("pooled endpoints after first packet = %d, want 1", got)
	}
	if _, ok := DefaultUdpEndpointPool.Get(key); !ok {
		t.Fatalf("expected endpoint %v to exist after first packet", key)
	}

	if err := cp.handlePkt(nil, payload, src, dst, routingResult, flowDecision, false); err != nil {
		t.Fatalf("second handlePkt: %v", err)
	}
	if got := underlay.calls.Load(); got != 1 {
		t.Fatalf("DialContext calls after second packet = %d, want 1 (reused endpoint)", got)
	}
	if got := countPooledUdpEndpoints(DefaultUdpEndpointPool); got != 1 {
		t.Fatalf("pooled endpoints after second packet = %d, want 1", got)
	}
}

func TestHandlePkt_DscpControlPlaneRoutingSeparatesEndpointsForDifferentDscp(t *testing.T) {
	oldPool := DefaultUdpEndpointPool
	DefaultUdpEndpointPool = NewUdpEndpointPool()
	defer func() {
		DefaultUdpEndpointPool.Reset()
		DefaultUdpEndpointPool = oldPool
	}()

	conn1 := &udpReuseSimulationConn{
		reads:   make(chan scriptedPacketRead),
		closeCh: make(chan struct{}),
	}
	conn2 := &udpReuseSimulationConn{
		reads:   make(chan scriptedPacketRead),
		closeCh: make(chan struct{}),
	}
	nextConn := 0
	d, underlay := newFactoryProxyEndpointDialer("hysteria2", "proxy.example:443", func() netproxy.Conn {
		if nextConn == 0 {
			nextConn++
			return conn1
		}
		nextConn++
		return conn2
	})
	cp := newUdpReuseSimulationControlPlane(newTestFixedOutboundGroup(d))
	cp.routingMatcher = newTestRoutingMatcherWithDscpRules(t, "8", "46")
	cp.udpRouteScopeSensitive = true

	src := netip.MustParseAddrPort("192.168.89.3:42687")
	dst := netip.MustParseAddrPort("52.199.194.44:23002")
	payload := []byte{0x61, 0x62, 0x63, 0x64}
	flowDecision := ClassifyUdpFlow(src, dst, payload)
	firstResult := &bpfRoutingResult{
		Outbound: uint8(consts.OutboundControlPlaneRouting),
		Dscp:     8,
	}
	secondResult := &bpfRoutingResult{
		Outbound: uint8(consts.OutboundControlPlaneRouting),
		Dscp:     46,
	}
	firstKey := flowDecision.EndpointKeyForDialWithScope("", newUdpEndpointRouteScope(firstResult), true)
	secondKey := flowDecision.EndpointKeyForDialWithScope("", newUdpEndpointRouteScope(secondResult), true)

	if err := cp.handlePkt(nil, payload, src, dst, firstResult, flowDecision, false); err != nil {
		t.Fatalf("handlePkt(first dscp): %v", err)
	}
	if err := cp.handlePkt(nil, payload, src, dst, secondResult, flowDecision, false); err != nil {
		t.Fatalf("handlePkt(second dscp): %v", err)
	}

	if got := underlay.calls.Load(); got != 2 {
		t.Fatalf("DialContext calls after different DSCP packets = %d, want 2", got)
	}
	if got := countPooledUdpEndpoints(DefaultUdpEndpointPool); got != 2 {
		t.Fatalf("pooled endpoints after different DSCP packets = %d, want 2", got)
	}
	if _, ok := DefaultUdpEndpointPool.Get(firstKey); !ok {
		t.Fatalf("expected first DSCP endpoint %v to exist", firstKey)
	}
	if _, ok := DefaultUdpEndpointPool.Get(secondKey); !ok {
		t.Fatalf("expected second DSCP endpoint %v to exist", secondKey)
	}
}
