/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/component/sniffing"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/sirupsen/logrus"
)

type phase0TCPTLSAction string

const (
	phase0TCPTLSActionDirect phase0TCPTLSAction = "direct"
	phase0TCPTLSActionProxy  phase0TCPTLSAction = "proxy"
	phase0TCPTLSActionBlock  phase0TCPTLSAction = "block"
)

type phase0TCPTLSCorpusFixture struct {
	name             string
	clientHello      []byte
	expectedDomain   string
	expectedOutbound consts.OutboundIndex
	expectedMark     uint32
	expectedMust     bool
	expectedTarget   string
	expectedNetwork  string
	expectedAction   phase0TCPTLSAction
}

// phase0TLSClientHello is a minimal TLS 1.2 ClientHello with SNI
// "tls.phase0.test". Its fixed bytes make the corpus independent of a live
// TLS stack while still exercising the production stream sniffer.
var phase0TLSClientHello = []byte{
	0x16, 0x03, 0x01, 0x00, 0x47,
	0x01, 0x00, 0x00, 0x43,
	0x03, 0x03,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00,
	0x00, 0x02, 0x13, 0x01,
	0x01, 0x00,
	0x00, 0x18,
	0x00, 0x00, 0x00, 0x14,
	0x00, 0x12, 0x00, 0x00, 0x0f,
	't', 'l', 's', '.', 'p', 'h', 'a', 's', 'e', '0', '.', 't', 'e', 's', 't',
}

func phase0TCPTLSCorpusFixtures() []phase0TCPTLSCorpusFixture {
	return []phase0TCPTLSCorpusFixture{{
		name:             "tls_sni_routes_to_marked_must_proxy",
		clientHello:      phase0TLSClientHello,
		expectedDomain:   "tls.phase0.test",
		expectedOutbound: consts.OutboundUserDefinedMin,
		expectedMark:     42,
		expectedMust:     true,
		expectedTarget:   "198.51.100.20:443",
		expectedNetwork:  "tcp",
		expectedAction:   phase0TCPTLSActionProxy,
	}}
}

// TestPhase0TCPTLSCorpus_LegacyBaseline fixes the legacy TCP/TLS observable
// decision: parse a ClientHello SNI, route that evidence, and dial the chosen
// proxy. Later policy or flow refactors must preserve this entire outcome.
func TestPhase0TCPTLSCorpus_LegacyBaseline(t *testing.T) {
	for _, fixture := range phase0TCPTLSCorpusFixtures() {
		t.Run(fixture.name, func(t *testing.T) {
			replayPhase0TCPTLSCorpusFixture(t, fixture)
		})
	}
}

func replayPhase0TCPTLSCorpusFixture(t *testing.T, fixture phase0TCPTLSCorpusFixture) {
	t.Helper()

	sniffer := sniffing.NewStreamSniffer(bytes.NewReader(fixture.clientHello), time.Second)
	t.Cleanup(func() { _ = sniffer.Close() })
	domain, err := sniffer.SniffTcp()
	if err != nil {
		t.Fatalf("SniffTcp() error = %v", err)
	}
	if domain != fixture.expectedDomain {
		t.Fatalf("SNI = %q, want %q", domain, fixture.expectedDomain)
	}

	matcher := newPhase0TCPTLSLegacyMatcher(t, fixture)
	clientConn, proxyConn := net.Pipe()
	t.Cleanup(func() { _ = proxyConn.Close() })
	dialer, underlay := newCountingProxyEndpointDialer("shadowsocks_2022", "proxy.example:443", clientConn)
	cp := newTestDialControlPlane(newTestFixedOutboundGroup(dialer))
	cp.routingMatcher = matcher
	cp.dialMode = consts.DialMode_Ip

	src := netip.MustParseAddrPort("192.0.2.10:41000")
	dst := netip.MustParseAddrPort("198.51.100.20:443")
	routingResult := &bpfRoutingResult{Outbound: uint8(consts.OutboundControlPlaneRouting)}
	outbound, mark, must, err := cp.Route(src, dst, domain, consts.L4ProtoType_TCP, routingResult)
	if err != nil {
		t.Fatalf("Route() error = %v", err)
	}
	if outbound != fixture.expectedOutbound || mark != fixture.expectedMark || must != fixture.expectedMust {
		t.Fatalf("route = (outbound=%v mark=%d must=%v), want (%v %d %v)", outbound, mark, must, fixture.expectedOutbound, fixture.expectedMark, fixture.expectedMust)
	}

	routingResult.Outbound = uint8(outbound)
	routingResult.Mark = mark
	if must {
		routingResult.Must = 1
	}
	conn, result, err := cp.routeDial(context.Background(), tcpProxyDialParamFromRoutingResult(routingResult, domain, src, dst))
	if err != nil {
		t.Fatalf("routeDial() error = %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	if result.OutboundIndex != fixture.expectedOutbound || result.Mark != fixture.expectedMark || result.Must != fixture.expectedMust {
		t.Fatalf("dial result = (outbound=%v mark=%d must=%v), want (%v %d %v)", result.OutboundIndex, result.Mark, result.Must, fixture.expectedOutbound, fixture.expectedMark, fixture.expectedMust)
	}
	if binding := newTcpFlowBinding(cp.PolicyEpoch(), result); binding.Route.Outbound != fixture.expectedOutbound || binding.Route.Mark != fixture.expectedMark || binding.Route.Must != fixture.expectedMust || binding.Egress.Target != fixture.expectedTarget {
		t.Fatalf("TCP flow binding = %+v, want outbound=%v mark=%d must=%v target=%q", binding, fixture.expectedOutbound, fixture.expectedMark, fixture.expectedMust, fixture.expectedTarget)
	}
	if result.DialTarget != fixture.expectedTarget || !result.IsDialIp {
		t.Fatalf("dial = (target=%q dial_ip=%v), want (%q true)", result.DialTarget, result.IsDialIp, fixture.expectedTarget)
	}
	magicNetwork, err := netproxy.ParseMagicNetwork(result.Network)
	if err != nil {
		t.Fatalf("ParseMagicNetwork() error = %v", err)
	}
	if magicNetwork.Network != fixture.expectedNetwork || magicNetwork.Mark != fixture.expectedMark || magicNetwork.Mptcp {
		t.Fatalf("network = %+v, want tcp with mark %d and mptcp disabled", magicNetwork, fixture.expectedMark)
	}
	if result.SelectionNetworkTypeObj == nil || result.SelectionNetworkTypeObj.L4Proto != consts.L4ProtoStr_TCP || result.SelectionNetworkTypeObj.IpVersion != consts.IpVersionStr_4 {
		t.Fatalf("selected network family = %+v, want tcp/ipv4", result.SelectionNetworkTypeObj)
	}
	if action := phase0TCPTLSActionForOutbound(result.OutboundIndex); action != fixture.expectedAction {
		t.Fatalf("action = %q, want %q", action, fixture.expectedAction)
	}
	if got := underlay.calls.Load(); got != 1 {
		t.Fatalf("proxy DialContext calls = %d, want 1", got)
	}
}

func newPhase0TCPTLSLegacyMatcher(t *testing.T, fixture phase0TCPTLSCorpusFixture) *RoutingMatcher {
	t.Helper()
	program, err := routing.NewNormalizedProgram(
		[]*config_parser.RoutingRule{{
			AndFunctions: []*config_parser.Function{{
				Name: consts.Function_Domain,
				Params: []*config_parser.Param{{
					Key: string(consts.RoutingDomainKey_Full),
					Val: fixture.expectedDomain,
				}},
			}},
			Outbound: config_parser.Function{
				Name: "proxy",
				Params: []*config_parser.Param{
					{Key: "mark", Val: "42"},
					{Val: "must"},
				},
			},
		}},
		config.FunctionOrString("direct"),
	)
	if err != nil {
		t.Fatalf("NewNormalizedProgram() error = %v", err)
	}
	builder, err := NewRoutingMatcherBuilderFromProgram(
		logrus.New(),
		program,
		map[string]uint8{
			"direct": uint8(consts.OutboundDirect),
			"proxy":  uint8(fixture.expectedOutbound),
		},
		nil,
	)
	if err != nil {
		t.Fatalf("NewRoutingMatcherBuilderFromProgram() error = %v", err)
	}
	matcher, err := builder.BuildUserspace()
	if err != nil {
		t.Fatalf("BuildUserspace() error = %v", err)
	}
	return matcher
}

func phase0TCPTLSActionForOutbound(outbound consts.OutboundIndex) phase0TCPTLSAction {
	switch outbound {
	case consts.OutboundDirect:
		return phase0TCPTLSActionDirect
	case consts.OutboundBlock:
		return phase0TCPTLSActionBlock
	default:
		return phase0TCPTLSActionProxy
	}
}
