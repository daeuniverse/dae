/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@daeuniverse.org>
 */

package daedns

import (
	"net/netip"
	"testing"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/sirupsen/logrus"
)

func TestRouterMatchSubscriptionUpstream(t *testing.T) {
	router := mustNewTestRouter(t,
		testInternalRule("subdns", testInternalFunction("sub", testInternalParam("", "my_sub"))),
		testInternalRule("linkdns", testInternalFunction("sub", testInternalParam("link_keyword", "special-provider"))),
	)

	upstream, ok := router.MatchSubscriptionUpstream("my_sub:https://example.com/list")
	if !ok || upstream != "subdns" {
		t.Fatalf("expected exact sub tag to match subdns, got upstream=%q ok=%v", upstream, ok)
	}

	upstream, ok = router.MatchSubscriptionUpstream("other:https://special-provider.example/sub")
	if !ok || upstream != "linkdns" {
		t.Fatalf("expected link keyword to match linkdns, got upstream=%q ok=%v", upstream, ok)
	}
}

func TestRouterDoesNotInheritSubscriptionSelectorToNodes(t *testing.T) {
	router := mustNewTestRouter(t,
		testInternalRule("subdns", testInternalFunction("sub", testInternalParam("", "my_sub"))),
	)

	upstream, ok := router.MatchNodeUpstream(NodeMeta{
		SubscriptionTag: "my_sub",
		Name:            "hk-01",
		Link:            "trojan://hk.example:443",
	})
	if ok {
		t.Fatalf("expected node lookup to ignore sub() rules, got upstream=%q", upstream)
	}
}

func TestRouterMatchNodeUpstreamPrefersSubNodeOverNode(t *testing.T) {
	router := mustNewTestRouter(t,
		testInternalRule("nodedns", testInternalFunction("node", testInternalParam("", "hk-01"))),
		testInternalRule("subnodedns",
			testInternalFunction("subnode",
				testInternalParam("subtag", "my_sub"),
				testInternalParam("name", "hk-01"),
			),
		),
	)

	upstream, ok := router.MatchNodeUpstream(NodeMeta{
		SubscriptionTag: "my_sub",
		Name:            "hk-01",
		Link:            "trojan://hk.example:443",
	})
	if !ok || upstream != "subnodedns" {
		t.Fatalf("expected subnode rule to override node rule, got upstream=%q ok=%v", upstream, ok)
	}

	upstream, ok = router.MatchNodeUpstream(NodeMeta{
		Name: "hk-01",
		Link: "trojan://hk.example:443",
	})
	if !ok || upstream != "nodedns" {
		t.Fatalf("expected plain node to use node matcher, got upstream=%q ok=%v", upstream, ok)
	}
}

func TestRouterMatchNodeUpstreamCatchAllSubNodeOnlyMatchesSubscriptionNodes(t *testing.T) {
	router := mustNewTestRouter(t,
		testInternalRule("nodedns", testInternalFunction("node")),
		testInternalRule("subnodedns", testInternalFunction("subnode")),
	)

	upstream, ok := router.MatchNodeUpstream(NodeMeta{
		SubscriptionTag: "my_sub",
		Name:            "hk-01",
		Link:            "trojan://hk.example:443",
	})
	if !ok || upstream != "subnodedns" {
		t.Fatalf("expected catch-all subnode to match subscription node first, got upstream=%q ok=%v", upstream, ok)
	}

	upstream, ok = router.MatchNodeUpstream(NodeMeta{
		Name: "manual-node",
		Link: "trojan://manual.example:443",
	})
	if !ok || upstream != "nodedns" {
		t.Fatalf("expected manual node to fall back to catch-all node rule, got upstream=%q ok=%v", upstream, ok)
	}
}

func TestRouterUsesEffectiveSoMarkFromDae(t *testing.T) {
	router := mustNewTestRouter(t,
		testInternalRule("subdns", testInternalFunction("sub")),
	)

	if router.soMark != common.InternalSoMarkFromDae {
		t.Fatalf("expected router to use effective internal so_mark, got %d", router.soMark)
	}
}

func TestRouterUsesDefaultBootstrapResolversWhenUnset(t *testing.T) {
	router := mustNewTestRouter(t,
		testInternalRule("subdns", testInternalFunction("sub")),
	)

	want := []netip.AddrPort{
		netip.MustParseAddrPort("119.29.29.29:53"),
		netip.MustParseAddrPort("223.5.5.5:53"),
	}
	if len(router.bootstrapDns) != len(want) {
		t.Fatalf("len(router.bootstrapDns) = %d, want %d", len(router.bootstrapDns), len(want))
	}
	for i := range want {
		if router.bootstrapDns[i] != want[i] {
			t.Fatalf("router.bootstrapDns[%d] = %v, want %v", i, router.bootstrapDns[i], want[i])
		}
	}
}

func TestRouterExplicitBootstrapResolverOverridesDefaults(t *testing.T) {
	router, err := New(logrus.New(), &config.Global{
		BootstrapResolver: "9.9.9.9:53",
	}, &config.Dns{
		Upstream: []config.KeyableString{
			"subdns:udp://1.1.1.1:53",
		},
		Routing: config.DnsRouting{
			Request: config.DnsRequestRouting{
				Rules: []*config_parser.RoutingRule{
					testInternalRule("subdns", testInternalFunction("sub")),
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if len(router.bootstrapDns) != 1 {
		t.Fatalf("len(router.bootstrapDns) = %d, want 1", len(router.bootstrapDns))
	}
	if router.bootstrapDns[0] != netip.MustParseAddrPort("9.9.9.9:53") {
		t.Fatalf("router.bootstrapDns[0] = %v, want 9.9.9.9:53", router.bootstrapDns[0])
	}
}

func mustNewTestRouter(t *testing.T, rules ...*config_parser.RoutingRule) *Router {
	t.Helper()

	router, err := New(logrus.New(), &config.Global{}, &config.Dns{
		Upstream: []config.KeyableString{
			"subdns:udp://1.1.1.1:53",
			"linkdns:udp://1.0.0.1:53",
			"nodedns:udp://9.9.9.9:53",
			"subnodedns:udp://8.8.8.8:53",
		},
		Routing: config.DnsRouting{
			Request: config.DnsRequestRouting{
				Rules: rules,
			},
		},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if router == nil {
		t.Fatal("expected router to be created")
	}
	return router
}

func testInternalRule(outbound string, andFunctions ...*config_parser.Function) *config_parser.RoutingRule {
	return &config_parser.RoutingRule{
		AndFunctions: andFunctions,
		Outbound:     config_parser.Function{Name: outbound},
	}
}

func testInternalFunction(name string, params ...*config_parser.Param) *config_parser.Function {
	return &config_parser.Function{
		Name:   name,
		Params: params,
	}
}

func testInternalParam(key, value string) *config_parser.Param {
	return &config_parser.Param{
		Key: key,
		Val: value,
	}
}
