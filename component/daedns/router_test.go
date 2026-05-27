/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@daeuniverse.org>
 */

package daedns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/assets"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/daeuniverse/dae/pkg/geodata"
	"github.com/daeuniverse/outbound/netproxy"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
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
				Fallback: "subdns",
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

func TestRouterWrapNodeDialerUsesGeneralRequestRoutingForNonControlHost(t *testing.T) {
	skipIfNoSocketMark(t)
	addr, stop := startTestDNSUDPServer(t, netip.MustParseAddr("203.0.113.7"))
	defer stop()

	router, err := New(logrus.New(), &config.Global{}, &config.Dns{
		Upstream: []config.KeyableString{
			config.KeyableString(fmt.Sprintf("fallbackdns:udp://%s", addr)),
		},
		Routing: config.DnsRouting{
			Request: config.DnsRequestRouting{
				Rules: []*config_parser.RoutingRule{
					testInternalRule("fallbackdns", testInternalFunction("qname", testInternalParam("suffix", "example.com"))),
				},
				Fallback: "fallbackdns",
			},
		},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if router == nil {
		t.Fatal("expected router to be created for general DNS request routing")
	}

	base := &stubDialer{}
	wrapped, err := router.WrapNodeDialer(base, NodeMeta{
		Name:        "test-node",
		Link:        "ss://proxy.example.com:443",
		AddressHost: "proxy.example.com",
	})
	if err != nil {
		t.Fatalf("WrapNodeDialer() error = %v", err)
	}
	if wrapped == base {
		t.Fatal("expected WrapNodeDialer to wrap base dialer when general request routing is available")
	}

	resolver, ok := wrapped.(interface {
		LookupIPAddr(context.Context, string, string) ([]net.IPAddr, error)
	})
	if !ok {
		t.Fatal("wrapped dialer does not expose LookupIPAddr")
	}
	ips, err := resolver.LookupIPAddr(context.Background(), "tcp", "service.example.com")
	if err != nil {
		t.Fatalf("LookupIPAddr() error = %v", err)
	}
	if len(ips) != 1 || !ips[0].IP.Equal(net.IPv4(203, 0, 113, 7)) {
		t.Fatalf("LookupIPAddr() = %v, want 203.0.113.7", ips)
	}
}

func TestRouterWrapNodeDialerUsesBootstrapForControlHostWithoutExplicitNodeRule(t *testing.T) {
	skipIfNoSocketMark(t)
	requestAddr, stopRequest := startTestDNSUDPServer(t, netip.MustParseAddr("203.0.113.7"))
	defer stopRequest()
	bootstrapAddr, stopBootstrap := startTestDNSUDPServer(t, netip.MustParseAddr("198.51.100.7"))
	defer stopBootstrap()

	router, err := New(logrus.New(), &config.Global{
		BootstrapResolver: bootstrapAddr,
	}, &config.Dns{
		Upstream: []config.KeyableString{
			config.KeyableString(fmt.Sprintf("fallbackdns:udp://%s", requestAddr)),
		},
		Routing: config.DnsRouting{
			Request: config.DnsRequestRouting{
				Rules: []*config_parser.RoutingRule{
					testInternalRule("fallbackdns", testInternalFunction("qname", testInternalParam("suffix", "example.com"))),
				},
				Fallback: "fallbackdns",
			},
		},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	base := &stubDialer{}
	wrapped, err := router.WrapNodeDialer(base, NodeMeta{
		Name:        "test-node",
		Link:        "ss://proxy.example.com:443",
		AddressHost: "proxy.example.com",
	})
	if err != nil {
		t.Fatalf("WrapNodeDialer() error = %v", err)
	}

	resolver, ok := wrapped.(interface {
		LookupIPAddr(context.Context, string, string) ([]net.IPAddr, error)
	})
	if !ok {
		t.Fatal("wrapped dialer does not expose LookupIPAddr")
	}
	ips, err := resolver.LookupIPAddr(context.Background(), "tcp", "proxy.example.com")
	if err != nil {
		t.Fatalf("LookupIPAddr() error = %v", err)
	}
	if base.lookupCalls != 0 {
		t.Fatalf("base lookup calls = %d, want 0", base.lookupCalls)
	}
	if len(ips) != 1 || !ips[0].IP.Equal(net.IPv4(198, 51, 100, 7)) {
		t.Fatalf("LookupIPAddr() = %v, want 198.51.100.7", ips)
	}
}

func TestRouterWrapNodeDialerFallsBackToBaseResolverForPassThroughFallback(t *testing.T) {
	for _, fallback := range []string{"asis", "reject"} {
		t.Run(fallback, func(t *testing.T) {
			router, err := New(logrus.New(), &config.Global{}, &config.Dns{
				Upstream: []config.KeyableString{
					"fallbackdns:udp://1.1.1.1:53",
				},
				Routing: config.DnsRouting{
					Request: config.DnsRequestRouting{
						Rules: []*config_parser.RoutingRule{
							testInternalRule("fallbackdns", testInternalFunction("qname", testInternalParam("suffix", "example.com"))),
						},
						Fallback: fallback,
					},
				},
			})
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}

			base := &stubDialer{lookupResult: []net.IPAddr{{IP: net.IPv4(198, 51, 100, 7)}}}
			wrapped, err := router.WrapNodeDialer(base, NodeMeta{
				Name:        "test-node",
				Link:        "ss://proxy.invalid:443",
				AddressHost: "proxy.invalid",
			})
			if err != nil {
				t.Fatalf("WrapNodeDialer() error = %v", err)
			}

			resolver, ok := wrapped.(interface {
				LookupIPAddr(context.Context, string, string) ([]net.IPAddr, error)
			})
			if !ok {
				t.Fatal("wrapped dialer does not expose LookupIPAddr")
			}
			ips, err := resolver.LookupIPAddr(context.Background(), "tcp", "target.invalid")
			if err != nil {
				t.Fatalf("LookupIPAddr() error = %v", err)
			}
			if base.lookupCalls != 1 {
				t.Fatalf("base lookup calls = %d, want 1", base.lookupCalls)
			}
			if base.lookupNetwork != "tcp" || base.lookupHost != "target.invalid" {
				t.Fatalf("base lookup = (%q, %q), want (%q, %q)", base.lookupNetwork, base.lookupHost, "tcp", "target.invalid")
			}
			if len(ips) != 1 || !ips[0].IP.Equal(net.IPv4(198, 51, 100, 7)) {
				t.Fatalf("LookupIPAddr() = %v, want 198.51.100.7", ips)
			}
		})
	}
}

func TestRouterWrapNodeDialerFallsBackToBaseResolverWhenRequestUpstreamReturnsNoAddress(t *testing.T) {
	skipIfNoSocketMark(t)
	addr, stop := startTestEmptyDNSUDPServer(t)
	defer stop()

	router, err := New(logrus.New(), &config.Global{}, &config.Dns{
		Upstream: []config.KeyableString{
			config.KeyableString(fmt.Sprintf("fallbackdns:udp://%s", addr)),
		},
		Routing: config.DnsRouting{
			Request: config.DnsRequestRouting{
				Rules: []*config_parser.RoutingRule{
					testInternalRule("fallbackdns", testInternalFunction("qname", testInternalParam("suffix", "example.com"))),
				},
				Fallback: "fallbackdns",
			},
		},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	base := &stubDialer{lookupResult: []net.IPAddr{{IP: net.IPv4(198, 51, 100, 8)}}}
	wrapped, err := router.WrapNodeDialer(base, NodeMeta{
		Name:        "test-node",
		Link:        "ss://proxy.example.com:443",
		AddressHost: "proxy.example.com",
	})
	if err != nil {
		t.Fatalf("WrapNodeDialer() error = %v", err)
	}

	resolver, ok := wrapped.(interface {
		LookupIPAddr(context.Context, string, string) ([]net.IPAddr, error)
	})
	if !ok {
		t.Fatal("wrapped dialer does not expose LookupIPAddr")
	}
	ips, err := resolver.LookupIPAddr(context.Background(), "tcp", "target.example.com")
	if err != nil {
		t.Fatalf("LookupIPAddr() error = %v", err)
	}
	if base.lookupCalls != 1 {
		t.Fatalf("base lookup calls = %d, want 1", base.lookupCalls)
	}
	if len(ips) != 1 || !ips[0].IP.Equal(net.IPv4(198, 51, 100, 8)) {
		t.Fatalf("LookupIPAddr() = %v, want 198.51.100.8", ips)
	}
}

func TestRouterUsesExternalGeodataDirsForRequestRules(t *testing.T) {
	skipIfNoSocketMark(t)
	addr, stop := startTestDNSUDPServer(t, netip.MustParseAddr("203.0.113.9"))
	defer stop()

	geoDir := t.TempDir()
	writeTestGeoSite(t, filepath.Join(geoDir, "geosite.dat"), "test-ext", "example.com")

	router, err := NewWithOption(logrus.New(), &config.Global{}, &config.Dns{
		Upstream: []config.KeyableString{
			config.KeyableString(fmt.Sprintf("extdns:udp://%s", addr)),
		},
		Routing: config.DnsRouting{
			Request: config.DnsRequestRouting{
				Rules: []*config_parser.RoutingRule{
					testInternalRule("extdns", testInternalFunction("qname", testInternalParam("geosite", "test-ext"))),
				},
				Fallback: "asis",
			},
		},
	}, &NewOption{LocationFinder: assets.NewLocationFinder([]string{geoDir})})
	if err != nil {
		t.Fatalf("NewWithOption() error = %v", err)
	}

	base := &stubDialer{}
	wrapped, err := router.WrapNodeDialer(base, NodeMeta{
		Name:        "test-node",
		Link:        "ss://proxy.example.com:443",
		AddressHost: "proxy.example.com",
	})
	if err != nil {
		t.Fatalf("WrapNodeDialer() error = %v", err)
	}

	resolver, ok := wrapped.(interface {
		LookupIPAddr(context.Context, string, string) ([]net.IPAddr, error)
	})
	if !ok {
		t.Fatal("wrapped dialer does not expose LookupIPAddr")
	}
	ips, err := resolver.LookupIPAddr(context.Background(), "tcp", "service.example.com")
	if err != nil {
		t.Fatalf("LookupIPAddr() error = %v", err)
	}
	if len(ips) != 1 || !ips[0].IP.Equal(net.IPv4(203, 0, 113, 9)) {
		t.Fatalf("LookupIPAddr() = %v, want 203.0.113.9", ips)
	}
}

func TestRouterWrapNodeDialerUsesExplicitNodeUpstreamForControlHost(t *testing.T) {
	skipIfNoSocketMark(t)
	nodeAddr, stopNode := startTestDNSUDPServer(t, netip.MustParseAddr("192.0.2.9"))
	defer stopNode()
	requestAddr, stopRequest := startTestDNSUDPServer(t, netip.MustParseAddr("203.0.113.9"))
	defer stopRequest()
	bootstrapAddr, stopBootstrap := startTestDNSUDPServer(t, netip.MustParseAddr("198.51.100.9"))
	defer stopBootstrap()

	router, err := New(logrus.New(), &config.Global{
		BootstrapResolver: bootstrapAddr,
	}, &config.Dns{
		Upstream: []config.KeyableString{
			config.KeyableString(fmt.Sprintf("fallbackdns:udp://%s", requestAddr)),
			config.KeyableString(fmt.Sprintf("nodedns:udp://%s", nodeAddr)),
		},
		Routing: config.DnsRouting{
			Request: config.DnsRequestRouting{
				Rules: []*config_parser.RoutingRule{
					testInternalRule("fallbackdns", testInternalFunction("qname", testInternalParam("suffix", "example.com"))),
					testInternalRule("nodedns", testInternalFunction("node", testInternalParam("", "test-node"))),
				},
				Fallback: "fallbackdns",
			},
		},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	base := &stubDialer{}
	wrapped, err := router.WrapNodeDialer(base, NodeMeta{
		Name:        "test-node",
		Link:        "ss://proxy.example.com:443",
		AddressHost: "proxy.example.com",
	})
	if err != nil {
		t.Fatalf("WrapNodeDialer() error = %v", err)
	}

	resolver, ok := wrapped.(interface {
		LookupIPAddr(context.Context, string, string) ([]net.IPAddr, error)
	})
	if !ok {
		t.Fatal("wrapped dialer does not expose LookupIPAddr")
	}
	ips, err := resolver.LookupIPAddr(context.Background(), "tcp", "proxy.example.com")
	if err != nil {
		t.Fatalf("LookupIPAddr() error = %v", err)
	}
	if len(ips) != 1 || !ips[0].IP.Equal(net.IPv4(192, 0, 2, 9)) {
		t.Fatalf("LookupIPAddr() = %v, want 192.0.2.9", ips)
	}
}

func TestRouterWrapSubscriptionDialerUsesBootstrapForSubscriptionHostWithoutExplicitRule(t *testing.T) {
	skipIfNoSocketMark(t)
	requestAddr, stopRequest := startTestDNSUDPServer(t, netip.MustParseAddr("203.0.113.10"))
	defer stopRequest()
	bootstrapAddr, stopBootstrap := startTestDNSUDPServer(t, netip.MustParseAddr("198.51.100.10"))
	defer stopBootstrap()

	router, err := New(logrus.New(), &config.Global{
		BootstrapResolver: bootstrapAddr,
	}, &config.Dns{
		Upstream: []config.KeyableString{
			config.KeyableString(fmt.Sprintf("fallbackdns:udp://%s", requestAddr)),
		},
		Routing: config.DnsRouting{
			Request: config.DnsRequestRouting{
				Rules: []*config_parser.RoutingRule{
					testInternalRule("fallbackdns", testInternalFunction("qname", testInternalParam("suffix", "example.com"))),
				},
				Fallback: "fallbackdns",
			},
		},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	base := &stubDialer{}
	wrapped, err := router.WrapSubscriptionDialer(base, "my_sub:https://sub.example.com/list")
	if err != nil {
		t.Fatalf("WrapSubscriptionDialer() error = %v", err)
	}

	resolver, ok := wrapped.(interface {
		LookupIPAddr(context.Context, string, string) ([]net.IPAddr, error)
	})
	if !ok {
		t.Fatal("wrapped dialer does not expose LookupIPAddr")
	}
	ips, err := resolver.LookupIPAddr(context.Background(), "tcp", "sub.example.com")
	if err != nil {
		t.Fatalf("LookupIPAddr() error = %v", err)
	}
	if base.lookupCalls != 0 {
		t.Fatalf("base lookup calls = %d, want 0", base.lookupCalls)
	}
	if len(ips) != 1 || !ips[0].IP.Equal(net.IPv4(198, 51, 100, 10)) {
		t.Fatalf("LookupIPAddr() = %v, want 198.51.100.10", ips)
	}
}

func TestRouterLookupIPAddrDedupScopesByUpstream(t *testing.T) {
	skipIfNoSocketMark(t)
	addr1, got1, release1, stop1 := startBlockingDNSUDPServer(t, netip.MustParseAddr("203.0.113.11"))
	defer stop1()
	addr2, got2, release2, stop2 := startBlockingDNSUDPServer(t, netip.MustParseAddr("198.51.100.11"))
	defer stop2()

	router := newTestLookupRouter(t,
		fmt.Sprintf("up1:udp://%s", addr1),
		fmt.Sprintf("up2:udp://%s", addr2),
	)

	type lookupResult struct {
		ips []net.IPAddr
		err error
	}
	result1Ch := make(chan lookupResult, 1)
	result2Ch := make(chan lookupResult, 1)

	go func() {
		ips, err := router.LookupIPAddr(context.Background(), "up1", "tcp", "proxy.example.com")
		result1Ch <- lookupResult{ips: ips, err: err}
	}()

	select {
	case <-got1:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for first upstream query")
	}

	go func() {
		ips, err := router.LookupIPAddr(context.Background(), "up2", "tcp", "proxy.example.com")
		result2Ch <- lookupResult{ips: ips, err: err}
	}()

	select {
	case <-got2:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for second upstream query")
	}

	close(release1)
	close(release2)

	result1 := <-result1Ch
	if result1.err != nil {
		t.Fatalf("LookupIPAddr(up1) error = %v", result1.err)
	}
	if len(result1.ips) != 1 || !result1.ips[0].IP.Equal(net.IPv4(203, 0, 113, 11)) {
		t.Fatalf("LookupIPAddr(up1) = %v, want 203.0.113.11", result1.ips)
	}

	result2 := <-result2Ch
	if result2.err != nil {
		t.Fatalf("LookupIPAddr(up2) error = %v", result2.err)
	}
	if len(result2.ips) != 1 || !result2.ips[0].IP.Equal(net.IPv4(198, 51, 100, 11)) {
		t.Fatalf("LookupIPAddr(up2) = %v, want 198.51.100.11", result2.ips)
	}
}

func TestRouterLookupIPAddrDedupKeepsFollowerAliveWhenLeaderTimesOut(t *testing.T) {
	skipIfNoSocketMark(t)
	addr, gotQuery, release, stop := startBlockingDNSUDPServer(t, netip.MustParseAddr("203.0.113.12"))
	defer stop()

	router := newTestLookupRouter(t, fmt.Sprintf("up1:udp://%s", addr))

	type lookupResult struct {
		ips []net.IPAddr
		err error
	}
	leaderResultCh := make(chan lookupResult, 1)
	followerResultCh := make(chan lookupResult, 1)

	leaderCtx, leaderCancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer leaderCancel()

	go func() {
		ips, err := router.LookupIPAddr(leaderCtx, "up1", "tcp", "proxy.example.com")
		leaderResultCh <- lookupResult{ips: ips, err: err}
	}()

	select {
	case <-gotQuery:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for shared upstream query")
	}

	go func() {
		ips, err := router.LookupIPAddr(context.Background(), "up1", "tcp", "proxy.example.com")
		followerResultCh <- lookupResult{ips: ips, err: err}
	}()

	time.Sleep(40 * time.Millisecond)
	close(release)

	leaderResult := <-leaderResultCh
	if leaderResult.err == nil || !isContextDeadlineExceeded(leaderResult.err) {
		t.Fatalf("leader error = %v, want context deadline exceeded", leaderResult.err)
	}

	followerResult := <-followerResultCh
	if followerResult.err != nil {
		t.Fatalf("follower LookupIPAddr() error = %v", followerResult.err)
	}
	if len(followerResult.ips) != 1 || !followerResult.ips[0].IP.Equal(net.IPv4(203, 0, 113, 12)) {
		t.Fatalf("follower LookupIPAddr() = %v, want 203.0.113.12", followerResult.ips)
	}
}

func TestRouterLookupIPAddrDedupLetsFollowerCancelIndependently(t *testing.T) {
	skipIfNoSocketMark(t)
	addr, gotQuery, release, stop := startBlockingDNSUDPServer(t, netip.MustParseAddr("203.0.113.13"))
	defer stop()

	router := newTestLookupRouter(t, fmt.Sprintf("up1:udp://%s", addr))

	type lookupResult struct {
		ips []net.IPAddr
		err error
	}
	leaderResultCh := make(chan lookupResult, 1)

	go func() {
		ips, err := router.LookupIPAddr(context.Background(), "up1", "tcp", "proxy.example.com")
		leaderResultCh <- lookupResult{ips: ips, err: err}
	}()

	select {
	case <-gotQuery:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for shared upstream query")
	}

	followerCtx, followerCancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer followerCancel()

	followerDone := make(chan error, 1)
	go func() {
		_, err := router.LookupIPAddr(followerCtx, "up1", "tcp", "proxy.example.com")
		followerDone <- err
	}()

	select {
	case err := <-followerDone:
		if err == nil || !isContextDeadlineExceeded(err) {
			t.Fatalf("follower error = %v, want context deadline exceeded", err)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("follower lookup did not respect its own context deadline")
	}

	close(release)

	leaderResult := <-leaderResultCh
	if leaderResult.err != nil {
		t.Fatalf("leader LookupIPAddr() error = %v", leaderResult.err)
	}
	if len(leaderResult.ips) != 1 || !leaderResult.ips[0].IP.Equal(net.IPv4(203, 0, 113, 13)) {
		t.Fatalf("leader LookupIPAddr() = %v, want 203.0.113.13", leaderResult.ips)
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
				Rules:    rules,
				Fallback: "subdns",
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

func newTestLookupRouter(t *testing.T, upstreams ...string) *Router {
	t.Helper()
	if len(upstreams) == 0 {
		t.Fatal("expected at least one upstream")
	}
	firstTag, _ := common.GetTagFromLinkLikePlaintext(upstreams[0])
	rawUpstreams := make([]config.KeyableString, 0, len(upstreams))
	for _, upstream := range upstreams {
		rawUpstreams = append(rawUpstreams, config.KeyableString(upstream))
	}

	router, err := New(logrus.New(), &config.Global{}, &config.Dns{
		Upstream: rawUpstreams,
		Routing: config.DnsRouting{
			Request: config.DnsRequestRouting{
				Rules: []*config_parser.RoutingRule{
					testInternalRule(firstTag, testInternalFunction("qname", testInternalParam("suffix", "never-match.invalid"))),
				},
				Fallback: firstTag,
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

type stubDialer struct {
	lookupResult  []net.IPAddr
	lookupErr     error
	lookupCalls   int
	lookupNetwork string
	lookupHost    string
}

func (d *stubDialer) DialContext(_ context.Context, _, _ string) (netproxy.Conn, error) {
	return nil, fmt.Errorf("unexpected dial")
}

func (d *stubDialer) LookupIPAddr(_ context.Context, network, host string) ([]net.IPAddr, error) {
	d.lookupCalls++
	d.lookupNetwork = network
	d.lookupHost = host
	if d.lookupErr != nil {
		return nil, d.lookupErr
	}
	return d.lookupResult, nil
}

func writeTestGeoSite(t *testing.T, path string, code string, domain string) {
	t.Helper()

	data, err := proto.Marshal(&geodata.GeoSiteList{Entry: []*geodata.GeoSite{{
		CountryCode: code,
		Domain: []*geodata.Domain{{
			Type:  geodata.Domain_RootDomain,
			Value: domain,
		}},
	}}})
	if err != nil {
		t.Fatalf("proto.Marshal() error = %v", err)
	}
	if err = os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
}

// skipIfNoSocketMark skips the test if the process lacks permission to set
// SO_MARK on sockets (e.g. CI containers without CAP_NET_ADMIN).
func skipIfNoSocketMark(t *testing.T) {
	t.Helper()
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		t.Skipf("skipping: cannot create socket: %v", err)
	}
	defer func() { _ = syscall.Close(fd) }()
	err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_MARK, 0)
	if err != nil {
		t.Skipf("skipping: SO_MARK not permitted (need CAP_NET_ADMIN): %v", err)
	}
}

func startTestDNSUDPServer(t *testing.T, addr netip.Addr) (string, func()) {
	return startTestDNSUDPServerWithResponse(t, func(question dnsmessage.Question) []dnsmessage.RR {
		if question.Qtype != dnsmessage.TypeA {
			return nil
		}
		return []dnsmessage.RR{&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{Name: question.Name, Rrtype: dnsmessage.TypeA, Class: dnsmessage.ClassINET, Ttl: 60},
			A:   addr.AsSlice(),
		}}
	})
}

func startTestEmptyDNSUDPServer(t *testing.T) (string, func()) {
	return startTestDNSUDPServerWithResponse(t, func(question dnsmessage.Question) []dnsmessage.RR {
		return nil
	})
}

func startTestDNSUDPServerWithResponse(t *testing.T, answerFunc func(dnsmessage.Question) []dnsmessage.RR) (string, func()) {
	t.Helper()

	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 2048)
		for {
			n, remoteAddr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var req dnsmessage.Msg
			if err = req.Unpack(buf[:n]); err != nil || len(req.Question) == 0 {
				continue
			}
			resp := dnsmessage.Msg{MsgHdr: dnsmessage.MsgHdr{Id: req.Id, Response: true, RecursionAvailable: true}, Question: req.Question}
			resp.Answer = append(resp.Answer, answerFunc(req.Question[0])...)
			wire, packErr := resp.Pack()
			if packErr != nil {
				continue
			}
			_, _ = pc.WriteTo(wire, remoteAddr)
		}
	}()
	return pc.LocalAddr().String(), func() {
		_ = pc.Close()
		<-done
	}
}

func startBlockingDNSUDPServer(t *testing.T, addr netip.Addr) (string, <-chan struct{}, chan struct{}, func()) {
	t.Helper()

	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	gotQuery := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 2048)
		firstQuery := true
		for {
			n, remoteAddr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var req dnsmessage.Msg
			if err = req.Unpack(buf[:n]); err != nil || len(req.Question) == 0 {
				continue
			}
			if firstQuery {
				firstQuery = false
				close(gotQuery)
			}
			<-release
			resp := dnsmessage.Msg{MsgHdr: dnsmessage.MsgHdr{Id: req.Id, Response: true, RecursionAvailable: true}, Question: req.Question}
			if req.Question[0].Qtype == dnsmessage.TypeA {
				resp.Answer = append(resp.Answer, &dnsmessage.A{
					Hdr: dnsmessage.RR_Header{Name: req.Question[0].Name, Rrtype: dnsmessage.TypeA, Class: dnsmessage.ClassINET, Ttl: 60},
					A:   addr.AsSlice(),
				})
			}
			wire, packErr := resp.Pack()
			if packErr != nil {
				continue
			}
			_, _ = pc.WriteTo(wire, remoteAddr)
		}
	}()
	return pc.LocalAddr().String(), gotQuery, release, func() {
		select {
		case <-release:
		default:
			close(release)
		}
		_ = pc.Close()
		<-done
	}
}

func isContextDeadlineExceeded(err error) bool {
	return errors.Is(err, context.DeadlineExceeded)
}
