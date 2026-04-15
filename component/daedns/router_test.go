/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@daeuniverse.org>
 */

package daedns

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"syscall"
	"testing"

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

func TestRouterWrapNodeDialerUsesGeneralRequestRoutingFallback(t *testing.T) {
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
	wrapped, err := router.WrapNodeDialer(base, NodeMeta{Name: "test-node", Link: "ss://proxy.example.com:443"})
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
	ips, err := resolver.LookupIPAddr(context.Background(), "tcp", "proxy.example.com")
	if err != nil {
		t.Fatalf("LookupIPAddr() error = %v", err)
	}
	if len(ips) != 1 || !ips[0].IP.Equal(net.IPv4(203, 0, 113, 7)) {
		t.Fatalf("LookupIPAddr() = %v, want 203.0.113.7", ips)
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
			wrapped, err := router.WrapNodeDialer(base, NodeMeta{Name: "test-node", Link: "ss://proxy.invalid:443"})
			if err != nil {
				t.Fatalf("WrapNodeDialer() error = %v", err)
			}

			resolver, ok := wrapped.(interface {
				LookupIPAddr(context.Context, string, string) ([]net.IPAddr, error)
			})
			if !ok {
				t.Fatal("wrapped dialer does not expose LookupIPAddr")
			}
			ips, err := resolver.LookupIPAddr(context.Background(), "tcp", "proxy.invalid")
			if err != nil {
				t.Fatalf("LookupIPAddr() error = %v", err)
			}
			if base.lookupCalls != 1 {
				t.Fatalf("base lookup calls = %d, want 1", base.lookupCalls)
			}
			if base.lookupNetwork != "tcp" || base.lookupHost != "proxy.invalid" {
				t.Fatalf("base lookup = (%q, %q), want (%q, %q)", base.lookupNetwork, base.lookupHost, "tcp", "proxy.invalid")
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
	wrapped, err := router.WrapNodeDialer(base, NodeMeta{Name: "test-node", Link: "ss://proxy.example.com:443"})
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
	wrapped, err := router.WrapNodeDialer(base, NodeMeta{Name: "test-node", Link: "ss://proxy.example.com:443"})
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
	if len(ips) != 1 || !ips[0].IP.Equal(net.IPv4(203, 0, 113, 9)) {
		t.Fatalf("LookupIPAddr() = %v, want 203.0.113.9", ips)
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
	defer syscall.Close(fd)
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
