/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/sirupsen/logrus"
)

func TestFlowRuleEvidence(t *testing.T) {
	port := func(outbound string, value string) *config_parser.RoutingRule {
		return traceRule([]*config_parser.Function{traceFunction(consts.Function_Port, false, value)}, outbound)
	}
	rules := []*config_parser.RoutingRule{
		port("proxy", "80"),
		port("proxy", "81"),
		traceRule([]*config_parser.Function{
			traceFunction(consts.Function_SourceIp, false, "192.0.2.2"),
			{Name: consts.Function_Domain, Params: []*config_parser.Param{{Key: "full", Val: "example.test"}}},
		}, "proxy"),
		port("must_rules", "443"),
		port("proxy", "443"),
		traceRule([]*config_parser.Function{traceFunction(consts.Function_SourceIp, false, "192.0.2.2")}, "direct"),
	}
	configured, fallback := snapshotConfiguredRules(rules, "direct")
	makePlane := func(t *testing.T, enabled bool, generation string) *ControlPlane {
		t.Helper()
		merge, origins := flowRuleOrigins(enabled)
		program, err := routing.NewNormalizedProgram(rules, "direct", &routing.AliasOptimizer{}, merge, &routing.DeduplicateParamsOptimizer{})
		if err != nil {
			t.Fatal(err)
		}
		var injected []routing.SniffPuntInjection
		program.Rules, injected = routing.InferSniffPunt(program.Rules)
		if len(injected) != 1 || len(program.Rules) != len(rules) {
			t.Fatalf("expected both a merge and an inferred punt, got %d rules, %d injections", len(program.Rules), len(injected))
		}
		builder, err := NewRoutingMatcherBuilderFromProgram(logrus.New(), program, map[string]uint8{
			"direct": uint8(consts.OutboundDirect),
			"proxy":  uint8(consts.OutboundUserDefinedMin),
		}, nil)
		if err != nil {
			t.Fatal(err)
		}
		matcher, err := builder.BuildUserspace()
		if err != nil {
			t.Fatal(err)
		}
		matcher.bindFlowRules(program, origins, configured, fallback, generation)
		return &ControlPlane{controlPlaneGenerationState: controlPlaneGenerationState{routingMatcher: matcher}}
	}
	previous := makePlane(t, true, "8")
	current := makePlane(t, true, "9")
	disabled := makePlane(t, false, "10")
	for _, c := range []struct {
		name, src, dst, domain string
		proto                  consts.L4ProtoType
		id, expression         string
		outbound               consts.OutboundIndex
		must                   bool
	}{
		{"merged", "192.0.2.2:1234", "198.18.0.2:81", "", consts.L4ProtoType_TCP, "", "", consts.OutboundUserDefinedMin, false},
		{"whitelist", "192.0.2.2:1234", "198.18.0.2:443", "example.test", consts.L4ProtoType_UDP, "traffic:2", configured[2].Expression, consts.OutboundUserDefinedMin, false},
		{"must-and-terminal", "192.0.2.2:1234", "198.18.0.2:443", "", consts.L4ProtoType_TCP, "traffic:4", configured[4].Expression, consts.OutboundUserDefinedMin, true},
		{"punt-then-direct", "192.0.2.2:1234", "198.18.0.2:9000", "", consts.L4ProtoType_UDP, "traffic:5", configured[5].Expression, consts.OutboundDirect, false},
		{"fallback", "192.0.2.3:1234", "198.18.0.2:9000", "", consts.L4ProtoType_UDP, "traffic:fallback", "fallback: direct", consts.OutboundDirect, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			src, dst := netip.MustParseAddrPort(c.src), netip.MustParseAddrPort(c.dst)
			var readers sync.WaitGroup
			for range 8 {
				readers.Go(func() {
					for _, candidate := range []struct {
						plane      *ControlPlane
						generation string
					}{{previous, "8"}, {current, "9"}, {disabled, ""}} {
						for range 20 {
							var evidence *flowRuleEvidence
							outbound, mark, must, err := candidate.plane.route(src, dst, c.domain, c.proto, nil, &evidence)
							if err != nil || outbound != c.outbound || mark != 0 || must != c.must {
								t.Errorf("route = %v/%d/%v/%v", outbound, mark, must, err)
								return
							}
							if c.id == "" || candidate.generation == "" {
								if evidence != nil {
									t.Errorf("unexpected evidence %+v", evidence)
								}
								continue
							}
							want := flowRuleEvidence{c.id, candidate.generation, c.expression}
							if evidence == nil || *evidence != want {
								t.Errorf("evidence = %+v, want %+v", evidence, want)
								return
							}
						}
					}
				})
			}
			readers.Wait()
		})
	}
}

func TestFlowRuleHistoryReleasesExpiredEvidence(t *testing.T) {
	manager := NewSessionManager(context.Background())
	now := time.Now()
	manager.appendFlowHistory(SessionFlowSnapshot{
		ID:   "old",
		rule: &flowRuleEvidence{id: "traffic:0", generation: "8", expression: "dport(443) -> proxy"},
	}, now)
	entry, ok := manager.FlowHistoryEntryByID("old")
	if !ok {
		t.Fatal("missing recorded flow")
	}
	if id, generation, _ := entry.RuleEvidence(); id != "traffic:0" || generation != "8" {
		t.Fatalf("retained evidence = %q/%q", id, generation)
	}
	manager.pruneFlowHistoryLocked(now.Add(FlowHistoryRetention + time.Second))
	if manager.flowHistoryLen != 0 || manager.flowHistory[0].rule != nil {
		t.Fatal("expired history retained rule evidence")
	}
}
