/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	"io"
	"testing"
	"time"

	componentdns "github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/control"
	"github.com/daeuniverse/dae/pkg/config_parser"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func TestReloadDNSCachePolicyBoundary(t *testing.T) {
	for _, tc := range []struct {
		name     string
		change   func(*config.Config)
		preserve bool
	}{
		{name: "unchanged", change: func(*config.Config) {}, preserve: true},
		{name: "non_dns_policy", change: func(c *config.Config) { c.Routing.Fallback = "block" }, preserve: true},
		{name: "listener_address", change: func(c *config.Config) { c.Dns.Bind = "127.0.0.1:5353" }, preserve: true},
		{name: "runtime_limits", change: func(c *config.Config) {
			c.Dns.MaxCacheSize = 1024
			c.Dns.OptimisticCacheTtl = 90
		}, preserve: true},
		{name: "response_fallback", change: func(c *config.Config) { c.Dns.Routing.Response.Fallback = "reject" }},
		{name: "response_rule", change: func(c *config.Config) {
			c.Dns.Routing.Response.Rules = []*config_parser.RoutingRule{{
				AndFunctions: []*config_parser.Function{{Name: "ip", Params: []*config_parser.Param{{Val: "198.51.100.11"}}}},
				Outbound:     config_parser.Function{Name: "reject"},
			}}
		}},
		{name: "ip_preference", change: func(c *config.Config) { c.Dns.IpVersionPrefer = 6 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			oldConf := &config.Config{Dns: config.Dns{
				Upstream: []config.KeyableString{"u:udp://192.0.2.11:53"},
				Routing: config.DnsRouting{
					Request:  config.DnsRequestRouting{Fallback: "u"},
					Response: config.DnsResponseRouting{Fallback: "accept"},
				},
				OptimisticCache: true,
			}}
			newConf := &config.Config{Dns: oldConf.Dns}
			tc.change(newConf)
			logger := logrus.New()
			logger.SetOutput(io.Discard)
			newController := func(conf *config.Config) (*control.DnsController, string) {
				t.Helper()
				routing, err := componentdns.New(&conf.Dns, &componentdns.NewOption{
					Logger:                logger,
					UpstreamReadyCallback: func(*componentdns.Upstream) error { return nil },
				})
				require.NoError(t, err)
				_, upstream, err := routing.RequestSelect(context.Background(), "reload-policy.test.", dnsmessage.TypeA)
				require.NoError(t, err)
				controller, err := control.NewDnsController(routing, &control.DnsControllerOption{
					Log: logger, IpVersionPrefer: conf.Dns.IpVersionPrefer, OptimisticCache: conf.Dns.OptimisticCache,
					NewCache: func(_ string, answers, ns, extra []dnsmessage.RR, deadline, originalDeadline time.Time) (*control.DnsCache, error) {
						return &control.DnsCache{Answer: answers, NS: ns, Extra: extra, Deadline: deadline, OriginalDeadline: originalDeadline}, nil
					},
				})
				require.NoError(t, err)
				t.Cleanup(func() { require.NoError(t, controller.Close()) })
				return controller, "reload-policy.test.1|upstream@" + upstream.String()
			}
			old, key := newController(oldConf)
			query := new(dnsmessage.Msg)
			query.SetQuestion("reload-policy.test.", dnsmessage.TypeA)
			response := new(dnsmessage.Msg)
			response.SetReply(query)
			answer, err := dnsmessage.NewRR("reload-policy.test. 300 IN A 198.51.100.11")
			require.NoError(t, err)
			response.Answer = []dnsmessage.RR{answer}
			require.NoError(t, old.NormalizeAndCacheDnsResp_(response, key))

			for _, staged := range []bool{false, true} {
				name := "snapshot"
				if staged {
					name = "staged"
				}
				t.Run(name, func(t *testing.T) {
					cloneCalls := 0
					candidate, rollback := cloneReloadDNSCaches(oldConf, newConf, staged, func() map[string]*control.DnsCache {
						cloneCalls++
						return old.CloneCacheForReload()
					})
					if staged && dnsConfigEqual(oldConf, newConf) {
						require.Nil(t, candidate)
						require.Nil(t, rollback)
						require.Zero(t, cloneCalls, "unchanged staged DNS must retain the streaming/shared-store path")
						return
					}

					next, nextKey := newController(newConf)
					require.Equal(t, key, nextKey, "the upstream cache scope stays unchanged")
					_, err := next.RestoreReloadCacheAndProject(candidate, nil, time.Now())
					require.NoError(t, err)
					wire, _ := next.LookupDnsRespCache_(query.Copy(), nextKey, false)
					if tc.preserve {
						require.NotEmpty(t, wire, "unchanged DNS policy must preserve the cached answer")
					} else {
						require.Empty(t, wire, "new DNS policy must not serve an old accepted answer")
					}

					if !staged {
						reverted, rollbackKey := newController(oldConf)
						_, err := reverted.RestoreReloadCacheAndProject(rollback, nil, time.Now())
						require.NoError(t, err)
						wire, _ = reverted.LookupDnsRespCache_(query.Copy(), rollbackKey, false)
						require.NotEmpty(t, wire, "legacy rollback must keep the old policy's cache")
					}
					wire, _ = old.LookupDnsRespCache_(query.Copy(), key, false)
					require.NotEmpty(t, wire, "preparing a candidate must not invalidate the active generation")
				})
			}
		})
	}
}
