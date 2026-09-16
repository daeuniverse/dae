/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"fmt"
	"io"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	componentdns "github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

const phase0NamedUpstreamScopeQName = "same-name.scope.test."

func TestPhase0DnsNamedUpstreamRoutesKeepDistinctCacheScopes(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	primaryRouting := newPhase0NamedUpstreamRouting(t, logger, "primary", "192.0.2.11:53")
	secondaryRouting := newPhase0NamedUpstreamRouting(t, logger, "secondary", "192.0.2.12:53")

	var primaryForwards atomic.Int32
	var secondaryForwards atomic.Int32
	originalFactory := dnsForwarderFactory
	dnsForwarderFactory = func(upstream *componentdns.Upstream, _ dialArgument, _ *logrus.Logger) (DnsForwarder, error) {
		switch upstream.Hostname {
		case "192.0.2.11":
			return &stubDnsForwarder{forward: func(context.Context, []byte) (*dnsmessage.Msg, error) {
				primaryForwards.Add(1)
				return dnsAResponseMsg(phase0NamedUpstreamScopeQName, "198.51.100.11"), nil
			}}, nil
		case "192.0.2.12":
			return &stubDnsForwarder{forward: func(context.Context, []byte) (*dnsmessage.Msg, error) {
				secondaryForwards.Add(1)
				return dnsAResponseMsg(phase0NamedUpstreamScopeQName, "198.51.100.12"), nil
			}}, nil
		default:
			return nil, fmt.Errorf("unexpected named DNS upstream %q", upstream)
		}
	}
	t.Cleanup(func() { dnsForwarderFactory = originalFactory })

	option := phase0NamedUpstreamControllerOption(logger)
	controller, err := NewDnsController(primaryRouting, option)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, controller.Close()) })

	req := &udpRequest{
		realSrc:       netip.MustParseAddrPort("192.0.2.70:53000"),
		realDst:       netip.MustParseAddrPort("192.0.2.53:53"),
		routingResult: &bpfRoutingResult{},
	}
	baseKey := controller.cacheKey(phase0NamedUpstreamScopeQName, dnsmessage.TypeA)

	primaryIndex, primaryUpstream, err := primaryRouting.RequestSelect(context.Background(), phase0NamedUpstreamScopeQName, dnsmessage.TypeA)
	require.NoError(t, err)
	require.NotNil(t, primaryUpstream)
	primaryKey := controller.responseCacheKey(baseKey, req, primaryIndex, primaryUpstream)

	first := resolvePhase0NamedUpstreamScope(t, controller, req, 0x6101)
	require.Equal(t, "198.51.100.11", dnsAnswerIPv4(t, first))
	require.EqualValues(t, 1, primaryForwards.Load())
	_, primaryCached := controller.dnsCache.Load(primaryKey)
	require.True(t, primaryCached, "primary route should populate its scoped cache key")

	require.NoError(t, controller.TryUpdateRuntime(option, secondaryRouting))
	secondaryIndex, secondaryUpstream, err := secondaryRouting.RequestSelect(context.Background(), phase0NamedUpstreamScopeQName, dnsmessage.TypeA)
	require.NoError(t, err)
	require.NotNil(t, secondaryUpstream)
	secondaryKey := controller.responseCacheKey(baseKey, req, secondaryIndex, secondaryUpstream)
	require.NotEqual(t, primaryKey, secondaryKey, "distinct named upstream routes need distinct cache keys")

	second := resolvePhase0NamedUpstreamScope(t, controller, req, 0x6102)
	require.Equal(t, "198.51.100.12", dnsAnswerIPv4(t, second))
	require.EqualValues(t, 1, primaryForwards.Load(), "secondary route must not serve the primary cache entry")
	require.EqualValues(t, 1, secondaryForwards.Load(), "secondary route should resolve once")
	_, secondaryCached := controller.dnsCache.Load(secondaryKey)
	require.True(t, secondaryCached, "secondary route should populate its scoped cache key")

	require.NoError(t, controller.TryUpdateRuntime(option, primaryRouting))
	third := resolvePhase0NamedUpstreamScope(t, controller, req, 0x6103)
	require.Equal(t, "198.51.100.11", dnsAnswerIPv4(t, third))
	require.EqualValues(t, 1, primaryForwards.Load(), "primary route should reuse only its own cache entry")
	require.EqualValues(t, 1, secondaryForwards.Load())
}

func newPhase0NamedUpstreamRouting(t *testing.T, logger *logrus.Logger, upstreamName, endpoint string) *componentdns.Dns {
	t.Helper()
	routing, err := componentdns.New(&config.Dns{
		Upstream: []config.KeyableString{config.KeyableString(upstreamName + ":udp://" + endpoint)},
		Routing: config.DnsRouting{
			Request: config.DnsRequestRouting{
				Rules: []*config_parser.RoutingRule{{
					AndFunctions: []*config_parser.Function{{
						Name: consts.Function_QName,
						Params: []*config_parser.Param{{
							Key: string(consts.RoutingDomainKey_Full),
							Val: "same-name.scope.test",
						}},
					}},
					Outbound: config_parser.Function{Name: upstreamName},
				}},
				Fallback: "asis",
			},
			Response: config.DnsResponseRouting{Fallback: "accept"},
		},
	}, &componentdns.NewOption{
		Logger: logger,
		UpstreamReadyCallback: func(*componentdns.Upstream) error {
			return nil
		},
	})
	require.NoError(t, err)
	return routing
}

func phase0NamedUpstreamControllerOption(logger *logrus.Logger) *DnsControllerOption {
	return &DnsControllerOption{
		Log:              logger,
		LifecycleContext: context.Background(),
		BestDialerChooser: func(_ context.Context, snapshot DnsRequestSnapshot, _ *componentdns.Upstream) (*dialArgument, error) {
			return &dialArgument{
				l4proto:    consts.L4ProtoStr_UDP,
				ipversion:  consts.IpVersionStr_4,
				bestTarget: snapshot.RealDst,
			}, nil
		},
		NewCache: func(_ string, answers, ns, extra []dnsmessage.RR, deadline, originalDeadline time.Time) (*DnsCache, error) {
			return &DnsCache{
				Answer:           answers,
				NS:               ns,
				Extra:            extra,
				Deadline:         deadline,
				OriginalDeadline: originalDeadline,
			}, nil
		},
	}
}

func resolvePhase0NamedUpstreamScope(t *testing.T, controller *DnsController, req *udpRequest, id uint16) *dnsmessage.Msg {
	t.Helper()
	query := new(dnsmessage.Msg)
	query.SetQuestion(phase0NamedUpstreamScopeQName, dnsmessage.TypeA)
	query.Id = id
	writer := &captureResponseWriter{}
	require.NoError(t, controller.HandleWithResponseWriter_(context.Background(), query, req, writer))
	response := writer.Message()
	require.NotNil(t, response)
	return response
}
