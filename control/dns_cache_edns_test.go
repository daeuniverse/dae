/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"fmt"
	"io"
	"sync/atomic"
	"testing"
	"time"

	componentdns "github.com/daeuniverse/dae/component/dns"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func TestDNSCachePreservesEDNSMetadata(t *testing.T) {
	for _, ttl := range []uint32{300, 86400} {
		t.Run(fmt.Sprint(ttl), func(t *testing.T) {
			logger := logrus.New()
			logger.SetOutput(io.Discard)
			routing := newPhase0NamedUpstreamRouting(t, logger, "u", "192.0.2.11:53")
			response := dnsAResponseMsg(phase0NamedUpstreamScopeQName, "198.51.100.11")
			response.Answer[0].Header().Ttl = ttl
			response.SetEdns0(1232, true)
			opt := response.IsEdns0()
			opt.SetZ(0x0040)
			opt.Option = []dnsmessage.EDNS0{&dnsmessage.EDNS0_LOCAL{Code: 65001, Data: []byte{1, 2, 3}}}
			extra, err := dnsmessage.NewRR("extra.scope.test. 60 IN TXT \"metadata\"")
			require.NoError(t, err)
			response.Extra = append(response.Extra, extra)
			wire, err := response.Pack()
			require.NoError(t, err)
			require.NoError(t, response.Unpack(wire))
			opt = response.IsEdns0()

			var forwards atomic.Int32
			originalFactory := dnsForwarderFactory
			dnsForwarderFactory = func(*componentdns.Upstream, dialArgument, *logrus.Logger) (DnsForwarder, error) {
				return &stubDnsForwarder{forward: func(context.Context, []byte) (*dnsmessage.Msg, error) {
					forwards.Add(1)
					return response.Copy(), nil
				}}, nil
			}
			t.Cleanup(func() { dnsForwarderFactory = originalFactory })
			controller, err := NewDnsController(routing, phase0NamedUpstreamControllerOption(logger))
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, controller.Close()) })
			req := &udpRequest{routingResult: &bpfRoutingResult{}}

			for i, path := range []string{"miss", "hit"} {
				t.Run(path, func(t *testing.T) {
					got := resolvePhase0NamedUpstreamScope(t, controller, req, uint16(i+1))
					require.EqualValues(t, 1, forwards.Load())
					require.Equal(t, opt, got.IsEdns0(), "cache TTL must not overwrite EDNS version, flags or options")
				})
			}

			entries := controller.CloneCacheForReload()
			require.Len(t, entries, 1)
			for _, cache := range entries {
				require.Equal(t, opt, cache.Extra[0], "prepack must restore the stored OPT")
				t.Run("refresh", func(t *testing.T) {
					wire := cache.GetPackedResponseWithApproximateTTL(phase0NamedUpstreamScopeQName, dnsmessage.TypeA, cache.Deadline.Add(-30*time.Second))
					var got dnsmessage.Msg
					require.NoError(t, got.Unpack(wire))
					// The answer carries the real remaining lifetime: this pack
					// asks for the state 30s before the deadline, so the answer
					// leaves with 30 and ordinary records are aged the same way.
					require.EqualValues(t, 30, got.Answer[0].Header().Ttl, "an address answer leaves with its remaining lifetime, not a zero marker")
					require.EqualValues(t, 30, got.Extra[1].Header().Ttl, "ordinary additional records still receive the remaining TTL")
					require.Equal(t, opt, got.IsEdns0())
					require.Equal(t, opt, cache.Extra[0], "refresh must not mutate shared stored records")
				})
			}
		})
	}
}
