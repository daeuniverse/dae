/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	componentdns "github.com/daeuniverse/dae/component/dns"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

// Exercise the production refresh path, stubbing only the upstream transport.
// A referral must preserve stale data without disabling subsequent refreshes.
func TestBackgroundRefreshResponseSemantics(t *testing.T) {
	for _, tc := range []struct {
		name    string
		rcode   int
		cname   bool
		ns      bool
		soa     bool
		outcome string
	}{
		{name: "ns_only_referral", ns: true, outcome: "keep"},
		{name: "cname_referral", cname: true, ns: true, outcome: "keep"},
		{name: "soa_nodata", soa: true, outcome: "replace"},
		{name: "soa_and_ns_nodata", soa: true, ns: true, outcome: "replace"},
		{name: "cname_soa_and_ns_nodata", cname: true, soa: true, ns: true, outcome: "replace"},
		{name: "empty_nodata_without_soa", outcome: "evict"},
		{name: "cname_nodata_without_soa", cname: true, outcome: "evict"},
		{name: "nxdomain", rcode: dnsmessage.RcodeNameError, outcome: "evict"},
		{name: "servfail", rcode: dnsmessage.RcodeServerFailure, outcome: "keep"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var forwardCalls atomic.Int32
			installCorpusDnsForwarderFactory(t, func(*componentdns.Upstream, dialArgument, *logrus.Logger) (DnsForwarder, error) {
				return &stubDnsForwarder{forward: func(_ context.Context, data []byte) (*dnsmessage.Msg, error) {
					query := new(dnsmessage.Msg)
					if err := query.Unpack(data); err != nil {
						return nil, err
					}
					response := new(dnsmessage.Msg)
					response.SetReply(query)
					response.Rcode = tc.rcode
					if tc.cname {
						response.Answer = []dnsmessage.RR{&dnsmessage.CNAME{
							Hdr:    dnsmessage.RR_Header{Name: query.Question[0].Name, Rrtype: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, Ttl: 60},
							Target: "target.example.com.",
						}}
					}
					if tc.ns {
						response.Ns = append(response.Ns, &dnsmessage.NS{
							Hdr: dnsmessage.RR_Header{Name: "example.com.", Rrtype: dnsmessage.TypeNS, Class: dnsmessage.ClassINET, Ttl: 300},
							Ns:  "ns.example.com.",
						})
					}
					if tc.soa {
						response.Ns = append(response.Ns, &dnsmessage.SOA{
							Hdr:    dnsmessage.RR_Header{Name: "example.com.", Rrtype: dnsmessage.TypeSOA, Class: dnsmessage.ClassINET, Ttl: 300},
							Ns:     "ns.example.com.",
							Mbox:   "hostmaster.example.com.",
							Minttl: 60,
						})
					}
					forwardCalls.Add(1)
					return response, nil
				}}, nil
			})

			ctrl := newSemanticsController(t)
			query := corpusDnsQuery(0x1234, "stale.example.com.", dnsmessage.TypeA)
			req := defaultUdpRequest()
			cacheKey := ctrl.responseCacheKey(ctrl.cacheKey(query.Question[0].Name, dnsmessage.TypeA), req, consts.DnsRequestOutboundIndex_AsIs, nil)
			positive := dnsAResponseMsg(query.Question[0].Name, "203.0.113.7")
			require.NoError(t, ctrl.UpdateDnsCacheTtlWithKey(cacheKey, query.Question[0].Name, dnsmessage.TypeA, positive.Answer, nil, nil, -1))
			stale := storedEntry(t, ctrl, cacheKey)
			deadline := stale.Deadline

			wire, refresh := ctrl.LookupDnsRespCache_(query.Copy(), cacheKey, false)
			require.NotEmpty(t, wire)
			require.True(t, refresh)
			require.True(t, stale.IsRefreshing())

			// Run the background worker synchronously so completion is certain
			// before checking its cache effects and refreshing flag cleanup.
			ctrl.backgroundRefresh(cacheKey, query, req, consts.DnsRequestOutboundIndex_AsIs, nil)
			require.EqualValues(t, 1, forwardCalls.Load())

			switch tc.outcome {
			case "keep":
				require.Same(t, stale, storedEntry(t, ctrl, cacheKey))
				require.Equal(t, deadline, stale.Deadline)
				require.False(t, stale.IsRefreshing())
				wire, refresh = ctrl.LookupDnsRespCache_(query.Copy(), cacheKey, false)
				require.True(t, refresh, "a retained stale answer must allow another refresh")
				replayed := new(dnsmessage.Msg)
				require.NoError(t, replayed.Unpack(wire))
				require.Len(t, replayed.Answer, 1)
				answer, ok := replayed.Answer[0].(*dnsmessage.A)
				require.True(t, ok)
				require.Equal(t, "203.0.113.7", answer.A.String())
				ctrl.backgroundRefresh(cacheKey, query, req, consts.DnsRequestOutboundIndex_AsIs, nil)
				require.EqualValues(t, 2, forwardCalls.Load())
				require.Same(t, stale, storedEntry(t, ctrl, cacheKey))
				require.False(t, stale.IsRefreshing())
			case "replace":
				entry := storedEntry(t, ctrl, cacheKey)
				require.NotSame(t, stale, entry)
				require.True(t, entry.Deadline.After(time.Now()))
				wire, refresh = ctrl.LookupDnsRespCache_(query.Copy(), cacheKey, false)
				require.False(t, refresh)
				replayed := new(dnsmessage.Msg)
				require.NoError(t, replayed.Unpack(wire))
				require.Equal(t, dnsmessage.RcodeSuccess, replayed.Rcode)
				require.NotNil(t, findAuthoritySoa(replayed))
				require.False(t, hasRelevantAnswer(replayed, query.Question[0]))
			case "evict":
				_, present := ctrl.dnsCache.Load(cacheKey)
				require.False(t, present)
				wire, refresh = ctrl.LookupDnsRespCache_(query.Copy(), cacheKey, false)
				require.Nil(t, wire)
				require.False(t, refresh)
			default:
				t.Fatalf("unknown outcome %q", tc.outcome)
			}
		})
	}
}
