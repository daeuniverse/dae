/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	stderrors "errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	componentdns "github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// This file holds the Phase 0 DNS corpus fixtures. Each fixture focuses on
// one observable behaviour the refactor must preserve. Fixtures are pure
// data + factory functions; the driver lives in refactor_dns_corpus.go.

// udpCacheMissFixture pins the cold-cache UDP path: a fresh query that
// misses cache, contacts the upstream via the forwarder factory, and
// returns the canned answer. The canned answer IP encodes the dial target
// so the assertion catches any drift in dial-arg construction.
func udpCacheMissFixture() DnsCorpusFixture {
	var forwardCalls atomic.Int32
	return DnsCorpusFixture{
		Name:        "udp_cache_miss",
		Description: "Cold cache: UDP query misses cache, forwards upstream, returns canned answer",
		BuildConfig: func() *config.Dns {
			return &config.Dns{
				Routing: config.DnsRouting{
					Request:  config.DnsRequestRouting{Fallback: "asis"},
					Response: config.DnsResponseRouting{Fallback: "accept"},
				},
			}
		},
		ForwarderFactory: func(upstream *componentdns.Upstream, dialArg dialArgument, _ *logrus.Logger) (DnsForwarder, error) {
			return &stubDnsForwarder{forward: func(ctx context.Context, data []byte) (*dnsmessage.Msg, error) {
				forwardCalls.Add(1)
				return dnsAResponseMsg("cache-miss.test.", dialArg.bestTarget.Addr().String()), nil
			}}, nil
		},
		Cases: []DnsCorpusCase{
			{
				Name: "cold_query_forwards_and_returns_dialtarget_ip",
				Query: func() *dnsmessage.Msg {
					return corpusDnsQuery(0x1001, "cache-miss.test.", dnsmessage.TypeA)
				},
				Expected: DnsCorpusExpected{
					HasRcode:       true,
					Rcode:          dnsmessage.RcodeSuccess,
					HasAnswerCount: true,
					AnswerCount:    1,
					AnswerIPv4:     "1.1.1.1", // matches defaultUdpRequest realDst
					HasAnswerTTL:   true,
					// The delivered answer carries the real TTL: the upstream
					// value on the first response, the remaining lifetime on a
					// cache hit. dae tracks freshness in the entry deadline and
					// the stale window, not by zeroing the wire.
					AnswerTTLMin: 1,
					AnswerTTLMax: 60,
					WireHex:      "1001818000010001000000000a63616368652d6d697373047465737400000100010a63616368652d6d6973730474657374000001000100000000000401010101",
				},
				PostAssert: func(t *testing.T, _ *DnsController, _ *dnsmessage.Msg) {
					if got := forwardCalls.Load(); got != 1 {
						t.Fatalf("upstream forward calls = %d, want 1", got)
					}
				},
			},
		},
	}
}

// rejectBeforeCacheFixture pins the routing-level reject short-circuit. Even
// when a warm cache entry exists, a Reject routing rule MUST bypass cache and
// return an empty-answer response. This guards the doc comment in
// HandleWithResponseWriter_: "This ensures Reject rules are always applied,
// even if cache exists."
func rejectBeforeCacheFixture() DnsCorpusFixture {
	var forwardCalls atomic.Int32
	return DnsCorpusFixture{
		Name:        "reject_before_cache",
		Description: "Routing reject short-circuits even when a warm cache entry exists",
		BuildConfig: func() *config.Dns {
			return &config.Dns{
				Routing: config.DnsRouting{
					Request: config.DnsRequestRouting{
						Rules: []*config_parser.RoutingRule{{
							AndFunctions: []*config_parser.Function{{
								Name: consts.Function_QName,
								Params: []*config_parser.Param{{
									Key: string(consts.RoutingDomainKey_Full),
									Val: "reject.test",
								}},
							}},
							Outbound: config_parser.Function{Name: "reject"},
						}},
						Fallback: "asis",
					},
					Response: config.DnsResponseRouting{Fallback: "accept"},
				},
			}
		},
		ForwarderFactory: func(upstream *componentdns.Upstream, dialArg dialArgument, _ *logrus.Logger) (DnsForwarder, error) {
			return &stubDnsForwarder{forward: func(ctx context.Context, data []byte) (*dnsmessage.Msg, error) {
				forwardCalls.Add(1)
				return dnsAResponseMsg("reject.test.", "9.9.9.9"), nil
			}}, nil
		},
		Cases: []DnsCorpusCase{
			{
				Name: "reject_domain_returns_empty_answer_without_forward",
				PreState: func(t *testing.T, ctrl *DnsController) {
					// Warm the cache with a value that the legacy code would
					// return if reject did not short-circuit. If the refactor
					// ever serves this cached answer, the test catches it.
					key := ctrl.cacheKey("reject.test.", dnsmessage.TypeA)
					installCorpusCache(t, ctrl, key, "reject.test.", dnsmessage.TypeA, dnsAResponseMsg("reject.test.", "9.9.9.9").Answer, 300)
				},
				Query: func() *dnsmessage.Msg {
					return corpusDnsQuery(0x1003, "reject.test.", dnsmessage.TypeA)
				},
				Expected: DnsCorpusExpected{
					HasRcode:       true,
					Rcode:          dnsmessage.RcodeSuccess,
					HasAnswerCount: true,
					AnswerCount:    0,
					WireHex:        "1003818000010000000000000672656a65637404746573740000010001",
				},
				PostAssert: func(t *testing.T, _ *DnsController, _ *dnsmessage.Msg) {
					if got := forwardCalls.Load(); got != 0 {
						t.Fatalf("upstream forward calls = %d, want 0", got)
					}
				},
			},
		},
	}
}

// udpCacheHitFixture pins the warm-cache UDP path: a query whose cache key is
// already populated returns immediately without invoking the forwarder. The
// canned warm-cache IP differs from anything the forwarder would return so a
// regression that bypasses cache is observable.
func udpCacheHitFixture() DnsCorpusFixture {
	var forwardCalls atomic.Int32
	return DnsCorpusFixture{
		Name:        "udp_cache_hit",
		Description: "Warm cache: cached answer is served without contacting upstream",
		BuildConfig: func() *config.Dns {
			return &config.Dns{
				Routing: config.DnsRouting{
					Request:  config.DnsRequestRouting{Fallback: "asis"},
					Response: config.DnsResponseRouting{Fallback: "accept"},
				},
			}
		},
		ForwarderFactory: func(upstream *componentdns.Upstream, dialArg dialArgument, _ *logrus.Logger) (DnsForwarder, error) {
			return &stubDnsForwarder{forward: func(ctx context.Context, data []byte) (*dnsmessage.Msg, error) {
				forwardCalls.Add(1)
				return dnsAResponseMsg("cache-hit.test.", "203.0.113.99"), nil
			}}, nil
		},
		Cases: []DnsCorpusCase{
			{
				Name: "warm_cache_returns_cached_ip",
				PreState: func(t *testing.T, ctrl *DnsController) {
					req := defaultUdpRequest()
					baseKey := ctrl.cacheKey("cache-hit.test.", dnsmessage.TypeA)
					cacheKey := ctrl.responseCacheKey(
						baseKey, req,
						consts.DnsRequestOutboundIndex_AsIs, nil,
					)
					installCorpusCache(t, ctrl, cacheKey, "cache-hit.test.", dnsmessage.TypeA, dnsAResponseMsg("cache-hit.test.", "203.0.113.42").Answer, 300)
				},
				Query: func() *dnsmessage.Msg {
					return corpusDnsQuery(0x1002, "cache-hit.test.", dnsmessage.TypeA)
				},
				Expected: DnsCorpusExpected{
					HasRcode:       true,
					Rcode:          dnsmessage.RcodeSuccess,
					HasAnswerCount: true,
					AnswerCount:    1,
					AnswerIPv4:     "203.0.113.42", // the cached IP, not the factory IP
					HasAnswerTTL:   true,
					AnswerTTLMin:   300,
					AnswerTTLMax:   300,
					WireHex:        "1002818000010001000000000963616368652d686974047465737400000100010963616368652d68697404746573740000010001000000000004cb00712a",
				},
				PostAssert: func(t *testing.T, _ *DnsController, _ *dnsmessage.Msg) {
					if got := forwardCalls.Load(); got != 0 {
						t.Fatalf("upstream forward calls = %d, want 0", got)
					}
				},
			},
		},
	}
}

// udpCacheHitAAAAFixture pins the warm-cache IPv6 path. Keeping this as a
// separate fixture makes the qtype and cache-key family explicit in the
// legacy-vs-pipeline differential rather than relying on an A-only cache case.
func udpCacheHitAAAAFixture() DnsCorpusFixture {
	var forwardCalls atomic.Int32
	return DnsCorpusFixture{
		Name:        "udp_cache_hit_aaaa",
		Description: "Warm AAAA cache: cached IPv6 answer is served without contacting upstream",
		BuildConfig: func() *config.Dns {
			return &config.Dns{
				Routing: config.DnsRouting{
					Request:  config.DnsRequestRouting{Fallback: "asis"},
					Response: config.DnsResponseRouting{Fallback: "accept"},
				},
			}
		},
		ForwarderFactory: func(upstream *componentdns.Upstream, dialArg dialArgument, _ *logrus.Logger) (DnsForwarder, error) {
			return &stubDnsForwarder{forward: func(ctx context.Context, data []byte) (*dnsmessage.Msg, error) {
				forwardCalls.Add(1)
				return dnsAAAAResponseMsg("aaaa-cache.test.", "2001:db8::99"), nil
			}}, nil
		},
		Cases: []DnsCorpusCase{
			{
				Name: "warm_aaaa_cache_returns_cached_ipv6",
				PreState: func(t *testing.T, ctrl *DnsController) {
					req := defaultUdpRequest()
					baseKey := ctrl.cacheKey("aaaa-cache.test.", dnsmessage.TypeAAAA)
					cacheKey := ctrl.responseCacheKey(
						baseKey, req,
						consts.DnsRequestOutboundIndex_AsIs, nil,
					)
					installCorpusCache(t, ctrl, cacheKey, "aaaa-cache.test.", dnsmessage.TypeAAAA,
						dnsAAAAResponseMsg("aaaa-cache.test.", "2001:db8::42").Answer, 300)
				},
				Query: func() *dnsmessage.Msg {
					return corpusDnsQuery(0x1006, "aaaa-cache.test.", dnsmessage.TypeAAAA)
				},
				Expected: DnsCorpusExpected{
					HasRcode:       true,
					Rcode:          dnsmessage.RcodeSuccess,
					HasAnswerCount: true,
					AnswerCount:    1,
					AnswerIPv6:     "2001:db8::42",
					HasAnswerTTL:   true,
					AnswerTTLMin:   300,
					AnswerTTLMax:   300,
					WireHex:        "1006818000010001000000000a616161612d6361636865047465737400001c00010a616161612d6361636865047465737400001c000100000000001020010db8000000000000000000000042",
				},
				PostAssert: func(t *testing.T, _ *DnsController, _ *dnsmessage.Msg) {
					if got := forwardCalls.Load(); got != 0 {
						t.Fatalf("upstream forward calls = %d, want 0", got)
					}
				},
			},
		},
	}
}

// negativeResponseFixture pins the upstream negative-response boundary. A
// successful transport carrying NXDOMAIN must still be delivered to the
// caller, but it must not become a positive address cache entry that hides a
// later retry.
func negativeResponseFixture() DnsCorpusFixture {
	var forwardCalls atomic.Int32
	return DnsCorpusFixture{
		Name:        "negative_upstream_response",
		Description: "NXDOMAIN is delivered and is not stored as an address cache entry",
		BuildConfig: func() *config.Dns {
			return &config.Dns{
				Routing: config.DnsRouting{
					Request:  config.DnsRequestRouting{Fallback: "asis"},
					Response: config.DnsResponseRouting{Fallback: "accept"},
				},
			}
		},
		ForwarderFactory: func(upstream *componentdns.Upstream, dialArg dialArgument, _ *logrus.Logger) (DnsForwarder, error) {
			return &stubDnsForwarder{forward: func(context.Context, []byte) (*dnsmessage.Msg, error) {
				forwardCalls.Add(1)
				return dnsNegativeResponseMsg("negative.test."), nil
			}}, nil
		},
		Cases: []DnsCorpusCase{
			{
				Name: "nxdomain_is_delivered",
				Query: func() *dnsmessage.Msg {
					return corpusDnsQuery(0x1007, "negative.test.", dnsmessage.TypeA)
				},
				Expected: DnsCorpusExpected{
					HasRcode:       true,
					Rcode:          dnsmessage.RcodeNameError,
					HasAnswerCount: true,
					AnswerCount:    0,
					WireHex:        "100781030001000000000000086e6567617469766504746573740000010001",
				},
				PostAssert: func(t *testing.T, _ *DnsController, _ *dnsmessage.Msg) {
					if got := forwardCalls.Load(); got != 1 {
						t.Fatalf("upstream forward calls = %d, want 1", got)
					}
				},
			},
			{
				Name: "nxdomain_is_not_reused_as_positive_cache",
				Query: func() *dnsmessage.Msg {
					return corpusDnsQuery(0x1008, "negative.test.", dnsmessage.TypeA)
				},
				Expected: DnsCorpusExpected{
					HasRcode:       true,
					Rcode:          dnsmessage.RcodeNameError,
					HasAnswerCount: true,
					AnswerCount:    0,
					WireHex:        "100881030001000000000000086e6567617469766504746573740000010001",
				},
				PostAssert: func(t *testing.T, _ *DnsController, _ *dnsmessage.Msg) {
					if got := forwardCalls.Load(); got != 2 {
						t.Fatalf("upstream forward calls = %d, want 2", got)
					}
				},
			},
		},
	}
}

// udpCacheStaleOptimisticFixture pins the optimistic-refresh path: when a
// cached entry is past its freshness window but still within its TTL cap,
// the controller serves the stale answer synchronously while triggering a
// background refresh. The observable contract is: caller sees the stale IP
// immediately and does not wait for refresh.
func udpCacheStaleOptimisticFixture() DnsCorpusFixture {
	var forwardCalls atomic.Int32
	return DnsCorpusFixture{
		Name:        "udp_cache_stale_optimistic",
		Description: "Stale-but-not-expired cache serves stale IP immediately; background refresh is async",
		BuildConfig: func() *config.Dns {
			return &config.Dns{
				Routing: config.DnsRouting{
					Request:  config.DnsRequestRouting{Fallback: "asis"},
					Response: config.DnsResponseRouting{Fallback: "accept"},
				},
			}
		},
		ForwarderFactory: func(upstream *componentdns.Upstream, dialArg dialArgument, _ *logrus.Logger) (DnsForwarder, error) {
			return &stubDnsForwarder{forward: func(ctx context.Context, data []byte) (*dnsmessage.Msg, error) {
				forwardCalls.Add(1)
				return dnsAResponseMsg("stale.test.", "203.0.113.240"), nil
			}}, nil
		},
		Cases: []DnsCorpusCase{
			{
				Name: "stale_entry_serves_old_ip",
				PreState: func(t *testing.T, ctrl *DnsController) {
					req := defaultUdpRequest()
					baseKey := ctrl.cacheKey("stale.test.", dnsmessage.TypeA)
					cacheKey := ctrl.responseCacheKey(
						baseKey, req,
						consts.DnsRequestOutboundIndex_AsIs, nil,
					)
					if err := ctrl.UpdateDnsCacheTtlWithKey(
						cacheKey, "stale.test.", dnsmessage.TypeA,
						dnsAResponseMsg("stale.test.", "203.0.113.7").Answer,
						nil, nil, 60,
					); err != nil {
						t.Fatalf("UpdateDnsCacheTtlWithKey error = %v", err)
					}
					cacheValue, ok := ctrl.dnsCache.Load(cacheKey)
					if !ok {
						t.Fatal("stale cache entry was not stored")
					}
					cache := cacheValue.(*DnsCache)
					expiredAt := time.Now().Add(-time.Second)
					cache.Deadline = expiredAt
					cache.deadlineNano.Store(expiredAt.UnixNano())
				},
				Query: func() *dnsmessage.Msg {
					return corpusDnsQuery(0x1004, "stale.test.", dnsmessage.TypeA)
				},
				Expected: DnsCorpusExpected{
					HasRcode:       true,
					Rcode:          dnsmessage.RcodeSuccess,
					HasAnswerCount: true,
					AnswerCount:    1,
					AnswerIPv4:     "203.0.113.7", // cached (possibly stale) IP
				},
				PostAssert: func(t *testing.T, _ *DnsController, _ *dnsmessage.Msg) {
					deadline := time.Now().Add(time.Second)
					for forwardCalls.Load() == 0 && time.Now().Before(deadline) {
						time.Sleep(10 * time.Millisecond)
					}
					if got := forwardCalls.Load(); got != 1 {
						t.Fatalf("background refresh forward calls = %d, want 1", got)
					}
				},
			},
		},
	}
}

// dnsCnameOnlyNodataMsg builds a NOERROR response whose answer section holds
// only a CNAME aliasing away from the requested A type: RFC 2308 §2.2 NODATA
// (with no SOA here, so it is also uncacheable per §5).
func dnsCnameOnlyNodataMsg(name, target string) *dnsmessage.Msg {
	msg := new(dnsmessage.Msg)
	msg.SetReply(&dnsmessage.Msg{})
	msg.SetQuestion(name, dnsmessage.TypeA)
	msg.Answer = []dnsmessage.RR{
		&dnsmessage.CNAME{
			Hdr: dnsmessage.RR_Header{
				Name:   dnsmessage.CanonicalName(name),
				Rrtype: dnsmessage.TypeCNAME,
				Class:  dnsmessage.ClassINET,
				Ttl:    60,
			},
			Target: dnsmessage.CanonicalName(target),
		},
	}
	return msg
}

// udpCacheStaleCnameNodataRefreshFixture pins RFC 8767 §4 supersession for an
// uncacheable negative refresh: a background refresh returning a CNAME-only
// NODATA without SOA cannot be stored (RFC 2308 §5), but it still disproves
// the expired positive, which must be evicted instead of remaining serveable
// for the rest of the stale window.
func udpCacheStaleCnameNodataRefreshFixture() DnsCorpusFixture {
	var forwardCalls atomic.Int32
	return DnsCorpusFixture{
		Name:        "udp_cache_stale_cname_nodata_refresh",
		Description: "CNAME-only NODATA refresh supersedes an expired positive even though the negative cannot be cached",
		BuildConfig: func() *config.Dns {
			return &config.Dns{
				Routing: config.DnsRouting{
					Request:  config.DnsRequestRouting{Fallback: "asis"},
					Response: config.DnsResponseRouting{Fallback: "accept"},
				},
			}
		},
		ForwarderFactory: func(upstream *componentdns.Upstream, dialArg dialArgument, _ *logrus.Logger) (DnsForwarder, error) {
			return &stubDnsForwarder{forward: func(ctx context.Context, data []byte) (*dnsmessage.Msg, error) {
				forwardCalls.Add(1)
				return dnsCnameOnlyNodataMsg("stale.test.", "gone.test."), nil
			}}, nil
		},
		Cases: []DnsCorpusCase{
			{
				Name: "cname_nodata_refresh_evicts_superseded_stale_entry",
				PreState: func(t *testing.T, ctrl *DnsController) {
					req := defaultUdpRequest()
					baseKey := ctrl.cacheKey("stale.test.", dnsmessage.TypeA)
					cacheKey := ctrl.responseCacheKey(
						baseKey, req,
						consts.DnsRequestOutboundIndex_AsIs, nil,
					)
					if err := ctrl.UpdateDnsCacheTtlWithKey(
						cacheKey, "stale.test.", dnsmessage.TypeA,
						dnsAResponseMsg("stale.test.", "203.0.113.7").Answer,
						nil, nil, 60,
					); err != nil {
						t.Fatalf("UpdateDnsCacheTtlWithKey error = %v", err)
					}
					cacheValue, ok := ctrl.dnsCache.Load(cacheKey)
					if !ok {
						t.Fatal("stale cache entry was not stored")
					}
					cache := cacheValue.(*DnsCache)
					expiredAt := time.Now().Add(-time.Second)
					cache.Deadline = expiredAt
					cache.deadlineNano.Store(expiredAt.UnixNano())
				},
				Query: func() *dnsmessage.Msg {
					return corpusDnsQuery(0x1004, "stale.test.", dnsmessage.TypeA)
				},
				Expected: DnsCorpusExpected{
					HasRcode:       true,
					Rcode:          dnsmessage.RcodeSuccess,
					HasAnswerCount: true,
					AnswerCount:    1,
					AnswerIPv4:     "203.0.113.7", // cached (possibly stale) IP
				},
				PostAssert: func(t *testing.T, ctrl *DnsController, _ *dnsmessage.Msg) {
					req := defaultUdpRequest()
					baseKey := ctrl.cacheKey("stale.test.", dnsmessage.TypeA)
					cacheKey := ctrl.responseCacheKey(
						baseKey, req,
						consts.DnsRequestOutboundIndex_AsIs, nil,
					)
					deadline := time.Now().Add(2 * time.Second)
					for time.Now().Before(deadline) {
						if forwardCalls.Load() >= 1 {
							if _, ok := ctrl.dnsCache.Load(cacheKey); !ok {
								return // refresh superseded and evicted the expired positive
							}
						}
						time.Sleep(10 * time.Millisecond)
					}
					if forwardCalls.Load() == 0 {
						t.Fatal("background refresh never forwarded")
					}
					t.Fatal("expired positive survived an accepted CNAME-only NODATA refresh")
				},
			},
		},
	}
}

// tcpUdpFallbackFixture pins the user-observable tcp+udp fallback path. A
// request selects the named upstream, its UDP attempt fails, and the same
// request succeeds over TCP. This covers the complete request routing and
// delivery path rather than only calling forwardWithFallback directly.
func tcpUdpFallbackFixture() DnsCorpusFixture {
	var udpCalls atomic.Int32
	var tcpCalls atomic.Int32
	return DnsCorpusFixture{
		Name:        "tcp_udp_fallback",
		Description: "Named tcp+udp upstream falls back from failed UDP to TCP",
		BuildConfig: func() *config.Dns {
			return &config.Dns{
				Upstream: []config.KeyableString{
					"fallback:tcp+udp://192.0.2.53:53",
				},
				Routing: config.DnsRouting{
					Request:  config.DnsRequestRouting{Fallback: "fallback"},
					Response: config.DnsResponseRouting{Fallback: "accept"},
				},
			}
		},
		BestDialerChooser: func(ctx context.Context, snapshot DnsRequestSnapshot, upstream *componentdns.Upstream) (*dialArgument, error) {
			switch upstream.Scheme {
			case componentdns.UpstreamScheme_TCP_UDP:
				return &dialArgument{
					l4proto:    consts.L4ProtoStr_UDP,
					ipversion:  consts.IpVersionStr_4,
					bestTarget: snapshot.RealDst,
				}, nil
			case componentdns.UpstreamScheme_TCP:
				return &dialArgument{
					l4proto:    consts.L4ProtoStr_TCP,
					ipversion:  consts.IpVersionStr_4,
					bestTarget: snapshot.RealDst,
				}, nil
			default:
				return nil, stderrors.New("unexpected upstream scheme")
			}
		},
		ForwarderFactory: func(upstream *componentdns.Upstream, dialArg dialArgument, _ *logrus.Logger) (DnsForwarder, error) {
			switch dialArg.l4proto {
			case consts.L4ProtoStr_UDP:
				udpCalls.Add(1)
				return &stubDnsForwarder{forward: func(context.Context, []byte) (*dnsmessage.Msg, error) {
					return nil, stderrors.New("udp transport failed")
				}}, nil
			case consts.L4ProtoStr_TCP:
				tcpCalls.Add(1)
				return &stubDnsForwarder{forward: func(context.Context, []byte) (*dnsmessage.Msg, error) {
					return dnsAResponseMsg("tcp-fallback.test.", "198.51.100.53"), nil
				}}, nil
			default:
				return nil, stderrors.New("unexpected transport")
			}
		},
		Cases: []DnsCorpusCase{
			{
				Name: "udp_failure_returns_tcp_answer",
				Query: func() *dnsmessage.Msg {
					return corpusDnsQuery(0x1005, "tcp-fallback.test.", dnsmessage.TypeA)
				},
				Expected: DnsCorpusExpected{
					HasRcode:       true,
					Rcode:          dnsmessage.RcodeSuccess,
					HasAnswerCount: true,
					AnswerCount:    1,
					AnswerIPv4:     "198.51.100.53",
					HasAnswerTTL:   true,
					// The delivered answer carries the real TTL: the upstream
					// value on the first response, the remaining lifetime on a
					// cache hit. dae tracks freshness in the entry deadline and
					// the stale window, not by zeroing the wire.
					AnswerTTLMin: 1,
					AnswerTTLMax: 60,
					WireHex:      "1005818000010001000000000c7463702d66616c6c6261636b047465737400000100010c7463702d66616c6c6261636b04746573740000010001000000000004c6336435",
				},
				PostAssert: func(t *testing.T, _ *DnsController, _ *dnsmessage.Msg) {
					if got := udpCalls.Load(); got != 1 {
						t.Fatalf("UDP forward calls = %d, want 1", got)
					}
					if got := tcpCalls.Load(); got != 1 {
						t.Fatalf("TCP forward calls = %d, want 1", got)
					}
				},
			},
		},
	}
}

// tcpUdpBlackholeFallbackFixture pins UDP black-hole fallback: the UDP
// attempt exhausts its full timeout budget without a response (silent packet
// loss), and the same request must still succeed over TCP. The TCP fallback
// gets a fresh per-attempt budget instead of inheriting the request context's
// shorter deadline, which previously expired before the fallback could run.
func tcpUdpBlackholeFallbackFixture() DnsCorpusFixture {
	return DnsCorpusFixture{
		Name:        "tcp_udp_blackhole_fallback",
		Description: "UDP black hole (silent drop) still reaches TCP fallback",
		BuildConfig: func() *config.Dns {
			return &config.Dns{
				Upstream: []config.KeyableString{
					"fallback:tcp+udp://192.0.2.53:53",
				},
				Routing: config.DnsRouting{
					Request:  config.DnsRequestRouting{Fallback: "fallback"},
					Response: config.DnsResponseRouting{Fallback: "accept"},
				},
			}
		},
		BestDialerChooser: func(ctx context.Context, snapshot DnsRequestSnapshot, upstream *componentdns.Upstream) (*dialArgument, error) {
			switch upstream.Scheme {
			case componentdns.UpstreamScheme_TCP_UDP:
				return &dialArgument{
					l4proto:    consts.L4ProtoStr_UDP,
					ipversion:  consts.IpVersionStr_4,
					bestTarget: snapshot.RealDst,
				}, nil
			case componentdns.UpstreamScheme_TCP:
				return &dialArgument{
					l4proto:    consts.L4ProtoStr_TCP,
					ipversion:  consts.IpVersionStr_4,
					bestTarget: snapshot.RealDst,
				}, nil
			default:
				return nil, stderrors.New("unexpected upstream scheme")
			}
		},
		ForwarderFactory: func(upstream *componentdns.Upstream, dialArg dialArgument, _ *logrus.Logger) (DnsForwarder, error) {
			switch dialArg.l4proto {
			case consts.L4ProtoStr_UDP:
				// Simulate a silent packet-loss black hole: block until the
				// attempt budget expires, returning no response.
				return &stubDnsForwarder{forward: func(ctx context.Context, _ []byte) (*dnsmessage.Msg, error) {
					<-ctx.Done()
					return nil, ctx.Err()
				}}, nil
			case consts.L4ProtoStr_TCP:
				return &stubDnsForwarder{forward: func(ctx context.Context, _ []byte) (*dnsmessage.Msg, error) {
					// Real transports fail immediately on an expired context;
					// the fallback only succeeds with a fresh per-attempt budget.
					if err := ctx.Err(); err != nil {
						return nil, err
					}
					return dnsAResponseMsg("tcp-fallback.test.", "198.51.100.53"), nil
				}}, nil
			default:
				return nil, stderrors.New("unexpected transport")
			}
		},
		Cases: []DnsCorpusCase{
			{
				Name: "udp_blackhole_recovers_via_tcp",
				Query: func() *dnsmessage.Msg {
					return corpusDnsQuery(0x1006, "tcp-fallback.test.", dnsmessage.TypeA)
				},
				Expected: DnsCorpusExpected{
					HasRcode:       true,
					Rcode:          dnsmessage.RcodeSuccess,
					HasAnswerCount: true,
					AnswerCount:    1,
					AnswerIPv4:     "198.51.100.53",
					HasAnswerTTL:   true,
					// The delivered answer carries the real TTL: the upstream
					// value on the first response, the remaining lifetime on a
					// cache hit. dae tracks freshness in the entry deadline and
					// the stale window, not by zeroing the wire.
					AnswerTTLMin: 1,
					AnswerTTLMax: 60,
					WireHex:      "1006818000010001000000000c7463702d66616c6c6261636b047465737400000100010c7463702d66616c6c6261636b04746573740000010001000000000004c6336435",
				},
			},
		},
	}
}

func dnsAAAAResponseMsg(name, address string) *dnsmessage.Msg {
	return &dnsmessage.Msg{
		MsgHdr: dnsmessage.MsgHdr{
			Response:           true,
			RecursionAvailable: true,
		},
		Question: []dnsmessage.Question{{Name: name, Qtype: dnsmessage.TypeAAAA, Qclass: dnsmessage.ClassINET}},
		Answer: []dnsmessage.RR{&dnsmessage.AAAA{
			Hdr:  dnsmessage.RR_Header{Name: name, Rrtype: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET, Ttl: 60},
			AAAA: net.ParseIP(address).To16(),
		}},
	}
}

func dnsNegativeResponseMsg(name string) *dnsmessage.Msg {
	msg := new(dnsmessage.Msg)
	msg.SetReply(&dnsmessage.Msg{})
	msg.SetQuestion(name, dnsmessage.TypeA)
	msg.Rcode = dnsmessage.RcodeNameError
	return msg
}
