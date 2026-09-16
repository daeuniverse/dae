/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	stderrors "errors"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	componentdns "github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/dae/config"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func newDNSResponseUDPTestPair(t *testing.T) (*udpRequest, *net.UDPConn) {
	t.Helper()
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = server.Close() })
	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	oldPool := DefaultAnyfromPool
	pool := newTestAnyfromPoolWithoutJanitor()
	DefaultAnyfromPool = pool
	t.Cleanup(func() {
		pool.Reset()
		DefaultAnyfromPool = oldPool
	})
	from := server.LocalAddr().(*net.UDPAddr).AddrPort()
	to := client.LocalAddr().(*net.UDPAddr).AddrPort()
	af := &Anyfrom{UDPConn: server, ttl: AnyfromTimeout}
	af.RefreshTtl()
	key := anyfromPoolKey{lAddr: from}
	shard := pool.shardForKey(key)
	shard.mu.Lock()
	shard.pool[key] = af
	shard.mu.Unlock()
	return &udpRequest{realSrc: to, realDst: from, lConn: server, routingResult: &bpfRoutingResult{}, downloadRecord: func(int64) {}}, client
}

func TestDNSRejectResponseOversizedOPT(t *testing.T) {
	req, client := newDNSResponseUDPTestPair(t)
	logger := newDNSListenerTestLogger()
	routing, err := componentdns.New(&config.Dns{Routing: config.DnsRouting{
		Request:  config.DnsRequestRouting{Fallback: "reject"},
		Response: config.DnsResponseRouting{Fallback: "accept"},
	}}, &componentdns.NewOption{Logger: logger, UpstreamReadyCallback: func(*componentdns.Upstream) error { return nil }})
	require.NoError(t, err)
	controller, err := NewDnsController(routing, phase0NamedUpstreamControllerOption(logger))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, controller.Close()) })
	query := new(dnsmessage.Msg)
	query.SetQuestion(phase0NamedUpstreamScopeQName, dnsmessage.TypeA)
	query.SetEdns0(512, true)
	query.IsEdns0().Option = []dnsmessage.EDNS0{&dnsmessage.EDNS0_PADDING{Padding: make([]byte, 600)}}
	require.NoError(t, client.SetReadDeadline(time.Now().Add(time.Second)))
	require.NoError(t, controller.Handle_(context.Background(), query, req))
	buf := make([]byte, dnsmessage.MaxMsgSize)
	n, _, err := client.ReadFromUDPAddrPort(buf)
	require.NoError(t, err)
	var got dnsmessage.Msg
	require.NoError(t, got.Unpack(buf[:n]))
	t.Logf("rejected UDP bytes=%d TC=%t", n, got.Truncated)
	require.LessOrEqual(t, n, dnsDefaultUDPSize)
	require.True(t, got.Truncated)
	require.Empty(t, got.Answer)
	require.NotNil(t, got.IsEdns0())
	require.True(t, got.IsEdns0().Do())
}

func TestDNSDialSendOversizedOPT(t *testing.T) {
	for _, size := range []uint16{0, 512, 1232} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			req, client := newDNSResponseUDPTestPair(t)

			logger := newDNSListenerTestLogger()
			routing := newPhase0NamedUpstreamRouting(t, logger, "u", "192.0.2.11:53")
			response := dnsAResponseMsg(phase0NamedUpstreamScopeQName, "198.51.100.11")
			response.SetEdns0(1232, true)
			response.IsEdns0().SetZ(0x0040)
			response.IsEdns0().Option = []dnsmessage.EDNS0{&dnsmessage.EDNS0_PADDING{Padding: make([]byte, 600)}}
			response.Compress = true
			wire, err := response.Pack()
			require.NoError(t, err)
			require.NoError(t, response.Unpack(wire))
			originalOPT := dnsmessage.Copy(response.IsEdns0()).(*dnsmessage.OPT)
			var forwards atomic.Int32
			originalFactory := dnsForwarderFactory
			dnsForwarderFactory = func(*componentdns.Upstream, dialArgument, *logrus.Logger) (DnsForwarder, error) {
				return &stubDnsForwarder{forward: func(context.Context, []byte) (*dnsmessage.Msg, error) {
					forwards.Add(1)
					return response.Copy(), nil
				}}, nil
			}
			t.Cleanup(func() { dnsForwarderFactory = originalFactory })
			stored := make(chan struct{}, 1)
			option := phase0NamedUpstreamControllerOption(logger)
			option.CacheAccessCallback = func(*DnsCache) error {
				select {
				case stored <- struct{}{}:
				default:
				}
				return nil
			}
			controller, err := NewDnsController(routing, option)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, controller.Close()) })
			query := new(dnsmessage.Msg)
			query.SetQuestion(phase0NamedUpstreamScopeQName, dnsmessage.TypeA)
			if size != 0 {
				query.SetEdns0(size, true)
			}
			queryWire, err := query.Pack()
			require.NoError(t, err)
			index, upstream, err := routing.RequestSelect(context.Background(), phase0NamedUpstreamScopeQName, dnsmessage.TypeA)
			require.NoError(t, err)
			cacheKey := controller.responseCacheKey(controller.cacheKey(phase0NamedUpstreamScopeQName, dnsmessage.TypeA), req, index, upstream)
			require.NoError(t, client.SetReadDeadline(time.Now().Add(time.Second)))
			require.NoError(t, controller.dialSend(context.Background(), req, queryWire, query.Id, upstream, nil, cacheKey))
			buf := make([]byte, dnsmessage.MaxMsgSize)
			n, source, err := client.ReadFromUDPAddrPort(buf)
			require.NoError(t, err)
			require.Equal(t, req.realDst, source)
			var got dnsmessage.Msg
			require.NoError(t, got.Unpack(buf[:n]))
			select {
			case <-stored:
			case <-time.After(time.Second):
				t.Fatal("asynchronous DNS cache was not populated")
			}

			tcp := &dnsTransportResponseWriter{addr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53000}}
			require.NoError(t, controller.HandleWithResponseWriter_(context.Background(), query.Copy(), req, tcp))
			full := tcp.Message()
			require.NotNil(t, full)
			require.False(t, full.Truncated)
			require.Len(t, full.Answer, 1)
			require.Equal(t, originalOPT, full.IsEdns0(), "async cache must retain the complete OPT for TCP")
			require.EqualValues(t, 1, forwards.Load(), "TCP must read the asynchronously stored answer")
			limit := dnsUDPResponseSizeLimit(query)
			t.Logf("UDP bytes=%d limit=%d TC=%t; cached TCP answers=%d OPT bytes=%d", n, limit, got.Truncated, len(full.Answer), dnsmessage.Len(full.IsEdns0()))
			require.LessOrEqual(t, n, limit)
			require.Equal(t, len(wire) > limit, got.Truncated)
			require.NotNil(t, got.IsEdns0())
			require.Equal(t, originalOPT.Hdr.Ttl, got.IsEdns0().Hdr.Ttl)
			if len(wire) <= limit {
				require.Equal(t, originalOPT, got.IsEdns0())
			}
		})
	}
}

func TestDNSResponseOversizedOPT(t *testing.T) {
	for _, tc := range []struct {
		name    string
		options []dnsmessage.EDNS0
	}{
		{name: "padding", options: []dnsmessage.EDNS0{&dnsmessage.EDNS0_PADDING{Padding: make([]byte, 600)}}},
		{name: "large_unknown", options: []dnsmessage.EDNS0{&dnsmessage.EDNS0_LOCAL{Code: 65001, Data: make([]byte, 1500)}}},
		{name: "multiple_options", options: []dnsmessage.EDNS0{
			&dnsmessage.EDNS0_LOCAL{Code: 65001, Data: make([]byte, 200)},
			&dnsmessage.EDNS0_LOCAL{Code: 65002, Data: make([]byte, 200)},
			&dnsmessage.EDNS0_LOCAL{Code: 65003, Data: make([]byte, 200)},
		}},
		{name: "normal_opt"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response := dnsAResponseMsg(phase0NamedUpstreamScopeQName, "198.51.100.11")
			response.SetEdns0(4096, true)
			responseOPT := response.IsEdns0()
			responseOPT.SetZ(0x0040)
			keep := &dnsmessage.EDNS0_LOCAL{Code: 65000, Data: []byte("keep")}
			responseOPT.Option = append(responseOPT.Option, tc.options...)
			responseOPT.Option = append(responseOPT.Option, keep)
			response.Compress = true
			fullWire, err := response.Pack()
			require.NoError(t, err)
			require.NoError(t, response.Unpack(fullWire))
			originalOPT := dnsmessage.Copy(response.IsEdns0()).(*dnsmessage.OPT)

			checkUDP := func(t *testing.T, got *dnsmessage.Msg, limit int) {
				t.Helper()
				wire, err := got.Pack()
				require.NoError(t, err)
				require.LessOrEqual(t, len(wire), limit, "OPT must not exceed the UDP wire budget")
				var decoded dnsmessage.Msg
				require.NoError(t, decoded.Unpack(wire))
				require.Equal(t, len(fullWire) > limit, decoded.Truncated)
				opt := decoded.IsEdns0()
				require.NotNil(t, opt, "retain OPT metadata instead of dropping every OPT record")
				require.Equal(t, originalOPT.Hdr.Ttl, opt.Hdr.Ttl)
				require.Equal(t, originalOPT.UDPSize(), opt.UDPSize())
				require.Contains(t, opt.Option, keep, "an option that fits must survive an oversized sibling")
				if len(fullWire) <= limit {
					require.Equal(t, originalOPT, opt)
				}
			}

			t.Run("transparent_udp", func(t *testing.T) {
				for _, limit := range []int{512, 1232, 4096} {
					t.Run(fmt.Sprint(limit), func(t *testing.T) {
						got := new(dnsmessage.Msg)
						require.NoError(t, got.Unpack(truncateDNSResponse(fullWire, limit)))
						checkUDP(t, got, limit)
						unchanged, err := response.Pack()
						require.NoError(t, err)
						var original dnsmessage.Msg
						require.NoError(t, original.Unpack(unchanged))
						require.Equal(t, originalOPT, original.IsEdns0())
					})
				}
			})

			for _, cacheEnabled := range []bool{true, false} {
				t.Run(fmt.Sprintf("cache=%t", cacheEnabled), func(t *testing.T) {
					logger := newDNSListenerTestLogger()
					routing := newPhase0NamedUpstreamRouting(t, logger, "u", "192.0.2.11:53")
					var forwards atomic.Int32
					originalFactory := dnsForwarderFactory
					dnsForwarderFactory = func(*componentdns.Upstream, dialArgument, *logrus.Logger) (DnsForwarder, error) {
						return &stubDnsForwarder{forward: func(context.Context, []byte) (*dnsmessage.Msg, error) {
							forwards.Add(1)
							return response.Copy(), nil
						}}, nil
					}
					t.Cleanup(func() { dnsForwarderFactory = originalFactory })
					option := phase0NamedUpstreamControllerOption(logger)
					if !cacheEnabled {
						option.NewCache = func(string, []dnsmessage.RR, []dnsmessage.RR, []dnsmessage.RR, time.Time, time.Time) (*DnsCache, error) {
							return nil, stderrors.New("test cache storage failure")
						}
					}
					controller, err := NewDnsController(routing, option)
					require.NoError(t, err)
					t.Cleanup(func() { require.NoError(t, controller.Close()) })

					for i, request := range []struct {
						name string
						size uint16
						tcp  bool
					}{
						{name: "udp_large", size: 4096},
						{name: "udp_no_edns"},
						{name: "udp_small", size: 512},
						{name: "tcp_small", size: 512, tcp: true},
						{name: "udp_large_again", size: 4096},
					} {
						t.Run(request.name, func(t *testing.T) {
							query := new(dnsmessage.Msg)
							query.SetQuestion(phase0NamedUpstreamScopeQName, dnsmessage.TypeA)
							query.Id = uint16(i + 1)
							if request.size != 0 {
								query.SetEdns0(request.size, true)
							}
							writer := &dnsTransportResponseWriter{addr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53000}}
							if request.tcp {
								writer.addr = &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53000}
							}
							require.NoError(t, controller.HandleWithResponseWriter_(context.Background(), query, nil, wrapRuntimeTrackedDNSResponseWriter(writer, func(int64) {})))
							got := writer.Message()
							require.NotNil(t, got)
							require.Equal(t, query.Id, got.Id)
							if request.tcp {
								require.False(t, got.Truncated)
								require.Len(t, got.Answer, 1)
								require.Equal(t, originalOPT, got.IsEdns0(), "TCP must retain the entire cached OPT after small UDP replies")
							} else {
								checkUDP(t, got, dnsUDPResponseSizeLimit(query))
							}
							if cacheEnabled {
								require.EqualValues(t, 1, forwards.Load())
							} else {
								require.EqualValues(t, i+1, forwards.Load())
							}
						})
					}
				})
			}
		})
	}
}
