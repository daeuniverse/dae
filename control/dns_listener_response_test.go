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
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

type dnsTransportResponseWriter struct {
	captureResponseWriter
	addr net.Addr
}

func (w *dnsTransportResponseWriter) LocalAddr() net.Addr  { return w.addr }
func (w *dnsTransportResponseWriter) RemoteAddr() net.Addr { return w.addr }

func TestDNSListenerResponseSize(t *testing.T) {
	for _, cacheEnabled := range []bool{true, false} {
		for _, ednsSize := range []uint16{0, 128, 1232, 4096} {
			t.Run(fmt.Sprintf("cache=%t/edns=%d", cacheEnabled, ednsSize), func(t *testing.T) {
				logger := newDNSListenerTestLogger()
				routing := newPhase0NamedUpstreamRouting(t, logger, "u", "192.0.2.11:53")
				response := dnsAResponseMsg(phase0NamedUpstreamScopeQName, "198.51.100.11")
				for len(response.Answer) < 128 {
					response.Answer = append(response.Answer, dnsmessage.Copy(response.Answer[0]))
				}
				response.SetEdns0(4096, true)
				response.Compress = true
				fullWire, err := response.Pack()
				require.NoError(t, err)
				require.Greater(t, len(fullWire), 1232)
				require.Less(t, len(fullWire), 4096)

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
				plane := &ControlPlane{
					ctx:                    context.Background(),
					controlPlaneDNSRuntime: controlPlaneDNSRuntime{dnsController: controller},
				}
				listener, err := NewDNSListener(logger, "127.0.0.1:5353", plane)
				require.NoError(t, err)
				plane.dnsListener = listener
				handler := &dnsHandler{listener: listener, log: logger}

				for i, path := range []string{"udp_first", "udp_repeat", "tcp"} {
					t.Run(path, func(t *testing.T) {
						query := new(dnsmessage.Msg)
						query.SetQuestion(phase0NamedUpstreamScopeQName, dnsmessage.TypeA)
						query.Id = uint16(i + 1)
						if ednsSize != 0 {
							query.SetEdns0(ednsSize, true)
						}
						writer := &dnsTransportResponseWriter{addr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53000}}
						if path == "tcp" {
							writer.addr = &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53000}
						}
						handler.ServeDNS(writer, query)
						got := writer.Message()
						require.NotNil(t, got)
						require.Equal(t, query.Id, got.Id)
						require.Equal(t, query.Question, got.Question)
						require.Equal(t, dnsmessage.RcodeSuccess, got.Rcode)
						wire, err := got.Pack()
						require.NoError(t, err)
						var decoded dnsmessage.Msg
						require.NoError(t, decoded.Unpack(wire))
						if path == "tcp" {
							require.False(t, got.Truncated, "TCP must not use the request's UDP size limit")
							require.Len(t, got.Answer, len(response.Answer), "UDP must not truncate the shared cached payload")
						} else {
							limit := dnsUDPResponseSizeLimit(query)
							require.LessOrEqual(t, len(wire), limit)
							require.Equal(t, len(fullWire) > limit, got.Truncated)
							require.NotEmpty(t, got.Answer)
						}
						if cacheEnabled {
							require.EqualValues(t, 1, forwards.Load())
						} else {
							require.EqualValues(t, i+1, forwards.Load(), "storage failure must exercise the non-cache writer path")
						}
					})
				}
			})
		}
	}
}
