/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/dns"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

type stubDnsForwarder struct {
	forward func(ctx context.Context, data []byte) (*dnsmessage.Msg, error)
}

func (s *stubDnsForwarder) ForwardDNS(ctx context.Context, data []byte) (*dnsmessage.Msg, error) {
	if s.forward == nil {
		return nil, nil
	}
	return s.forward(ctx, data)
}

func (s *stubDnsForwarder) Close() error { return nil }

func TestDnsForwarder_TcpUdpFallback_UdpFailThenTcp(t *testing.T) {
	originalFactory := dnsForwarderFactory
	t.Cleanup(func() {
		dnsForwarderFactory = originalFactory
	})

	var udpCalls atomic.Int32
	var tcpCalls atomic.Int32
	var unavailableCalls atomic.Int32

	want := new(dnsmessage.Msg)
	want.SetReply(&dnsmessage.Msg{MsgHdr: dnsmessage.MsgHdr{Id: 1}})

	dnsForwarderFactory = func(upstream *dns.Upstream, dialArg dialArgument, _ *logrus.Logger) (DnsForwarder, error) {
		switch dialArg.l4proto {
		case consts.L4ProtoStr_UDP:
			udpCalls.Add(1)
			return &stubDnsForwarder{forward: func(ctx context.Context, data []byte) (*dnsmessage.Msg, error) {
				return nil, errors.New("udp path failed")
			}}, nil
		case consts.L4ProtoStr_TCP:
			tcpCalls.Add(1)
			return &stubDnsForwarder{forward: func(ctx context.Context, data []byte) (*dnsmessage.Msg, error) {
				return want, nil
			}}, nil
		default:
			return nil, errors.New("unexpected proto")
		}
	}

	ctrl := &DnsController{
		log: logrus.New(),
		bestDialerChooser: func(req *udpRequest, upstream *dns.Upstream) (*dialArgument, error) {
			switch upstream.Scheme {
			case dns.UpstreamScheme_TCP_UDP:
				return &dialArgument{l4proto: consts.L4ProtoStr_UDP}, nil
			case dns.UpstreamScheme_TCP:
				return &dialArgument{l4proto: consts.L4ProtoStr_TCP}, nil
			default:
				return nil, errors.New("unexpected scheme")
			}
		},
		timeoutExceedCallback: func(dialArg *dialArgument, err error) {
			unavailableCalls.Add(1)
		},
	}

	upstream := &dns.Upstream{Scheme: dns.UpstreamScheme_TCP_UDP, Hostname: "dns.example", Port: 53}
	primary := &dialArgument{l4proto: consts.L4ProtoStr_UDP}

	resp, usedDialArg, err := ctrl.forwardWithFallback(context.Background(), &udpRequest{}, upstream, primary, []byte{0, 1, 2, 3})
	require.NoError(t, err)
	require.Equal(t, consts.L4ProtoStr_TCP, usedDialArg.l4proto)
	require.Same(t, want, resp)
	require.EqualValues(t, 1, udpCalls.Load(), "UDP should be attempted first")
	require.EqualValues(t, 1, tcpCalls.Load(), "TCP fallback should be attempted once")
	require.EqualValues(t, 1, unavailableCalls.Load(), "UDP failure should report unavailable once")
}

func TestDnsForwarder_ReportUnavailable_IgnoresCanceled(t *testing.T) {
	originalFactory := dnsForwarderFactory
	t.Cleanup(func() {
		dnsForwarderFactory = originalFactory
	})

	var unavailableCalls atomic.Int32

	dnsForwarderFactory = func(upstream *dns.Upstream, dialArg dialArgument, _ *logrus.Logger) (DnsForwarder, error) {
		return &stubDnsForwarder{forward: func(ctx context.Context, data []byte) (*dnsmessage.Msg, error) {
			return nil, context.Canceled
		}}, nil
	}

	ctrl := &DnsController{
		timeoutExceedCallback: func(dialArg *dialArgument, err error) {
			unavailableCalls.Add(1)
		},
	}

	_, err := ctrl.forwardWithDialArg(context.Background(), &dns.Upstream{Scheme: dns.UpstreamScheme_UDP, Hostname: "dns.example", Port: 53}, &dialArgument{l4proto: consts.L4ProtoStr_UDP}, []byte{0, 1})
	require.ErrorIs(t, err, context.Canceled)
	require.EqualValues(t, 0, unavailableCalls.Load(), "context canceled should not poison dialer health")
}
