/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	stderrors "errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/dns"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

type countingDnsForwarder struct {
	closed atomic.Int32
}

func (c *countingDnsForwarder) ForwardDNS(ctx context.Context, data []byte) (*dnsmessage.Msg, error) {
	return &dnsmessage.Msg{}, nil
}

func (c *countingDnsForwarder) Close() error {
	c.closed.Add(1)
	return nil
}

type failingDnsForwarder struct {
	err    error
	closed atomic.Int32
}

func (f *failingDnsForwarder) ForwardDNS(context.Context, []byte) (*dnsmessage.Msg, error) {
	return nil, f.err
}

func (f *failingDnsForwarder) Close() error {
	f.closed.Add(1)
	return nil
}

func TestDnsController_EvictIdleDnsForwarders(t *testing.T) {
	testTTL := 40 * time.Millisecond

	forwarder := &countingDnsForwarder{}
	entry := newCachedDnsForwarder(forwarder, time.Now().Add(-2*testTTL))

	key := dnsForwarderKey{
		upstream: "dns.example:53",
		dialArgument: dialArgument{
			l4proto: consts.L4ProtoStr_UDP,
		},
	}

	c := &DnsController{
		log:                 logrus.New(),
		dnsForwarderIdleTTL: testTTL,
	}
	c.dnsForwarderCache.Store(key, entry)

	c.evictIdleDnsForwarders(time.Now())

	_, ok := c.dnsForwarderCache.Load(key)
	require.False(t, ok, "idle forwarder should be evicted")
	require.EqualValues(t, 1, forwarder.closed.Load(), "evicted forwarder should be closed once")
}

func TestDnsController_EvictIdleDnsForwarders_SkipInFlight(t *testing.T) {
	testTTL := 40 * time.Millisecond

	forwarder := &countingDnsForwarder{}
	entry := newCachedDnsForwarder(forwarder, time.Now().Add(-2*testTTL))
	entry.inFlight.Store(1)

	key := dnsForwarderKey{
		upstream: "dns.example:53",
		dialArgument: dialArgument{
			l4proto: consts.L4ProtoStr_TCP,
		},
	}

	c := &DnsController{
		log:                 logrus.New(),
		dnsForwarderIdleTTL: testTTL,
	}
	c.dnsForwarderCache.Store(key, entry)

	c.evictIdleDnsForwarders(time.Now())

	_, ok := c.dnsForwarderCache.Load(key)
	require.True(t, ok, "in-flight forwarder should not be evicted")
	require.EqualValues(t, 0, forwarder.closed.Load(), "in-flight forwarder should not be closed")
}

func TestDnsController_ForwardWithDialArg_RetiresProxyUdpForwarderOnError(t *testing.T) {
	oldFactory := dnsForwarderFactory
	forwarder := &failingDnsForwarder{err: stderrors.New("i/o timeout")}
	dnsForwarderFactory = func(*dns.Upstream, dialArgument, *logrus.Logger) (DnsForwarder, error) {
		return forwarder, nil
	}
	defer func() {
		dnsForwarderFactory = oldFactory
	}()

	c := &DnsController{
		log: logrus.New(),
	}
	upstream := &dns.Upstream{
		Scheme:   "udp",
		Hostname: "dns.example",
		Port:     53,
	}
	dialArg := &dialArgument{
		l4proto:    consts.L4ProtoStr_UDP,
		ipversion:  consts.IpVersionStr_4,
		bestDialer: newTestProxyEndpointDialer("hysteria2", "proxy.example:443"),
		bestTarget: netip.MustParseAddrPort("1.1.1.1:53"),
	}

	_, err := c.forwardWithDialArg(context.Background(), upstream, dialArg, []byte{0x00, 0x01})
	require.Error(t, err)

	require.EqualValues(t, 1, forwarder.closed.Load(), "failed proxy UDP forwarder should be retired")
	c.dnsForwarderCache.Range(func(_, _ any) bool {
		t.Fatal("retired forwarder should not remain cached")
		return false
	})
}
