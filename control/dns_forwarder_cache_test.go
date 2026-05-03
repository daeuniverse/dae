/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
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
	"github.com/daeuniverse/dae/component/outbound"
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
		l4proto:  consts.L4ProtoStr_UDP,
	}

	c := newTestDnsController()
	c.log = logrus.New()
	c.dnsForwarderIdleTTL = testTTL
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
		l4proto:  consts.L4ProtoStr_TCP,
	}

	c := newTestDnsController()
	c.log = logrus.New()
	c.dnsForwarderIdleTTL = testTTL
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

	c := newTestDnsController()
	c.log = logrus.New()
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

func TestDnsController_ForwardWithDialArg_RetiresDirectUdpForwarderOnError(t *testing.T) {
	oldFactory := dnsForwarderFactory
	forwarder := &failingDnsForwarder{err: stderrors.New("i/o timeout")}
	dnsForwarderFactory = func(*dns.Upstream, dialArgument, *logrus.Logger) (DnsForwarder, error) {
		return forwarder, nil
	}
	defer func() {
		dnsForwarderFactory = oldFactory
	}()

	c := newTestDnsController()
	c.log = logrus.New()
	upstream := &dns.Upstream{
		Scheme:   "udp",
		Hostname: "dns.example",
		Port:     53,
	}
	dialArg := &dialArgument{
		l4proto:    consts.L4ProtoStr_UDP,
		ipversion:  consts.IpVersionStr_4,
		bestDialer: newTestEndpointDialer(),
		bestTarget: netip.MustParseAddrPort("1.1.1.1:53"),
	}

	_, err := c.forwardWithDialArg(context.Background(), upstream, dialArg, []byte{0x00, 0x01})
	require.Error(t, err)

	require.EqualValues(t, 1, forwarder.closed.Load(), "failed direct UDP forwarder should be retired")
	c.dnsForwarderCache.Range(func(_, _ any) bool {
		t.Fatal("retired forwarder should not remain cached")
		return false
	})
}

func TestDnsController_ResetDnsForwardersDrainsInFlightForwarders(t *testing.T) {
	forwarder := &countingDnsForwarder{}
	entry := newCachedDnsForwarder(forwarder, time.Now())
	require.True(t, entry.beginUse(), "expected cached forwarder to accept in-flight use before retirement")

	key := dnsForwarderKey{
		upstream: "dns.example:53",
		l4proto:  consts.L4ProtoStr_UDP,
	}

	c := newTestDnsController()
	c.log = logrus.New()
	c.dnsForwarderCache.Store(key, entry)

	require.NoError(t, c.ResetDnsForwarders())

	_, ok := c.dnsForwarderCache.Load(key)
	require.False(t, ok, "retired forwarder should be removed from cache immediately")
	require.EqualValues(t, 0, forwarder.closed.Load(), "in-flight forwarder should not be closed during retirement")

	entry.endUse()

	require.Eventually(t, func() bool {
		return forwarder.closed.Load() == 1
	}, time.Second, 10*time.Millisecond, "retired forwarder should close after the final in-flight request completes")
}

func TestNewDnsForwarderKeyIsStableAcrossReloadGenerations(t *testing.T) {
	upstream := &dns.Upstream{
		Scheme:   "udp",
		Hostname: "dns.example",
		Port:     53,
	}

	makeDialArg := func() *dialArgument {
		return &dialArgument{
			l4proto:      consts.L4ProtoStr_UDP,
			ipversion:    consts.IpVersionStr_4,
			bestDialer:   newTestProxyEndpointDialer("hysteria2", "proxy.example:443"),
			bestOutbound: &outbound.DialerGroup{Name: "proxy"},
			bestTarget:   netip.MustParseAddrPort("1.1.1.1:53"),
			mark:         0x2023,
			mptcp:        true,
		}
	}

	first := makeDialArg()
	second := makeDialArg()

	require.Equal(t, newDnsForwarderKey(upstream, first), newDnsForwarderKey(upstream, second))
}

func TestDnsControllerClose_ReleasesRetainedBuffers(t *testing.T) {
	c := &DnsController{
		dnsControllerStore: &dnsControllerStore{
			evictorBuf:  make([]*DnsCache, 0, 32),
			lruScratch:  make([]cacheEntry, 16),
			evictorWake: make(chan struct{}, 1),
			evictorQ:    make(chan *DnsCache, 4),
		},
		log: logrus.New(),
	}
	c.dnsCache.Store("example.com.1", &DnsCache{})
	c.dnsKnowledge.Store("example.com", time.Now().UnixNano())

	require.NoError(t, c.Close())
	require.Nil(t, c.evictorBuf, "Close should release evictor scratch")
	require.Nil(t, c.lruScratch, "Close should release LRU scratch")
	require.Nil(t, c.evictorWake, "Close should release evictor wake channel reference")
	require.Nil(t, c.evictorQ, "Close should release evictor queue reference")
	require.Nil(t, c.bpfUpdateCh, "Close should release BPF queue reference")
	require.Nil(t, c.bpfUpdateStop, "Close should release BPF stop channel reference")
	require.True(t, c.bpfUpdateClosed.Load(), "Close should mark BPF updates closed")

	_, ok := c.dnsCache.Load("example.com.1")
	require.False(t, ok, "Close should clear DNS cache entries")
	_, ok = c.dnsKnowledge.Load("example.com")
	require.False(t, ok, "Close should clear DNS knowledge entries")
}

func TestDnsController_ForwardWithDialArg_KeepsProxyTcpForwarderOnTimeout(t *testing.T) {
	oldFactory := dnsForwarderFactory
	forwarder := &failingDnsForwarder{err: stderrors.New("i/o timeout")}
	dnsForwarderFactory = func(*dns.Upstream, dialArgument, *logrus.Logger) (DnsForwarder, error) {
		return forwarder, nil
	}
	defer func() {
		dnsForwarderFactory = oldFactory
	}()

	c := newTestDnsController()
	c.log = logrus.New()
	upstream := &dns.Upstream{
		Scheme:   "tcp",
		Hostname: "dns.example",
		Port:     53,
	}
	dialArg := &dialArgument{
		l4proto:    consts.L4ProtoStr_TCP,
		ipversion:  consts.IpVersionStr_4,
		bestDialer: newTestProxyEndpointDialer("hysteria2", "proxy.example:443"),
		bestTarget: netip.MustParseAddrPort("1.1.1.1:53"),
	}
	key := newDnsForwarderKey(upstream, dialArg)

	_, err := c.forwardWithDialArg(context.Background(), upstream, dialArg, []byte{0x00, 0x01})
	require.Error(t, err)

	require.EqualValues(t, 0, forwarder.closed.Load(), "proxy TCP forwarder should stay cached for ordinary transport errors")
	cached, ok := c.dnsForwarderCache.Load(key)
	require.True(t, ok, "proxy TCP forwarder should remain cached")
	entry, ok := cached.(*cachedDnsForwarder)
	require.True(t, ok)
	require.Same(t, forwarder, entry.forwarder)
}

func TestDnsController_ForwardWithDialArg_KeepsDirectTcpForwarderOnError(t *testing.T) {
	oldFactory := dnsForwarderFactory
	forwarder := &failingDnsForwarder{err: stderrors.New("i/o timeout")}
	dnsForwarderFactory = func(*dns.Upstream, dialArgument, *logrus.Logger) (DnsForwarder, error) {
		return forwarder, nil
	}
	defer func() {
		dnsForwarderFactory = oldFactory
	}()

	c := newTestDnsController()
	c.log = logrus.New()
	upstream := &dns.Upstream{
		Scheme:   "tcp",
		Hostname: "dns.example",
		Port:     53,
	}
	dialArg := &dialArgument{
		l4proto:    consts.L4ProtoStr_TCP,
		ipversion:  consts.IpVersionStr_4,
		bestDialer: newTestEndpointDialer(),
		bestTarget: netip.MustParseAddrPort("1.1.1.1:53"),
	}
	key := newDnsForwarderKey(upstream, dialArg)

	_, err := c.forwardWithDialArg(context.Background(), upstream, dialArg, []byte{0x00, 0x01})
	require.Error(t, err)

	require.EqualValues(t, 0, forwarder.closed.Load(), "direct TCP forwarder should stay cached for ordinary transport errors")
	cached, ok := c.dnsForwarderCache.Load(key)
	require.True(t, ok, "direct TCP forwarder should remain cached")
	entry, ok := cached.(*cachedDnsForwarder)
	require.True(t, ok)
	require.Same(t, forwarder, entry.forwarder)
}

func TestDnsController_ForwardWithDialArg_KeepsProxyTcpFallbackForwarderOnTimeout(t *testing.T) {
	oldFactory := dnsForwarderFactory
	forwarder := &failingDnsForwarder{err: stderrors.New("i/o timeout")}
	dnsForwarderFactory = func(*dns.Upstream, dialArgument, *logrus.Logger) (DnsForwarder, error) {
		return forwarder, nil
	}
	defer func() {
		dnsForwarderFactory = oldFactory
	}()

	c := newTestDnsController()
	c.log = logrus.New()
	upstream := &dns.Upstream{
		Scheme:   "tcp+udp",
		Hostname: "dns.example",
		Port:     53,
	}
	dialArg := &dialArgument{
		l4proto:    consts.L4ProtoStr_TCP,
		ipversion:  consts.IpVersionStr_4,
		bestDialer: newTestProxyEndpointDialer("hysteria2", "proxy.example:443"),
		bestTarget: netip.MustParseAddrPort("1.1.1.1:53"),
	}
	key := newDnsForwarderKey(upstream, dialArg)

	_, err := c.forwardWithDialArg(context.Background(), upstream, dialArg, []byte{0x00, 0x01})
	require.Error(t, err)

	require.EqualValues(t, 0, forwarder.closed.Load(), "proxy TCP fallback forwarder should stay cached for ordinary transport errors")
	cached, ok := c.dnsForwarderCache.Load(key)
	require.True(t, ok, "proxy TCP fallback forwarder should remain cached")
	entry, ok := cached.(*cachedDnsForwarder)
	require.True(t, ok)
	require.Same(t, forwarder, entry.forwarder)
}

func TestDnsController_ForwardWithDialArg_TruncatedDoesNotRetireForwarder(t *testing.T) {
	oldFactory := dnsForwarderFactory
	forwarder := &failingDnsForwarder{err: ErrDNSTruncated}
	dnsForwarderFactory = func(*dns.Upstream, dialArgument, *logrus.Logger) (DnsForwarder, error) {
		return forwarder, nil
	}
	defer func() {
		dnsForwarderFactory = oldFactory
	}()

	c := newTestDnsController()
	c.log = logrus.New()
	upstream := &dns.Upstream{
		Scheme:   "udp",
		Hostname: "dns.example",
		Port:     53,
	}
	dialArg := &dialArgument{
		l4proto:    consts.L4ProtoStr_UDP,
		ipversion:  consts.IpVersionStr_4,
		bestDialer: newTestEndpointDialer(),
		bestTarget: netip.MustParseAddrPort("1.1.1.1:53"),
	}
	key := newDnsForwarderKey(upstream, dialArg)

	_, err := c.forwardWithDialArg(context.Background(), upstream, dialArg, []byte{0x00, 0x01})
	require.ErrorIs(t, err, ErrDNSTruncated)

	require.EqualValues(t, 0, forwarder.closed.Load(), "truncated response should not retire forwarder")
	cached, ok := c.dnsForwarderCache.Load(key)
	require.True(t, ok, "forwarder should remain cached after truncated response")
	entry, ok := cached.(*cachedDnsForwarder)
	require.True(t, ok)
	require.Same(t, forwarder, entry.forwarder)
}
