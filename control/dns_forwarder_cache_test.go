/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
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

func TestDnsController_EvictIdleDnsForwarders(t *testing.T) {
	oldTTL := dnsForwarderIdleTTL
	defer func() {
		dnsForwarderIdleTTL = oldTTL
	}()
	dnsForwarderIdleTTL = 40 * time.Millisecond

	forwarder := &countingDnsForwarder{}
	entry := newCachedDnsForwarder(forwarder, time.Now().Add(-2*dnsForwarderIdleTTL))

	key := dnsForwarderKey{
		upstream: "dns.example:53",
		dialArgument: dialArgument{
			l4proto: consts.L4ProtoStr_UDP,
		},
	}

	c := &DnsController{log: logrus.New()}
	c.dnsForwarderCache.Store(key, entry)

	c.evictIdleDnsForwarders(time.Now())

	_, ok := c.dnsForwarderCache.Load(key)
	require.False(t, ok, "idle forwarder should be evicted")
	require.EqualValues(t, 1, forwarder.closed.Load(), "evicted forwarder should be closed once")
}

func TestDnsController_EvictIdleDnsForwarders_SkipInFlight(t *testing.T) {
	oldTTL := dnsForwarderIdleTTL
	defer func() {
		dnsForwarderIdleTTL = oldTTL
	}()
	dnsForwarderIdleTTL = 40 * time.Millisecond

	forwarder := &countingDnsForwarder{}
	entry := newCachedDnsForwarder(forwarder, time.Now().Add(-2*dnsForwarderIdleTTL))
	entry.inFlight.Store(1)

	key := dnsForwarderKey{
		upstream: "dns.example:53",
		dialArgument: dialArgument{
			l4proto: consts.L4ProtoStr_TCP,
		},
	}

	c := &DnsController{log: logrus.New()}
	c.dnsForwarderCache.Store(key, entry)

	c.evictIdleDnsForwarders(time.Now())

	_, ok := c.dnsForwarderCache.Load(key)
	require.True(t, ok, "in-flight forwarder should not be evicted")
	require.EqualValues(t, 0, forwarder.closed.Load(), "in-flight forwarder should not be closed")
}
