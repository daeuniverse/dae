/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/component/dns"
	"github.com/stretchr/testify/require"
)

func testDnsDialerSnapshotUpstream() *dns.Upstream {
	return &dns.Upstream{
		Scheme:   dns.UpstreamScheme_UDP,
		Hostname: "dns.example",
		Port:     53,
		Ip46: &netutils.Ip46{
			Ip4: netip.MustParseAddr("1.1.1.1"),
			Ip6: netip.MustParseAddr("2606:4700:4700::1111"),
		},
	}
}

func TestBuildDnsDialerSnapshotKey_RoutingFingerprint(t *testing.T) {
	upstream := testDnsDialerSnapshotUpstream()

	req1 := &udpRequest{
		realSrc: netip.MustParseAddrPort("10.0.0.2:12345"),
		routingResult: &bpfRoutingResult{
			Dscp:  1,
			Mac:   [6]uint8{1, 2, 3, 4, 5, 6},
			Pname: [16]uint8{'c', 'u', 'r', 'l'},
		},
	}
	req2 := &udpRequest{
		realSrc: netip.MustParseAddrPort("10.0.0.2:12345"),
		routingResult: &bpfRoutingResult{
			Dscp:  2,
			Mac:   [6]uint8{1, 2, 3, 4, 5, 6},
			Pname: [16]uint8{'c', 'u', 'r', 'l'},
		},
	}

	k1, ok1 := buildDnsDialerSnapshotKey(req1, upstream)
	k2, ok2 := buildDnsDialerSnapshotKey(req2, upstream)
	require.True(t, ok1)
	require.True(t, ok2)
	require.NotEqual(t, k1, k2)
}

func TestControlPlane_DnsDialerSnapshotCache_HitAndExpire(t *testing.T) {
	oldTTL := dnsDialerSnapshotTTL
	dnsDialerSnapshotTTL = 20 * time.Millisecond
	defer func() { dnsDialerSnapshotTTL = oldTTL }()

	cp := &ControlPlane{}
	req := &udpRequest{
		realSrc: netip.MustParseAddrPort("10.0.0.2:23456"),
		routingResult: &bpfRoutingResult{
			Dscp:  3,
			Mac:   [6]uint8{7, 8, 9, 10, 11, 12},
			Pname: [16]uint8{'f', 'i', 'r', 'e', 'f', 'o', 'x'},
		},
	}
	upstream := testDnsDialerSnapshotUpstream()

	key, ok := buildDnsDialerSnapshotKey(req, upstream)
	require.True(t, ok)

	dialArg := &dialArgument{
		l4proto:    consts.L4ProtoStr_UDP,
		ipversion:  consts.IpVersionStr_4,
		bestTarget: netip.MustParseAddrPort("1.1.1.1:53"),
		mark:       7,
		mptcp:      false,
	}
	baseNow := time.Now()
	cp.storeDnsDialerSnapshot(key, dialArg, baseNow)

	cached, hit := cp.loadDnsDialerSnapshot(key, baseNow.Add(5*time.Millisecond))
	require.True(t, hit)
	require.Equal(t, uint32(7), cached.mark)

	cached.mark = 999
	cached2, hit2 := cp.loadDnsDialerSnapshot(key, baseNow.Add(6*time.Millisecond))
	require.True(t, hit2)
	require.Equal(t, uint32(7), cached2.mark, "cache should return copy instead of mutable shared pointer")

	expiredNow := baseNow.Add(dnsDialerSnapshotTTL + time.Millisecond)
	cached3, hit3 := cp.loadDnsDialerSnapshot(key, expiredNow)
	require.False(t, hit3)
	require.Nil(t, cached3)

	cp.cleanupDnsDialerSnapshot(expiredNow)
	_, stillExists := cp.dnsDialerSnapshot.Load(key)
	require.False(t, stillExists)
}
