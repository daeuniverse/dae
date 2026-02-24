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

// TestDnsDialerSnapshot_PortExemption verifies that DNS queries from the same client
// but with different source ports generate the same cache key, enabling cache reuse.
func TestDnsDialerSnapshot_PortExemption(t *testing.T) {
	upstream := testDnsDialerSnapshotUpstream()

	tests := []struct {
		name        string
		realSrc     netip.AddrPort
		realDst     netip.AddrPort
		expectMatch string // empty means no match, or name of matching test case
	}{
		{
			name:        "DNS same client different port 1",
			realSrc:     netip.MustParseAddrPort("192.168.1.100:54321"),
			realDst:     netip.MustParseAddrPort("8.8.8.8:53"),
			expectMatch: "DNS same client different port 2",
		},
		{
			name:        "DNS same client different port 2",
			realSrc:     netip.MustParseAddrPort("192.168.1.100:40000"),
			realDst:     netip.MustParseAddrPort("8.8.8.8:53"),
			expectMatch: "DNS same client different port 1",
		},
		{
			name:        "DNS same client different port 3",
			realSrc:     netip.MustParseAddrPort("192.168.1.100:12345"),
			realDst:     netip.MustParseAddrPort("8.8.8.8:53"),
			expectMatch: "DNS same client different port 1",
		},
		{
			name:        "DNS different client",
			realSrc:     netip.MustParseAddrPort("192.168.1.200:54321"),
			realDst:     netip.MustParseAddrPort("8.8.8.8:53"),
			expectMatch: "",
		},
		{
			name:        "Non-DNS traffic (port 443)",
			realSrc:     netip.MustParseAddrPort("192.168.1.100:54321"),
			realDst:     netip.MustParseAddrPort("1.1.1.1:443"),
			expectMatch: "",
		},
		{
			name:        "Non-DNS traffic different port",
			realSrc:     netip.MustParseAddrPort("192.168.1.100:54322"),
			realDst:     netip.MustParseAddrPort("10.0.0.1:80"),
			expectMatch: "",
		},
	}

	keys := make(map[string]dnsDialerSnapshotKey)

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := &udpRequest{
				realSrc: tc.realSrc,
				realDst: tc.realDst,
			}
			key, ok := buildDnsDialerSnapshotKey(req, upstream)
			require.True(t, ok)

			// Store key for matching
			keys[tc.name] = key

			// Verify port is zero for DNS traffic
			if tc.realDst.Port() == 53 {
				require.Equal(t, uint16(0), key.realSrc.Port(), "DNS traffic should have port 0 in cache key")
			}
		})
	}

	// Verify matching behavior
	for _, tc := range tests {
		if tc.expectMatch == "" {
			continue
		}
		t.Run(tc.name+" match", func(t *testing.T) {
			key1 := keys[tc.name]
			key2 := keys[tc.expectMatch]
			require.Equal(t, key1, key2, "same client DNS queries should match regardless of source port")
		})
	}

	// Verify non-matching behavior
	for _, tc := range tests {
		if tc.expectMatch != "" {
			continue
		}
		t.Run(tc.name+" no match", func(t *testing.T) {
			key1 := keys[tc.name]
			// Should not match DNS queries
			dnsQueries := []string{
				"DNS same client different port 1",
				"DNS same client different port 2",
				"DNS same client different port 3",
			}
			for _, dnsName := range dnsQueries {
				key2 := keys[dnsName]
				if key1 == key2 {
					t.Errorf("%s should not match %s", tc.name, dnsName)
				}
			}
		})
	}
}
