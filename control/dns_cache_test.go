/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net"
	"testing"
	"time"

	dnsmessage "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestDnsCache_FillInto_ClearsAnswerWhenCacheEmpty(t *testing.T) {
	req := new(dnsmessage.Msg)
	req.Answer = []dnsmessage.RR{
		&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{Name: "stale.example.", Rrtype: dnsmessage.TypeA, Class: dnsmessage.ClassINET, Ttl: 30},
			A:   net.IPv4(1, 2, 3, 4),
		},
	}

	cache := &DnsCache{}
	cache.FillInto(req)

	require.Nil(t, req.Answer, "Answer should be explicitly cleared when cache answer is empty")
	require.Equal(t, dnsmessage.RcodeSuccess, req.Rcode)
	require.True(t, req.Response)
	require.True(t, req.RecursionAvailable)
	require.False(t, req.Truncated)
}

func TestDnsCache_FillInto_DeepCopyAnswer(t *testing.T) {
	origin := &dnsmessage.A{
		Hdr: dnsmessage.RR_Header{Name: "copy.example.", Rrtype: dnsmessage.TypeA, Class: dnsmessage.ClassINET, Ttl: 60},
		A:   net.IP{9, 8, 7, 6},
	}

	cache := &DnsCache{Answer: []dnsmessage.RR{origin}}
	req := new(dnsmessage.Msg)
	cache.FillInto(req)

	require.Len(t, req.Answer, 1)
	require.NotSame(t, cache.Answer[0], req.Answer[0], "RR should be deep-copied")

	origin.A[0] = 1
	copiedA, ok := req.Answer[0].(*dnsmessage.A)
	require.True(t, ok)
	require.EqualValues(t, 9, copiedA.A[0], "copied answer should not be affected by source mutation")
}

func TestDnsCache_ShouldRefreshRouteBinding(t *testing.T) {
	cache := &DnsCache{}
	now := time.Now()

	require.True(t, cache.ShouldRefreshRouteBinding(now, time.Second))
	require.False(t, cache.ShouldRefreshRouteBinding(now.Add(100*time.Millisecond), time.Second))
	require.True(t, cache.ShouldRefreshRouteBinding(now.Add(1100*time.Millisecond), time.Second))
}

func TestDnsCache_CloneResetsSyncState(t *testing.T) {
	now := time.Now()
	cache := &DnsCache{}
	cache.MarkRouteBindingRefreshed(now)

	clone := cache.Clone()
	// Clone should reset sync state to 0, forcing immediate BPF update on reload
	require.Equal(t, int64(0), clone.lastRouteSyncNano.Load(), "lastRouteSyncNano should be reset to 0 in clone")
	require.Equal(t, uint64(0), clone.lastBpfDataHash.Load(), "lastBpfDataHash should be reset to 0 in clone")
	// This means the cloned cache should immediately need BPF update
	require.True(t, clone.NeedsBpfUpdate(now), "Cloned cache should immediately need BPF update")
	// After NeedsBpfUpdate, the timestamp should be updated to now
	require.Equal(t, now.UnixNano(), clone.lastRouteSyncNano.Load(), "lastRouteSyncNano should be updated after NeedsBpfUpdate")
}
