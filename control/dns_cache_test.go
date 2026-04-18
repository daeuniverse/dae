/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net"
	"strings"
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

func TestDnsCache_CloneForReloadReusesImmutablePayload(t *testing.T) {
	now := time.Now()
	answer := &dnsmessage.A{
		Hdr: dnsmessage.RR_Header{Name: "reload.example.", Rrtype: dnsmessage.TypeA, Class: dnsmessage.ClassINET, Ttl: 120},
		A:   net.IPv4(4, 3, 2, 1),
	}
	cache := &DnsCache{
		DomainBitmap:     []uint32{1, 2, 3},
		Answer:           []dnsmessage.RR{answer},
		Deadline:         now.Add(2 * time.Minute),
		OriginalDeadline: now.Add(2 * time.Minute),
	}
	cache.lastAccessNano.Store(now.UnixNano())
	cache.MarkBpfUpdated(now)
	require.NoError(t, cache.PrepackResponse("reload.example.", dnsmessage.TypeA))

	clone := cache.CloneForReload()
	require.NotNil(t, clone)
	require.Same(t, cache.Answer[0], clone.Answer[0], "reload clone should reuse immutable RR payload")
	require.Equal(t, cache.GetPackedResponse(), clone.GetPackedResponse(), "reload clone should reuse pre-packed response bytes")
	require.Equal(t, cache.lastAccessNano.Load(), clone.lastAccessNano.Load(), "reload clone should preserve LRU access time")
	require.Equal(t, int64(0), clone.lastRouteSyncNano.Load(), "reload clone should force fresh BPF sync")
	require.Equal(t, uint64(0), clone.lastBpfDataHash.Load(), "reload clone should force fresh BPF sync hash")
	require.False(t, clone.refreshing.Load(), "reload clone should not inherit old refresh-in-progress state")
}

func TestDnsCache_FillIntoWithTTL_DoesNotMutateRequestOnPackError(t *testing.T) {
	req := new(dnsmessage.Msg)
	req.SetQuestion(strings.Repeat("a", 64)+".example.", dnsmessage.TypeA)

	_, err := req.Pack()
	require.Error(t, err)
	require.False(t, req.Response)

	cache := &DnsCache{
		Answer: []dnsmessage.RR{
			&dnsmessage.A{
				Hdr: dnsmessage.RR_Header{Name: "example.", Rrtype: dnsmessage.TypeA, Class: dnsmessage.ClassINET, Ttl: 60},
				A:   net.IPv4(1, 1, 1, 1),
			},
		},
		Deadline: time.Now().Add(time.Minute),
	}

	require.Nil(t, cache.FillIntoWithTTL(req, time.Now()))
	require.False(t, req.Response, "request should remain a request when fallback packing fails")
	require.Nil(t, req.Answer, "request answer should remain untouched when fallback packing fails")
	require.False(t, req.RecursionAvailable)
}
