/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
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

func TestDnsCache_PrepackResponse_Correctness(t *testing.T) {
	answers := []dnsmessage.RR{
		&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{
				Name:   "test.example.com.",
				Rrtype: dnsmessage.TypeA,
				Class:  dnsmessage.ClassINET,
				Ttl:    300,
			},
			A: []byte{93, 184, 216, 34},
		},
		&dnsmessage.AAAA{
			Hdr: dnsmessage.RR_Header{
				Name:   "test.example.com.",
				Rrtype: dnsmessage.TypeAAAA,
				Class:  dnsmessage.ClassINET,
				Ttl:    300,
			},
			AAAA: []byte{0x26, 0x07, 0xf8, 0xb0, 0x40, 0x0, 0x8, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x20, 0x22},
		},
	}

	cache := &DnsCache{
		DomainBitmap:     []uint32{1, 2, 3},
		Answer:           answers,
		Deadline:         time.Now().Add(5 * time.Minute),
		OriginalDeadline: time.Now().Add(5 * time.Minute),
	}

	require.NoError(t, cache.PrepackResponse("test.example.com.", dnsmessage.TypeA))

	packed := cache.GetPackedResponse()
	require.NotNil(t, packed)

	var msg dnsmessage.Msg
	require.NoError(t, msg.Unpack(packed))
	require.Equal(t, dnsmessage.RcodeSuccess, msg.Rcode)
	require.True(t, msg.Response)
	require.True(t, msg.RecursionAvailable)
	require.Len(t, msg.Question, 1)
	require.Equal(t, "test.example.com.", msg.Question[0].Name)
}

func TestDnsCache_PrepackResponseBeforeStore_RestoresRRTTL(t *testing.T) {
	answer := &dnsmessage.A{
		Hdr: dnsmessage.RR_Header{
			Name:   "test.example.com.",
			Rrtype: dnsmessage.TypeA,
			Class:  dnsmessage.ClassINET,
			Ttl:    60,
		},
		A: []byte{93, 184, 216, 34},
	}
	ns := &dnsmessage.NS{
		Hdr: dnsmessage.RR_Header{
			Name:   "test.example.com.",
			Rrtype: dnsmessage.TypeNS,
			Class:  dnsmessage.ClassINET,
			Ttl:    120,
		},
		Ns: "ns1.example.com.",
	}
	extra := &dnsmessage.A{
		Hdr: dnsmessage.RR_Header{
			Name:   "ns1.example.com.",
			Rrtype: dnsmessage.TypeA,
			Class:  dnsmessage.ClassINET,
			Ttl:    180,
		},
		A: []byte{93, 184, 216, 35},
	}
	cache := &DnsCache{
		Answer:           []dnsmessage.RR{answer},
		NS:               []dnsmessage.RR{ns},
		Extra:            []dnsmessage.RR{extra},
		Deadline:         time.Now().Add(5 * time.Minute),
		OriginalDeadline: time.Now().Add(5 * time.Minute),
	}

	require.NoError(t, cache.prepackResponseBeforeStore("test.example.com.", dnsmessage.TypeA, 42, time.Now()))
	require.EqualValues(t, 60, answer.Header().Ttl)
	require.EqualValues(t, 120, ns.Header().Ttl)
	require.EqualValues(t, 180, extra.Header().Ttl)

	packed := cache.GetPackedResponse()
	require.NotNil(t, packed)

	var msg dnsmessage.Msg
	require.NoError(t, msg.Unpack(packed))
	require.EqualValues(t, 42, msg.Answer[0].Header().Ttl)
	require.EqualValues(t, 42, msg.Ns[0].Header().Ttl)
	require.EqualValues(t, 42, msg.Extra[0].Header().Ttl)
}

func TestDnsCache_FillIntoWithTTL_Correctness(t *testing.T) {
	deadline := time.Now().Add(300 * time.Second)
	cache := &DnsCache{
		DomainBitmap: []uint32{1, 2, 3},
		Answer: []dnsmessage.RR{
			&dnsmessage.A{
				Hdr: dnsmessage.RR_Header{
					Name:   "test.example.com.",
					Rrtype: dnsmessage.TypeA,
					Class:  dnsmessage.ClassINET,
					Ttl:    0,
				},
				A: []byte{93, 184, 216, 34},
			},
		},
		Deadline:         deadline,
		OriginalDeadline: deadline,
	}

	resp := cache.FillIntoWithTTL(new(dnsmessage.Msg), time.Now())
	require.NotNil(t, resp)

	var msg dnsmessage.Msg
	require.NoError(t, msg.Unpack(resp))
	require.Len(t, msg.Answer, 1)
	require.GreaterOrEqual(t, msg.Answer[0].Header().Ttl, uint32(299))
	require.LessOrEqual(t, msg.Answer[0].Header().Ttl, uint32(300))

	resp = cache.FillIntoWithTTL(new(dnsmessage.Msg), time.Now().Add(100*time.Second))
	require.NotNil(t, resp)
	require.NoError(t, msg.Unpack(resp))
	require.GreaterOrEqual(t, msg.Answer[0].Header().Ttl, uint32(199))
	require.LessOrEqual(t, msg.Answer[0].Header().Ttl, uint32(201))

	resp = cache.FillIntoWithTTL(new(dnsmessage.Msg), deadline.Add(-500*time.Millisecond))
	require.NotNil(t, resp)
	require.NoError(t, msg.Unpack(resp))
	require.EqualValues(t, 1, msg.Answer[0].Header().Ttl)
}

func TestDnsCache_GetPackedResponseWithApproximateTTL(t *testing.T) {
	deadline := time.Now().Add(300 * time.Second)
	cache := &DnsCache{
		DomainBitmap: []uint32{1, 2, 3},
		Answer: []dnsmessage.RR{
			&dnsmessage.A{
				Hdr: dnsmessage.RR_Header{
					Name:   "test.example.com.",
					Rrtype: dnsmessage.TypeA,
					Class:  dnsmessage.ClassINET,
					Ttl:    0,
				},
				A: []byte{93, 184, 216, 34},
			},
		},
		Deadline:         deadline,
		OriginalDeadline: deadline,
	}

	require.NoError(t, cache.PrepackResponse("test.example.com.", dnsmessage.TypeA))

	resp := cache.GetPackedResponseWithApproximateTTL("test.example.com.", dnsmessage.TypeA, time.Now())
	require.NotNil(t, resp)

	var msg dnsmessage.Msg
	require.NoError(t, msg.Unpack(resp))
	require.GreaterOrEqual(t, msg.Answer[0].Header().Ttl, uint32(299))
	require.LessOrEqual(t, msg.Answer[0].Header().Ttl, uint32(300))

	resp = cache.GetPackedResponseWithApproximateTTL("test.example.com.", dnsmessage.TypeA, time.Now().Add(20*time.Second))
	require.NotNil(t, resp)
	require.NoError(t, msg.Unpack(resp))
	require.GreaterOrEqual(t, msg.Answer[0].Header().Ttl, uint32(278))
	require.LessOrEqual(t, msg.Answer[0].Header().Ttl, uint32(282))

	resp = cache.GetPackedResponseWithApproximateTTL("test.example.com.", dnsmessage.TypeA, deadline.Add(-500*time.Millisecond))
	require.NotNil(t, resp)
	require.NoError(t, msg.Unpack(resp))
	require.EqualValues(t, 1, msg.Answer[0].Header().Ttl)

	require.Nil(t, cache.GetPackedResponseWithApproximateTTL("test.example.com.", dnsmessage.TypeA, deadline.Add(time.Second)))
}

func TestDnsCache_FallbackWhenPrepackNotAvailable(t *testing.T) {
	deadline := time.Now().Add(300 * time.Second)
	cache := &DnsCache{
		DomainBitmap: []uint32{1, 2, 3},
		Answer: []dnsmessage.RR{
			&dnsmessage.A{
				Hdr: dnsmessage.RR_Header{
					Name:   "test.example.com.",
					Rrtype: dnsmessage.TypeA,
					Class:  dnsmessage.ClassINET,
					Ttl:    0,
				},
				A: []byte{93, 184, 216, 34},
			},
		},
		Deadline:         deadline,
		OriginalDeadline: deadline,
	}

	require.Nil(t, cache.GetPackedResponseWithApproximateTTL("test.example.com.", dnsmessage.TypeA, time.Now()))

	resp := cache.FillIntoWithTTL(new(dnsmessage.Msg), time.Now())
	require.NotNil(t, resp)

	var msg dnsmessage.Msg
	require.NoError(t, msg.Unpack(resp))
	require.GreaterOrEqual(t, msg.Answer[0].Header().Ttl, uint32(299))
	require.LessOrEqual(t, msg.Answer[0].Header().Ttl, uint32(300))
}
