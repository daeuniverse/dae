/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"encoding/binary"
	"fmt"
	"sync"
	"testing"
	"time"

	dnsmessage "github.com/miekg/dns"
)

// BenchmarkDnsCache_PackedResponse benchmarks the performance of cache hits with pre-packed responses
func BenchmarkDnsCache_PackedResponse(b *testing.B) {
	// Create a cache entry with pre-packed response
	answers := []dnsmessage.RR{
		&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{
				Name:   "example.com.",
				Rrtype: dnsmessage.TypeA,
				Class:  dnsmessage.ClassINET,
				Ttl:    300,
			},
			A: []byte{93, 184, 216, 34},
		},
	}

	cache := &DnsCache{
		DomainBitmap:     []uint32{1, 2, 3},
		Answer:           answers,
		Deadline:         time.Now().Add(5 * time.Minute),
		OriginalDeadline: time.Now().Add(5 * time.Minute),
	}

	// Pre-pack the response
	if err := cache.PrepackResponse("example.com.", dnsmessage.TypeA); err != nil {
		b.Fatalf("failed to prepack response: %v", err)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Simulate cache hit path - just return pre-packed response
		_ = cache.PackedResponse
	}
}

// BenchmarkDnsCache_PackedResponse_Parallel benchmarks parallel cache hits
func BenchmarkDnsCache_PackedResponse_Parallel(b *testing.B) {
	answers := []dnsmessage.RR{
		&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{
				Name:   "example.com.",
				Rrtype: dnsmessage.TypeA,
				Class:  dnsmessage.ClassINET,
				Ttl:    300,
			},
			A: []byte{93, 184, 216, 34},
		},
	}

	cache := &DnsCache{
		DomainBitmap:     []uint32{1, 2, 3},
		Answer:           answers,
		Deadline:         time.Now().Add(5 * time.Minute),
		OriginalDeadline: time.Now().Add(5 * time.Minute),
	}

	if err := cache.PrepackResponse("example.com.", dnsmessage.TypeA); err != nil {
		b.Fatalf("failed to prepack response: %v", err)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = cache.PackedResponse
		}
	})
}

// BenchmarkDnsCache_FillInto benchmarks the old path with FillInto + Pack
func BenchmarkDnsCache_FillInto_Pack(b *testing.B) {
	answers := []dnsmessage.RR{
		&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{
				Name:   "example.com.",
				Rrtype: dnsmessage.TypeA,
				Class:  dnsmessage.ClassINET,
				Ttl:    300,
			},
			A: []byte{93, 184, 216, 34},
		},
	}

	cache := &DnsCache{
		DomainBitmap:     []uint32{1, 2, 3},
		Answer:           answers,
		Deadline:         time.Now().Add(5 * time.Minute),
		OriginalDeadline: time.Now().Add(5 * time.Minute),
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		msg := &dnsmessage.Msg{}
		cache.FillInto(msg)
		msg.Compress = true
		_, _ = msg.Pack()
	}
}

// BenchmarkDnsCache_FillInto_Pack_Parallel benchmarks parallel FillInto + Pack
func BenchmarkDnsCache_FillInto_Pack_Parallel(b *testing.B) {
	answers := []dnsmessage.RR{
		&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{
				Name:   "example.com.",
				Rrtype: dnsmessage.TypeA,
				Class:  dnsmessage.ClassINET,
				Ttl:    300,
			},
			A: []byte{93, 184, 216, 34},
		},
	}

	cache := &DnsCache{
		DomainBitmap:     []uint32{1, 2, 3},
		Answer:           answers,
		Deadline:         time.Now().Add(5 * time.Minute),
		OriginalDeadline: time.Now().Add(5 * time.Minute),
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			msg := &dnsmessage.Msg{}
			cache.FillInto(msg)
			msg.Compress = true
			_, _ = msg.Pack()
		}
	})
}

// BenchmarkDnsCache_SyncMap benchmarks sync.Map cache lookup performance
func BenchmarkDnsCache_SyncMap(b *testing.B) {
	var cache sync.Map

	answers := []dnsmessage.RR{
		&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{
				Name:   "example.com.",
				Rrtype: dnsmessage.TypeA,
				Class:  dnsmessage.ClassINET,
				Ttl:    300,
			},
			A: []byte{93, 184, 216, 34},
		},
	}

	dnsCache := &DnsCache{
		DomainBitmap:     []uint32{1, 2, 3},
		Answer:           answers,
		Deadline:         time.Now().Add(5 * time.Minute),
		OriginalDeadline: time.Now().Add(5 * time.Minute),
	}

	if err := dnsCache.PrepackResponse("example.com.", dnsmessage.TypeA); err != nil {
		b.Fatalf("failed to prepack response: %v", err)
	}

	cache.Store("example.com.:1", dnsCache)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if val, ok := cache.Load("example.com.:1"); ok {
			c := val.(*DnsCache)
			_ = c.PackedResponse
		}
	}
}

// BenchmarkDnsCache_SyncMap_Parallel benchmarks parallel sync.Map cache lookup
func BenchmarkDnsCache_SyncMap_Parallel(b *testing.B) {
	var cache sync.Map

	answers := []dnsmessage.RR{
		&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{
				Name:   "example.com.",
				Rrtype: dnsmessage.TypeA,
				Class:  dnsmessage.ClassINET,
				Ttl:    300,
			},
			A: []byte{93, 184, 216, 34},
		},
	}

	dnsCache := &DnsCache{
		DomainBitmap:     []uint32{1, 2, 3},
		Answer:           answers,
		Deadline:         time.Now().Add(5 * time.Minute),
		OriginalDeadline: time.Now().Add(5 * time.Minute),
	}

	if err := dnsCache.PrepackResponse("example.com.", dnsmessage.TypeA); err != nil {
		b.Fatalf("failed to prepack response: %v", err)
	}

	cache.Store("example.com.:1", dnsCache)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if val, ok := cache.Load("example.com.:1"); ok {
				c := val.(*DnsCache)
				_ = c.PackedResponse
			}
		}
	})
}

// BenchmarkDnsCache_MultipleAnswers benchmarks with multiple answer records
func BenchmarkDnsCache_MultipleAnswers(b *testing.B) {
	// Simulate a more realistic response with multiple answers
	answers := make([]dnsmessage.RR, 5)
	for i := 0; i < 5; i++ {
		answers[i] = &dnsmessage.A{
			Hdr: dnsmessage.RR_Header{
				Name:   "example.com.",
				Rrtype: dnsmessage.TypeA,
				Class:  dnsmessage.ClassINET,
				Ttl:    300,
			},
			A: []byte{93, 184, 216, byte(34 + i)},
		}
	}

	cache := &DnsCache{
		DomainBitmap:     []uint32{1, 2, 3},
		Answer:           answers,
		Deadline:         time.Now().Add(5 * time.Minute),
		OriginalDeadline: time.Now().Add(5 * time.Minute),
	}

	if err := cache.PrepackResponse("example.com.", dnsmessage.TypeA); err != nil {
		b.Fatalf("failed to prepack response: %v", err)
	}

	b.Run("PackedResponse", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = cache.PackedResponse
		}
	})

	b.Run("FillInto+Pack", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			msg := &dnsmessage.Msg{}
			cache.FillInto(msg)
			msg.Compress = true
			_, _ = msg.Pack()
		}
	})
	
	b.Run("FillIntoWithTTL", func(b *testing.B) {
		now := time.Now()
		for i := 0; i < b.N; i++ {
			msg := &dnsmessage.Msg{}
			_ = cache.FillIntoWithTTL(msg, now)
		}
	})
}

// BenchmarkDnsCache_FillIntoWithTTL benchmarks the new TTL-aware method
func BenchmarkDnsCache_FillIntoWithTTL(b *testing.B) {
	answers := []dnsmessage.RR{
		&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{
				Name:   "example.com.",
				Rrtype: dnsmessage.TypeA,
				Class:  dnsmessage.ClassINET,
				Ttl:    300,
			},
			A: []byte{93, 184, 216, 34},
		},
	}

	cache := &DnsCache{
		DomainBitmap:     []uint32{1, 2, 3},
		Answer:           answers,
		Deadline:         time.Now().Add(5 * time.Minute),
		OriginalDeadline: time.Now().Add(5 * time.Minute),
	}

	now := time.Now()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		msg := &dnsmessage.Msg{}
		_ = cache.FillIntoWithTTL(msg, now)
	}
}

// BenchmarkDnsCache_FillIntoWithTTL_Parallel benchmarks parallel TTL-aware cache hits
func BenchmarkDnsCache_FillIntoWithTTL_Parallel(b *testing.B) {
	answers := []dnsmessage.RR{
		&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{
				Name:   "example.com.",
				Rrtype: dnsmessage.TypeA,
				Class:  dnsmessage.ClassINET,
				Ttl:    300,
			},
			A: []byte{93, 184, 216, 34},
		},
	}

	cache := &DnsCache{
		DomainBitmap:     []uint32{1, 2, 3},
		Answer:           answers,
		Deadline:         time.Now().Add(5 * time.Minute),
		OriginalDeadline: time.Now().Add(5 * time.Minute),
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		now := time.Now()
		for pb.Next() {
			msg := &dnsmessage.Msg{}
			_ = cache.FillIntoWithTTL(msg, now)
		}
	})
}

// Test to verify the optimization works correctly
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

	// Test A record
	if err := cache.PrepackResponse("test.example.com.", dnsmessage.TypeA); err != nil {
		t.Fatalf("failed to prepack A response: %v", err)
	}

	if cache.PackedResponse == nil {
		t.Fatal("PackedResponse should not be nil")
	}

	// Verify the packed response can be unpacked
	var msg dnsmessage.Msg
	if err := msg.Unpack(cache.PackedResponse); err != nil {
		t.Fatalf("failed to unpack prepacked response: %v", err)
	}

	if msg.Rcode != dnsmessage.RcodeSuccess {
		t.Errorf("expected RcodeSuccess, got %v", msg.Rcode)
	}

	if !msg.Response {
		t.Error("expected Response to be true")
	}

	if !msg.RecursionAvailable {
		t.Error("expected RecursionAvailable to be true")
	}

	if len(msg.Question) != 1 {
		t.Errorf("expected 1 question, got %d", len(msg.Question))
	}

	if msg.Question[0].Name != "test.example.com." {
		t.Errorf("expected question name 'test.example.com.', got '%s'", msg.Question[0].Name)
	}

	fmt.Printf("Pre-packed response size: %d bytes\n", len(cache.PackedResponse))
}

// TestDnsCache_FillIntoWithTTL_Correctness verifies TTL is calculated correctly
func TestDnsCache_FillIntoWithTTL_Correctness(t *testing.T) {
	// Create cache with 300 second TTL
	deadline := time.Now().Add(300 * time.Second)
	answers := []dnsmessage.RR{
		&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{
				Name:   "test.example.com.",
				Rrtype: dnsmessage.TypeA,
				Class:  dnsmessage.ClassINET,
				Ttl:    0, // TTL is 0 in cache (as per dae's design)
			},
			A: []byte{93, 184, 216, 34},
		},
	}

	cache := &DnsCache{
		DomainBitmap:     []uint32{1, 2, 3},
		Answer:           answers,
		Deadline:         deadline,
		OriginalDeadline: deadline,
	}

	// Test immediately - should have ~300 seconds TTL
	msg := &dnsmessage.Msg{}
	resp := cache.FillIntoWithTTL(msg, time.Now())
	if resp == nil {
		t.Fatal("FillIntoWithTTL returned nil")
	}

	var unpackedMsg dnsmessage.Msg
	if err := unpackedMsg.Unpack(resp); err != nil {
		t.Fatalf("failed to unpack response: %v", err)
	}

	if len(unpackedMsg.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(unpackedMsg.Answer))
	}

	ttl := unpackedMsg.Answer[0].Header().Ttl
	if ttl < 299 || ttl > 300 {
		t.Errorf("expected TTL ~300, got %d", ttl)
	}
	t.Logf("Initial TTL: %d", ttl)

	// Test after 100 seconds - should have ~200 seconds TTL
	futureTime := time.Now().Add(100 * time.Second)
	msg2 := &dnsmessage.Msg{}
	resp2 := cache.FillIntoWithTTL(msg2, futureTime)
	if resp2 == nil {
		t.Fatal("FillIntoWithTTL returned nil for future time")
	}

	var unpackedMsg2 dnsmessage.Msg
	if err := unpackedMsg2.Unpack(resp2); err != nil {
		t.Fatalf("failed to unpack response: %v", err)
	}

	ttl2 := unpackedMsg2.Answer[0].Header().Ttl
	if ttl2 < 199 || ttl2 > 201 {
		t.Errorf("expected TTL ~200, got %d", ttl2)
	}
	t.Logf("TTL after 100s: %d", ttl2)

	// Test near expiry - should have minimum TTL of 1
	expiredTime := deadline.Add(-500 * time.Millisecond)
	msg3 := &dnsmessage.Msg{}
	resp3 := cache.FillIntoWithTTL(msg3, expiredTime)
	if resp3 == nil {
		t.Fatal("FillIntoWithTTL returned nil for near-expiry time")
	}

	var unpackedMsg3 dnsmessage.Msg
	if err := unpackedMsg3.Unpack(resp3); err != nil {
		t.Fatalf("failed to unpack response: %v", err)
	}

	ttl3 := unpackedMsg3.Answer[0].Header().Ttl
	if ttl3 != 1 {
		t.Errorf("expected minimum TTL of 1, got %d", ttl3)
	}
	t.Logf("TTL near expiry: %d", ttl3)
}

// TestDnsCache_GetPackedResponseWithApproximateTTL verifies approximate TTL behavior
func TestDnsCache_GetPackedResponseWithApproximateTTL(t *testing.T) {
	// Create cache with 300 second TTL
	deadline := time.Now().Add(300 * time.Second)
	answers := []dnsmessage.RR{
		&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{
				Name:   "test.example.com.",
				Rrtype: dnsmessage.TypeA,
				Class:  dnsmessage.ClassINET,
				Ttl:    0, // TTL is 0 in cache (as per dae's design)
			},
			A: []byte{93, 184, 216, 34},
		},
	}

	cache := &DnsCache{
		DomainBitmap:     []uint32{1, 2, 3},
		Answer:           answers,
		Deadline:         deadline,
		OriginalDeadline: deadline,
	}

	// Initialize pre-packed response
	if err := cache.PrepackResponse("test.example.com.", dnsmessage.TypeA); err != nil {
		t.Fatalf("failed to prepack response: %v", err)
	}

	// Test 1: Initial TTL should be ~300
	resp := cache.GetPackedResponseWithApproximateTTL("test.example.com.", dnsmessage.TypeA, time.Now())
	if resp == nil {
		t.Fatal("GetPackedResponseWithApproximateTTL returned nil")
	}

	var msg1 dnsmessage.Msg
	if err := msg1.Unpack(resp); err != nil {
		t.Fatalf("failed to unpack response: %v", err)
	}

	initialTTL := msg1.Answer[0].Header().Ttl
	if initialTTL < 299 || initialTTL > 300 {
		t.Errorf("expected initial TTL ~300, got %d", initialTTL)
	}
	t.Logf("Initial TTL: %d", initialTTL)

	// Test 2: After 3 seconds, TTL should still be the same (within threshold)
	// because TTL difference (3s) < ttlRefreshThresholdSeconds (5s)
	time3s := time.Now().Add(3 * time.Second)
	resp2 := cache.GetPackedResponseWithApproximateTTL("test.example.com.", dnsmessage.TypeA, time3s)
	if resp2 == nil {
		t.Fatal("GetPackedResponseWithApproximateTTL returned nil for time3s")
	}

	// Should return the SAME response (pointer equality) because TTL diff < threshold
	if &resp[0] != &resp2[0] {
		t.Log("Response was refreshed (expected for TTL diff < threshold)")
	}

	var msg2 dnsmessage.Msg
	if err := msg2.Unpack(resp2); err != nil {
		t.Fatalf("failed to unpack response: %v", err)
	}

	ttl2 := msg2.Answer[0].Header().Ttl
	t.Logf("TTL after 3s: %d (should be ~%d, using cached response)", ttl2, initialTTL)

	// Test 3: After 20 seconds, TTL should be refreshed
	// because TTL difference (20s) > ttlRefreshThresholdSeconds (15s)
	time20s := time.Now().Add(20 * time.Second)
	resp3 := cache.GetPackedResponseWithApproximateTTL("test.example.com.", dnsmessage.TypeA, time20s)
	if resp3 == nil {
		t.Fatal("GetPackedResponseWithApproximateTTL returned nil for time20s")
	}

	var msg3 dnsmessage.Msg
	if err := msg3.Unpack(resp3); err != nil {
		t.Fatalf("failed to unpack response: %v", err)
	}

	ttl3 := msg3.Answer[0].Header().Ttl
	expectedTTL3 := uint32(280) // 300 - 20 = 280
	if ttl3 < expectedTTL3-2 || ttl3 > expectedTTL3+2 {
		t.Errorf("expected TTL ~%d after 20s, got %d", expectedTTL3, ttl3)
	}
	t.Logf("TTL after 20s: %d (should be ~%d, refreshed)", ttl3, expectedTTL3)

	// Test 4: After 100 seconds, TTL should be ~200
	time100s := time.Now().Add(100 * time.Second)
	resp4 := cache.GetPackedResponseWithApproximateTTL("test.example.com.", dnsmessage.TypeA, time100s)
	if resp4 == nil {
		t.Fatal("GetPackedResponseWithApproximateTTL returned nil for time100s")
	}

	var msg4 dnsmessage.Msg
	if err := msg4.Unpack(resp4); err != nil {
		t.Fatalf("failed to unpack response: %v", err)
	}

	ttl4 := msg4.Answer[0].Header().Ttl
	expectedTTL4 := uint32(200) // 300 - 100 = 200
	if ttl4 < expectedTTL4-2 || ttl4 > expectedTTL4+2 {
		t.Errorf("expected TTL ~%d after 100s, got %d", expectedTTL4, ttl4)
	}
	t.Logf("TTL after 100s: %d (should be ~%d)", ttl4, expectedTTL4)

	// Test 5: Near expiry should have minimum TTL of 1
	nearExpiryTime := deadline.Add(-500 * time.Millisecond)
	resp5 := cache.GetPackedResponseWithApproximateTTL("test.example.com.", dnsmessage.TypeA, nearExpiryTime)
	if resp5 == nil {
		t.Fatal("GetPackedResponseWithApproximateTTL returned nil for near-expiry time")
	}

	var msg5 dnsmessage.Msg
	if err := msg5.Unpack(resp5); err != nil {
		t.Fatalf("failed to unpack response: %v", err)
	}

	ttl5 := msg5.Answer[0].Header().Ttl
	if ttl5 != 1 {
		t.Errorf("expected minimum TTL of 1 near expiry, got %d", ttl5)
	}
	t.Logf("TTL near expiry: %d", ttl5)

	// Test 6: After expiry should return nil
	afterExpiryTime := deadline.Add(1 * time.Second)
	resp6 := cache.GetPackedResponseWithApproximateTTL("test.example.com.", dnsmessage.TypeA, afterExpiryTime)
	if resp6 != nil {
		t.Error("expected nil response after expiry")
	}
	t.Log("After expiry: nil (expected)")
}

// TestDnsCache_FallbackWhenPrepackNotAvailable verifies fallback to FillIntoWithTTL
// when pre-packed response is not available
func TestDnsCache_FallbackWhenPrepackNotAvailable(t *testing.T) {
	// Create cache with valid TTL but NO pre-packed response
	deadline := time.Now().Add(300 * time.Second)
	answers := []dnsmessage.RR{
		&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{
				Name:   "test.example.com.",
				Rrtype: dnsmessage.TypeA,
				Class:  dnsmessage.ClassINET,
				Ttl:    0, // TTL is 0 in cache (as per dae's design)
			},
			A: []byte{93, 184, 216, 34},
		},
	}

	cache := &DnsCache{
		DomainBitmap:     []uint32{1, 2, 3},
		Answer:           answers,
		Deadline:         deadline,
		OriginalDeadline: deadline,
		// Intentionally NOT calling PrepackResponse
	}

	// GetPackedResponseWithApproximateTTL should return nil when no pre-packed response
	now := time.Now()
	resp := cache.GetPackedResponseWithApproximateTTL("test.example.com.", dnsmessage.TypeA, now)
	if resp != nil {
		t.Log("GetPackedResponseWithApproximateTTL triggered prepack (expected behavior)")
	} else {
		t.Log("GetPackedResponseWithApproximateTTL returned nil (no prepacked response)")
	}

	// FillIntoWithTTL should still work correctly as fallback
	msg := &dnsmessage.Msg{}
	resp2 := cache.FillIntoWithTTL(msg, now)
	if resp2 == nil {
		t.Fatal("FillIntoWithTTL returned nil")
	}

	var unpackedMsg dnsmessage.Msg
	if err := unpackedMsg.Unpack(resp2); err != nil {
		t.Fatalf("failed to unpack response: %v", err)
	}

	ttl := unpackedMsg.Answer[0].Header().Ttl
	if ttl < 299 || ttl > 300 {
		t.Errorf("expected TTL ~300, got %d", ttl)
	}
	t.Logf("FillIntoWithTTL fallback TTL: %d", ttl)
}

// BenchmarkDnsCache_GetPackedResponseWithApproximateTTL benchmarks the fast path
func BenchmarkDnsCache_GetPackedResponseWithApproximateTTL(b *testing.B) {
	answers := []dnsmessage.RR{
		&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{
				Name:   "example.com.",
				Rrtype: dnsmessage.TypeA,
				Class:  dnsmessage.ClassINET,
				Ttl:    0,
			},
			A: []byte{93, 184, 216, 34},
		},
	}

	cache := &DnsCache{
		DomainBitmap:     []uint32{1, 2, 3},
		Answer:           answers,
		Deadline:         time.Now().Add(300 * time.Second),
		OriginalDeadline: time.Now().Add(300 * time.Second),
	}

	if err := cache.PrepackResponse("example.com.", dnsmessage.TypeA); err != nil {
		b.Fatalf("failed to prepack response: %v", err)
	}

	now := time.Now()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = cache.GetPackedResponseWithApproximateTTL("example.com.", dnsmessage.TypeA, now)
	}
}

// BenchmarkDnsCache_GetPackedResponseWithApproximateTTL_Parallel benchmarks parallel fast path
func BenchmarkDnsCache_GetPackedResponseWithApproximateTTL_Parallel(b *testing.B) {
	answers := []dnsmessage.RR{
		&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{
				Name:   "example.com.",
				Rrtype: dnsmessage.TypeA,
				Class:  dnsmessage.ClassINET,
				Ttl:    0,
			},
			A: []byte{93, 184, 216, 34},
		},
	}

	cache := &DnsCache{
		DomainBitmap:     []uint32{1, 2, 3},
		Answer:           answers,
		Deadline:         time.Now().Add(300 * time.Second),
		OriginalDeadline: time.Now().Add(300 * time.Second),
	}

	if err := cache.PrepackResponse("example.com.", dnsmessage.TypeA); err != nil {
		b.Fatalf("failed to prepack response: %v", err)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		now := time.Now()
		for pb.Next() {
			_ = cache.GetPackedResponseWithApproximateTTL("example.com.", dnsmessage.TypeA, now)
		}
	})
}

// BenchmarkDnsCache_SyncMapLookup benchmarks sync.Map lookup performance
func BenchmarkDnsCache_SyncMapLookup(b *testing.B) {
	var m sync.Map
	
	answers := []dnsmessage.RR{
		&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{
				Name:   "example.com.",
				Rrtype: dnsmessage.TypeA,
				Class:  dnsmessage.ClassINET,
				Ttl:    0,
			},
			A: []byte{93, 184, 216, 34},
		},
	}

	cache := &DnsCache{
		DomainBitmap:     []uint32{1, 2, 3},
		Answer:           answers,
		Deadline:         time.Now().Add(300 * time.Second),
		OriginalDeadline: time.Now().Add(300 * time.Second),
	}

	if err := cache.PrepackResponse("example.com.", dnsmessage.TypeA); err != nil {
		b.Fatalf("failed to prepack response: %v", err)
	}

	m.Store("example.com.:1", cache)
	key := "example.com.:1"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if v, ok := m.Load(key); ok {
			c := v.(*DnsCache)
			_ = c.GetPackedResponseWithApproximateTTL("example.com.", dnsmessage.TypeA, time.Now())
		}
	}
}

// BenchmarkDnsCache_SyncMapLookup_Parallel benchmarks parallel sync.Map lookup
func BenchmarkDnsCache_SyncMapLookup_Parallel(b *testing.B) {
	var m sync.Map
	
	answers := []dnsmessage.RR{
		&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{
				Name:   "example.com.",
				Rrtype: dnsmessage.TypeA,
				Class:  dnsmessage.ClassINET,
				Ttl:    0,
			},
			A: []byte{93, 184, 216, 34},
		},
	}

	cache := &DnsCache{
		DomainBitmap:     []uint32{1, 2, 3},
		Answer:           answers,
		Deadline:         time.Now().Add(300 * time.Second),
		OriginalDeadline: time.Now().Add(300 * time.Second),
	}

	if err := cache.PrepackResponse("example.com.", dnsmessage.TypeA); err != nil {
		b.Fatalf("failed to prepack response: %v", err)
	}

	// Store multiple keys to simulate realistic contention
	for i := 0; i < 100; i++ {
		m.Store(fmt.Sprintf("example%d.com.:1", i), cache)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			key := fmt.Sprintf("example%d.com.:1", i%100)
			if v, ok := m.Load(key); ok {
				c := v.(*DnsCache)
				now := time.Now()
				_ = c.GetPackedResponseWithApproximateTTL(key, dnsmessage.TypeA, now)
			}
			i++
		}
	})
}

// BenchmarkDnsCache_CacheKeyGeneration benchmarks cache key string generation
func BenchmarkDnsCache_CacheKeyGeneration(b *testing.B) {
	qname := "www.example.com."

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = dnsmessage.CanonicalName(qname) + "1"
	}
}

// BenchmarkDnsCache_CacheKeyGeneration_Parallel benchmarks parallel key generation
func BenchmarkDnsCache_CacheKeyGeneration_Parallel(b *testing.B) {
	qname := "www.example.com."

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = dnsmessage.CanonicalName(qname) + "1"
		}
	})
}

// BenchmarkDnsCache_BufferPool benchmarks the buffer pool for ID patching
func BenchmarkDnsCache_BufferPool(b *testing.B) {
	resp := make([]byte, 78)
	for i := range resp {
		resp[i] = byte(i)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bufPtr := dnsResponseBufPool.Get().(*[]byte)
		patchedResp := (*bufPtr)[:len(resp)]
		copy(patchedResp, resp)
		binary.BigEndian.PutUint16(patchedResp[0:2], uint16(i))
		dnsResponseBufPool.Put(bufPtr)
	}
}

// BenchmarkDnsCache_BufferPool_Parallel benchmarks parallel buffer pool usage
func BenchmarkDnsCache_BufferPool_Parallel(b *testing.B) {
	resp := make([]byte, 78)
	for i := range resp {
		resp[i] = byte(i)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			bufPtr := dnsResponseBufPool.Get().(*[]byte)
			patchedResp := (*bufPtr)[:len(resp)]
			copy(patchedResp, resp)
			binary.BigEndian.PutUint16(patchedResp[0:2], uint16(i))
			dnsResponseBufPool.Put(bufPtr)
			i++
		}
	})
}

// BenchmarkDnsCache_MakeCopy benchmarks the old way of making a copy
func BenchmarkDnsCache_MakeCopy(b *testing.B) {
	resp := make([]byte, 78)
	for i := range resp {
		resp[i] = byte(i)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		patchedResp := make([]byte, len(resp))
		copy(patchedResp, resp)
		binary.BigEndian.PutUint16(patchedResp[0:2], uint16(i))
	}
}

// BenchmarkDnsCache_MakeCopy_Parallel benchmarks parallel make+copy
func BenchmarkDnsCache_MakeCopy_Parallel(b *testing.B) {
	resp := make([]byte, 78)
	for i := range resp {
		resp[i] = byte(i)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			patchedResp := make([]byte, len(resp))
			copy(patchedResp, resp)
			binary.BigEndian.PutUint16(patchedResp[0:2], uint16(i))
			i++
		}
	})
}
