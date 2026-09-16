/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"testing"

	dnsmessage "github.com/miekg/dns"
)

// buildLargeDNSResponse builds a DNS response with many A records whose
// packed size exceeds the classic 512-byte UDP limit (e.g. a CDN returning
// 35 A records).
func buildLargeDNSResponse(t *testing.T, count int) []byte {
	t.Helper()
	msg := &dnsmessage.Msg{}
	msg.SetQuestion("cdn.example.com.", dnsmessage.TypeA)
	msg.Response = true
	msg.RecursionAvailable = true
	for range count {
		rr, err := dnsmessage.NewRR("cdn.example.com. 300 IN A 203.0.113.1")
		if err != nil {
			t.Fatalf("NewRR: %v", err)
		}
		msg.Answer = append(msg.Answer, rr)
	}
	data, err := msg.Pack()
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	return data
}

func TestTruncateDNSResponse(t *testing.T) {
	// 35 A records exceed 512 bytes (the reported bug: CDN returns 35 A
	// records, packed size > 512, client got "noerror, 0 answer, tc=0").
	packed := buildLargeDNSResponse(t, 35)
	if len(packed) <= dnsDefaultUDPSize {
		t.Fatalf("test fixture too small: packed = %d bytes, want > %d", len(packed), dnsDefaultUDPSize)
	}

	truncated := truncateDNSResponse(packed, dnsDefaultUDPSize)

	var resp dnsmessage.Msg
	if err := resp.Unpack(truncated); err != nil {
		t.Fatalf("Unpack truncated response: %v", err)
	}
	if !resp.Truncated {
		t.Fatal("truncated response must set TC bit")
	}
	if len(truncated) > dnsDefaultUDPSize {
		t.Fatalf("truncated response still too large: %d > %d", len(truncated), dnsDefaultUDPSize)
	}
	if len(resp.Answer) == 0 {
		t.Fatal("truncated response should keep at least the answers that fit")
	}
	if len(resp.Question) == 0 {
		t.Fatal("truncated response must keep the question")
	}
}

func TestTruncateDNSResponseSmall(t *testing.T) {
	// Responses within the limit must pass through untouched.
	packed := buildLargeDNSResponse(t, 2)
	truncated := truncateDNSResponse(packed, dnsDefaultUDPSize)
	if len(truncated) != len(packed) {
		t.Fatalf("small response was modified: %d -> %d bytes", len(packed), len(truncated))
	}
}

func TestDnsUDPResponseSizeLimit(t *testing.T) {
	// No EDNS0 -> classic 512.
	req := &dnsmessage.Msg{}
	req.SetQuestion("example.com.", dnsmessage.TypeA)
	if got := dnsUDPResponseSizeLimit(req); got != 512 {
		t.Fatalf("no-EDNS0 limit = %d, want 512", got)
	}

	// EDNS0 with 4096 -> 4096.
	req.SetEdns0(4096, true)
	if got := dnsUDPResponseSizeLimit(req); got != 4096 {
		t.Fatalf("EDNS0 4096 limit = %d, want 4096", got)
	}

	// EDNS0 below 512 must be clamped up to 512 (RFC 6891 6.2.5).
	req.SetEdns0(128, true)
	if got := dnsUDPResponseSizeLimit(req); got != 512 {
		t.Fatalf("EDNS0 128 limit = %d, want 512", got)
	}
}
