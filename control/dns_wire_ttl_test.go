/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net"
	"testing"

	dnsmessage "github.com/miekg/dns"
)

func mustPackMsg(t *testing.T, msg *dnsmessage.Msg) []byte {
	t.Helper()
	wire, err := msg.Pack()
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	return wire
}

func unpackWire(t *testing.T, wire []byte) *dnsmessage.Msg {
	t.Helper()
	var msg dnsmessage.Msg
	if err := msg.Unpack(wire); err != nil {
		t.Fatalf("unpack: %v", err)
	}
	return &msg
}

func rrTtls(t *testing.T, msg *dnsmessage.Msg) []uint32 {
	t.Helper()
	var ttls []uint32
	for _, rr := range msg.Answer {
		ttls = append(ttls, rr.Header().Ttl)
	}
	for _, rr := range msg.Ns {
		ttls = append(ttls, rr.Header().Ttl)
	}
	for _, rr := range msg.Extra {
		if rr.Header().Rrtype == dnsRRTypeOpt {
			continue
		}
		ttls = append(ttls, rr.Header().Ttl)
	}
	return ttls
}

func TestClampWireRecordTtlsBasic(t *testing.T) {
	msg := new(dnsmessage.Msg)
	msg.SetQuestion("example.com.", dnsmessage.TypeA)
	msg.Response = true
	msg.Answer = []dnsmessage.RR{
		&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{Name: "example.com.", Rrtype: dnsmessage.TypeA, Class: dnsmessage.ClassINET, Ttl: 86400},
			A:   netip4(192, 0, 2, 1),
		},
		&dnsmessage.CNAME{
			Hdr:    dnsmessage.RR_Header{Name: "www.example.com.", Rrtype: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, Ttl: 30},
			Target: "example.com.",
		},
	}
	msg.Extra = []dnsmessage.RR{
		&dnsmessage.OPT{Hdr: dnsmessage.RR_Header{Name: ".", Rrtype: dnsRRTypeOpt, Class: 4096}},
	}
	wire := mustPackMsg(t, msg)

	out := clampWireRecordTtls(wire, 30)
	if out == nil {
		t.Fatal("clamp returned nil on a valid message")
	}
	got := unpackWire(t, out)
	ttls := rrTtls(t, got)
	if len(ttls) != 2 {
		t.Fatalf("expected 2 real RRs, got %d", len(ttls))
	}
	if ttls[0] != 30 {
		t.Fatalf("A ttl = %d, want 30 (clamped)", ttls[0])
	}
	if ttls[1] != 30 {
		t.Fatalf("CNAME ttl = %d, want 30 (already below bound unchanged)", ttls[1])
	}
	// OPT flags field must be untouched: byte 11 of the RR (name(1)+type(2)+
	// class(2) => flags start at offset 11 from the RR start).
	opt := got.Extra[0].(*dnsmessage.OPT)
	if opt.Hdr.Ttl != 0 {
		t.Fatalf("OPT header field mutated: %d", opt.Hdr.Ttl)
	}
}

func TestClampWireRecordTtlsLeavesZeroTtlAndOpt(t *testing.T) {
	msg := new(dnsmessage.Msg)
	msg.SetQuestion("example.com.", dnsmessage.TypeAAAA)
	msg.Response = true
	msg.Answer = []dnsmessage.RR{
		// dae-managed zero-TTL AAAA (downstream caching managed by dae).
		&dnsmessage.AAAA{
			Hdr:  dnsmessage.RR_Header{Name: "example.com.", Rrtype: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET, Ttl: 0},
			AAAA: netip16(),
		},
	}
	msg.Extra = []dnsmessage.RR{
		&dnsmessage.OPT{Hdr: dnsmessage.RR_Header{Name: ".", Rrtype: dnsRRTypeOpt, Class: 1232}},
	}
	wire := mustPackMsg(t, msg)

	out := clampWireRecordTtls(wire, 30)
	if out == nil {
		t.Fatal("clamp returned nil on a valid message")
	}
	got := unpackWire(t, out)
	ttls := rrTtls(t, got)
	if len(ttls) != 1 {
		t.Fatalf("expected 1 real RR, got %d", len(ttls))
	}
	if ttls[0] != 0 {
		t.Fatalf("zero-TTL record must stay zero, got %d", ttls[0])
	}
}

func TestClampWireRecordTtlsRejectsMalformed(t *testing.T) {
	msg := new(dnsmessage.Msg)
	msg.SetQuestion("example.com.", dnsmessage.TypeA)
	msg.Response = true
	msg.Answer = []dnsmessage.RR{
		&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{Name: "example.com.", Rrtype: dnsmessage.TypeA, Class: dnsmessage.ClassINET, Ttl: 3600},
			A:   netip4(192, 0, 2, 2),
		},
	}
	wire := mustPackMsg(t, msg)
	// Truncate in the middle of the RDATA.
	if out := clampWireRecordTtls(wire[:len(wire)-2], 30); out != nil {
		t.Fatal("clamp must reject truncated messages")
	}
	// Trailing garbage after the last RR must also be rejected.
	withGarbage := append(append([]byte(nil), wire...), 0xde, 0xad)
	if out := clampWireRecordTtls(withGarbage, 30); out != nil {
		t.Fatal("clamp must reject trailing garbage")
	}
	// No-op bound must return nil (caller keeps the original bytes).
	if out := clampWireRecordTtls(wire, 0); out != nil {
		t.Fatal("zero bound must yield nil")
	}
}

func TestClampWireRecordTtlsCompressedNames(t *testing.T) {
	msg := new(dnsmessage.Msg)
	msg.SetQuestion("a.very.long.example.com.", dnsmessage.TypeA)
	msg.Response = true
	// A chain whose names share suffixes exercises compression pointers.
	msg.Answer = []dnsmessage.RR{
		&dnsmessage.CNAME{
			Hdr:    dnsmessage.RR_Header{Name: "b.very.long.example.com.", Rrtype: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, Ttl: 7200},
			Target: "c.very.long.example.com.",
		},
		&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{Name: "c.very.long.example.com.", Rrtype: dnsmessage.TypeA, Class: dnsmessage.ClassINET, Ttl: 86400},
			A:   netip4(203, 0, 113, 9),
		},
	}
	msg.SetEdns0(1232, true)
	// Force a packed message with compression.
	msg.Compress = true
	wire := mustPackMsg(t, msg)
	if out := clampWireRecordTtls(wire, 30); out != nil {
		got := unpackWire(t, out)
		ttls := rrTtls(t, got)
		for i, ttl := range ttls {
			if ttl > 30 {
				t.Fatalf("RR %d ttl = %d, want <= 30", i, ttl)
			}
		}
	} else {
		t.Fatal("clamp rejected a valid compressed message")
	}
}

func netip4(a, b, c, d byte) net.IP {
	return net.IPv4(a, b, c, d).To4()
}

func netip16() net.IP {
	return net.ParseIP("2001:db8::1")
}
