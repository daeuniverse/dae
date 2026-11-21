/*
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package netutils

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	dnsmessage "github.com/miekg/dns"
)

// startUDPDNSRcode starts a UDP DNS responder that answers every query with
// rcode and no answer records: what a failing or empty upstream looks like on
// the wire, without needing a real resolver.
func startUDPDNSRcode(t *testing.T, rcode int) netip.AddrPort {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, maxDNSMessageSize)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var req dnsmessage.Msg
			if err := req.Unpack(buf[:n]); err != nil {
				continue
			}
			resp := new(dnsmessage.Msg)
			resp.SetReply(&req)
			resp.Rcode = rcode
			out, err := resp.Pack()
			if err != nil {
				continue
			}
			_, _ = pc.WriteTo(out, addr)
		}
	}()
	return netip.MustParseAddrPort(pc.LocalAddr().String())
}

func packedAnswer(t *testing.T, rcode int, withA bool) ([]byte, uint16) {
	t.Helper()
	m := new(dnsmessage.Msg)
	m.SetQuestion("example.com.", dnsmessage.TypeA)
	m.Response = true
	m.RecursionAvailable = true
	m.Rcode = rcode
	if withA {
		m.Answer = append(m.Answer, &dnsmessage.A{
			Hdr: dnsmessage.RR_Header{
				Name:   "example.com.",
				Rrtype: dnsmessage.TypeA,
				Class:  dnsmessage.ClassINET,
				Ttl:    60,
			},
			A: net.IPv4(93, 184, 216, 34).To4(),
		})
	}
	const id = 0x4242
	m.Id = id
	b, err := m.Pack()
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	return b, id
}

func TestDecodeResolvedAnswerRcode(t *testing.T) {
	for _, tc := range []struct {
		name     string
		rcode    int
		withA    bool
		wantErr  bool
		wantAnsw int
	}{
		{"success with record", dnsmessage.RcodeSuccess, true, false, 1},
		{"success without record", dnsmessage.RcodeSuccess, false, false, 0},
		{"nxdomain", dnsmessage.RcodeNameError, false, false, 0},
		{"servfail", dnsmessage.RcodeServerFailure, false, true, 0},
		{"refused", dnsmessage.RcodeRefused, false, true, 0},
		{"formerr", dnsmessage.RcodeFormatError, false, true, 0},
		{"notimp", dnsmessage.RcodeNotImplemented, false, true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload, id := packedAnswer(t, tc.rcode, tc.withA)
			got := decodeResolvedAnswer(payload, id)
			if tc.wantErr != (got.err != nil) {
				t.Fatalf("err: got %v, wantErr %v", got.err, tc.wantErr)
			}
			if len(got.ans) != tc.wantAnsw {
				t.Fatalf("answers: got %d, want %d", len(got.ans), tc.wantAnsw)
			}
		})
	}
}

func TestResolveNetipSERVFAILReturnsError(t *testing.T) {
	srv := startUDPDNSRcode(t, dnsmessage.RcodeServerFailure)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	addrs, err := ResolveNetip(ctx, stdNetDialer{}, srv, "example.com", dnsmessage.TypeA, "udp")
	if err == nil {
		t.Fatalf("SERVFAIL must be reported as an error, got addrs=%v err=nil", addrs)
	}
}

func TestResolveIp46SERVFAILReportsBothLegs(t *testing.T) {
	srv := startUDPDNSRcode(t, dnsmessage.RcodeServerFailure)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ip46, err4, err6 := ResolveIp46(ctx, stdNetDialer{}, srv, "example.com", "udp", false)
	if ip46.Ip4.IsValid() || ip46.Ip6.IsValid() {
		t.Fatalf("unexpected addresses: %v %v", ip46.Ip4, ip46.Ip6)
	}
	if err4 == nil || err6 == nil {
		t.Fatalf("both legs got SERVFAIL but reported err4=%v err6=%v", err4, err6)
	}
}

// NXDOMAIN has to stay a non-error. Callers key their negative caches off
// err == nil (see probeAndUpdateRealDomain), so turning it into an error would
// drop that cache and make every lookup of a non-existent name re-probe.
func TestResolveIp46NXDOMAINStaysNonError(t *testing.T) {
	srv := startUDPDNSRcode(t, dnsmessage.RcodeNameError)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ip46, err4, err6 := ResolveIp46(ctx, stdNetDialer{}, srv, "example.com", "udp", false)
	if ip46.Ip4.IsValid() || ip46.Ip6.IsValid() {
		t.Fatalf("unexpected addresses: %v %v", ip46.Ip4, ip46.Ip6)
	}
	if err4 != nil || err6 != nil {
		t.Fatalf("NXDOMAIN must stay a non-error, got err4=%v err6=%v", err4, err6)
	}
}
