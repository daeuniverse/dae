/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net/netip"
	"testing"
)

// D3 measurement: AddrPort.String + ParseAddrPort is the remaining roundtrip
// on FullCone WriteTo. Symmetric already reuses ue.DialTarget (e30de886).
// These numbers exist so a later round can decide whether an optional
// WriteToAddrPort is worth crossing the PacketConn string API. Do not treat
// a win here as a hotspot: existing research puts write syscall ~31% vs
// String ~7.7% samples / 1.5% alloc, and outbound LastStringValue already
// caches parse of a repeated target string.
func BenchmarkUdpWriteStringRoundtrip(b *testing.B) {
	dst := netip.MustParseAddrPort("203.0.113.10:443")
	ueFullCone := &UdpEndpoint{}
	ueSymmetric := &UdpEndpoint{DialTarget: dst.String()}
	ueSymmetric.poolKey.Dst = dst

	b.Run("fullcone_String", func(b *testing.B) {
		var s string
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			s = ueFullCone.dialTargetForWrite(dst)
		}
		sinkString = s
	})
	b.Run("symmetric_DialTarget", func(b *testing.B) {
		var s string
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			s = ueSymmetric.dialTargetForWrite(dst)
		}
		sinkString = s
	})
	b.Run("ParseAddrPort", func(b *testing.B) {
		s := dst.String()
		var ap netip.AddrPort
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			ap, _ = netip.ParseAddrPort(s)
		}
		sinkAddrPort = ap
	})
	b.Run("String_then_ParseAddrPort", func(b *testing.B) {
		var ap netip.AddrPort
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			ap, _ = netip.ParseAddrPort(ueFullCone.dialTargetForWrite(dst))
		}
		sinkAddrPort = ap
	})
}

var (
	sinkString   string
	sinkAddrPort netip.AddrPort
)
