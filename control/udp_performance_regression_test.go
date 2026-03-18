/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net/netip"
	"testing"
)

// BenchmarkNormalizeSendPktAddrFamily_Old benchmarks the OLD simple version.
func BenchmarkNormalizeSendPktAddrFamily_Old(b *testing.B) {
	from := mustParseAddrPort("[::1]:12345")
	realTo := mustParseAddrPort("192.168.1.1:53")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		normalizeSendPktAddrFamilyOld(from, realTo)
	}
}

// BenchmarkNormalizeSendPktAddrFamily_New benchmarks the NEW complex version.
func BenchmarkNormalizeSendPktAddrFamily_New(b *testing.B) {
	from := mustParseAddrPort("[::1]:12345")
	realTo := mustParseAddrPort("192.168.1.1:53")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		normalizeSendPktAddrFamily(from, realTo)
	}
}

// BenchmarkNormalizeSendPktAddrFamily_IPv4ToIPv6_Old benchmarks IPv4 to IPv6 (old).
func BenchmarkNormalizeSendPktAddrFamily_IPv4ToIPv6_Old(b *testing.B) {
	from := mustParseAddrPort("192.168.1.1:12345")
	realTo := mustParseAddrPort("[::1]:53")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		normalizeSendPktAddrFamilyOld(from, realTo)
	}
}

// BenchmarkNormalizeSendPktAddrFamily_IPv4ToIPv6_New benchmarks IPv4 to IPv6 (new).
func BenchmarkNormalizeSendPktAddrFamily_IPv4ToIPv6_New(b *testing.B) {
	from := mustParseAddrPort("192.168.1.1:12345")
	realTo := mustParseAddrPort("[::1]:53")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		normalizeSendPktAddrFamily(from, realTo)
	}
}

// BenchmarkNormalizeSendPktAddrFamily_SameFamily_Old benchmarks same-family (old).
func BenchmarkNormalizeSendPktAddrFamily_SameFamily_Old(b *testing.B) {
	from := mustParseAddrPort("192.168.1.1:12345")
	realTo := mustParseAddrPort("192.168.1.2:53")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		normalizeSendPktAddrFamilyOld(from, realTo)
	}
}

// BenchmarkNormalizeSendPktAddrFamily_SameFamily_New benchmarks same-family (new).
func BenchmarkNormalizeSendPktAddrFamily_SameFamily_New(b *testing.B) {
	from := mustParseAddrPort("192.168.1.1:12345")
	realTo := mustParseAddrPort("192.168.1.2:53")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		normalizeSendPktAddrFamily(from, realTo)
	}
}

// normalizeSendPktAddrFamilyOld is the OLD simple version from a8d0e81.
func normalizeSendPktAddrFamilyOld(from, realTo netip.AddrPort) (bindAddr, writeAddr netip.AddrPort) {
	bindAddr = from
	writeAddr = realTo

	// Case 1: IPv6 socket writing to IPv4 target.
	if realTo.Addr().Is4() && from.Addr().Is6() {
		writeAddr = netip.AddrPortFrom(
			netip.AddrFrom16(realTo.Addr().As16()),
			realTo.Port(),
		)
	}

	// Case 2: IPv4 source with IPv6 destination (including IPv4-mapped IPv6)
	// should use an IPv6 bind address so socket family matches write target.
	if from.Addr().Is4() && realTo.Addr().Is6() {
		bindAddr = netip.AddrPortFrom(
			netip.AddrFrom16(from.Addr().As16()),
			from.Port(),
		)
	}

	return bindAddr, writeAddr
}

func mustParseAddrPort(s string) netip.AddrPort {
	addr, err := netip.ParseAddrPort(s)
	if err != nil {
		panic(err)
	}
	return addr
}
