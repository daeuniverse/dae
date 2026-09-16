/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package trie

import (
	"net/netip"
	"testing"
)

func TestTrie(t *testing.T) {
	trie, err := NewTrie([]string{
		"moc.cbatnetnoc.",
		"moc.cbatnetnoc^",
		"nc.",
		"ua.moc.cbci.",
		"ua.moc.cbci^",
		"ua.moc.duolcababila.",
		"ua.moc.duolcababila^",
		"udiab.",
		"udiab^",
		"ue.cbci.",
		"ue.cbci^",
		"uhos.",
		"uhos^",
		"ul.cbci.",
		"ul.cbci^",
		"ur.dj.",
		"ur.dj^",
		"ur.llamt.",
		"ur.llamt^",
		"ur.sserpxeila.",
		"ur.sserpxeila^",
		"ur.wocsomcbci.",
		"ur.wocsomcbci^",
		"vt.32b.",
		"vt.32b^",
		"vt.akoaix.",
		"vt.akoaix^",
		"vt.eesia.",
		"vt.eesia^",
		"vt.eiq.",
		"vt.eiq^",
		"vt.gca.",
		"vt.gca^",
		"vt.ilibilib.",
		"vt.ilibilib^",
		"vt.iqnahz.",
		"vt.iqnahz^",
		"vt.ixiy.",
		"vt.ixiy^",
		"vt.low.",
		"vt.low^",
		"vt.nc361.",
		"vt.nc361^",
		"vt.obihzgnahs.",
		"vt.obihzgnahs^",
		"vt.ogmi.",
		"vt.ogmi^",
		"vt.spp.",
		"vt.spp^",
		"vt.uohsuhc.",
		"vt.uohsuhc^",
		"vt.uyuod.",
		"vt.uyuod^",
		"vt.vtig.",
		"vt.vtig^",
		"vt.vtnh.",
		"vt.vtnh^",
		"vt.zcbj.",
		"vt.zcbj^",
		"wk.moc.cbci.",
		"wk.moc.cbci^",
		"wt.moc.duolcababila.",
		"wt.moc.duolcababila^",
		"wt.moc.levarthh.",
		"wt.moc.levarthh^",
		"xc.f.",
		"xc.f^",
		"xm.moc.cbci.",
		"xm.moc.cbci^",
		"yapila.",
		"yapila^",
		"yl.lacisum.",
		"yl.lacisum^",
		"ym.moc.duolcababila.",
		"ym.moc.duolcababila^",
		"ym.pirtc.",
		"ym.pirtc^",
		"zib.anihcbmc.",
		"zib.anihcbmc^",
		"zib.duolcsndz.",
		"zib.duolcsndz^",
		"zib.fmc.",
		"zib.fmc^",
		"zk.ytamlacbci.",
		"zk.ytamlacbci^",
		"nc.ude.ctsu.srorrim.pct_.sptth_", // https://github.com/daeuniverse/daed/issues/400
	}, NewValidChars([]byte("0123456789abcdefghijklmnopqrstuvwxyz-.^_")))
	if err != nil {
		t.Fatal(err)
	}
	if trie.HasPrefix("nc.tset^") != true {
		t.Fatal("^test.cn")
	}
	if trie.HasPrefix("nc^") != false {
		t.Fatal("^cn")
	}
	if trie.HasPrefix("nc.") != true {
		t.Fatal(".cn")
	}
	if trie.HasPrefix("nc.^") != true {
		t.Fatal("^.cn")
	}
	if trie.HasPrefix("nc._") != true {
		t.Fatal("_.cn")
	}
	if trie.HasPrefix("n") != false {
		t.Fatal("n")
	}
	if trie.HasPrefix("n^") != false {
		t.Fatal("^n")
	}
	if trie.HasPrefix("moc.cbatnetnoc^") != true {
		t.Fatal("contentabc.com")
	}
}

func TestNewTrieFromPrefixesEmpty(t *testing.T) {
	// An empty prefix set must build a trie that matches nothing instead of
	// panicking (reachable via empty geoip expansion).
	tr, err := NewTrieFromPrefixes(nil)
	if err != nil {
		t.Fatalf("NewTrieFromPrefixes(nil): %v", err)
	}
	if tr.HasPrefix("") || tr.HasPrefix("0") || tr.HasPrefix("010101") {
		t.Fatalf("empty trie must not match anything")
	}

	tr, err = NewTrieFromPrefixes([]netip.Prefix{})
	if err != nil {
		t.Fatalf("NewTrieFromPrefixes(empty): %v", err)
	}
	if tr.HasPrefix("") || tr.HasPrefix("1") {
		t.Fatalf("empty trie must not match anything")
	}

	// Sanity: a non-empty trie still matches.
	tr, err = NewTrieFromPrefixes([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")})
	if err != nil {
		t.Fatalf("NewTrieFromPrefixes: %v", err)
	}
	if !tr.HasPrefix(Prefix2bin128(netip.MustParsePrefix("10.1.2.3/32"))) {
		t.Fatalf("10.0.0.0/8 should match 10.1.2.3")
	}
}

// TestPrefix2bin128NormalizesIPv4MappedPrefixes is a regression guard: an
// IPv4-mapped prefix written with an IPv4 bit count (::ffff:1.2.3.0/24, the
// shape produced by 16-byte geoip encodings) used to be stored as the first
// 24 bits of the mapped form - all zero - so it matched every IPv4 address.
func TestPrefix2bin128NormalizesIPv4MappedPrefixes(t *testing.T) {
	mapped := Prefix2bin128(netip.MustParsePrefix("::ffff:1.2.3.0/24"))
	plain := Prefix2bin128(netip.MustParsePrefix("1.2.3.0/24"))
	if mapped != plain {
		t.Fatalf("mapped prefix bin = %q (%d bits), want %q (%d bits)",
			mapped, len(mapped), plain, len(plain))
	}
	if len(mapped) != 96+24 {
		t.Fatalf("mapped prefix bin length = %d, want 120", len(mapped))
	}
	// The RFC 4291 spelling of the same network must normalize identically.
	if got := Prefix2bin128(netip.MustParsePrefix("::ffff:1.2.3.0/120")); got != plain {
		t.Fatalf("::ffff:1.2.3.0/120 bin = %q, want %q", got, plain)
	}
	// A plain IPv6 prefix must keep its 128-bit reading.
	if got := Prefix2bin128(netip.MustParsePrefix("2001:db8::/32")); len(got) != 32 {
		t.Fatalf("2001:db8::/32 bin length = %d, want 32", len(got))
	}
}

func TestTrieIPv4MappedPrefixDoesNotMatchAllIPv4(t *testing.T) {
	tr, err := NewTrieFromPrefixes([]netip.Prefix{netip.MustParsePrefix("::ffff:1.2.3.0/24")})
	if err != nil {
		t.Fatalf("NewTrieFromPrefixes: %v", err)
	}
	lookup := func(addr string) bool {
		// Mirror the production query encoding: addresses always enter as
		// 16 bytes, so IPv4 is looked up in its ::ffff: mapped form.
		a := netip.MustParseAddr(addr).As16()
		return tr.HasPrefix(Prefix2bin128(netip.PrefixFrom(netip.AddrFrom16(a), 128)))
	}
	for _, addr := range []string{"1.2.3.4", "1.2.3.255"} {
		if !lookup(addr) {
			t.Fatalf("::ffff:1.2.3.0/24 should match %v", addr)
		}
	}
	for _, addr := range []string{"8.8.8.8", "1.2.4.1", "192.168.1.1", "2001:db8::1"} {
		if lookup(addr) {
			t.Fatalf("regression: ::ffff:1.2.3.0/24 must not match %v", addr)
		}
	}
}
