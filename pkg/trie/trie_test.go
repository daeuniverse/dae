/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2023, daeuniverse Organization <dae@v2raya.org>
 */

package trie

import "testing"

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
	if !(trie.HasPrefix("nc.tset^") == true) {
		t.Fatal("^test.cn")
	}
	if !(trie.HasPrefix("nc^") == false) {
		t.Fatal("^cn")
	}
	if !(trie.HasPrefix("nc.") == true) {
		t.Fatal(".cn")
	}
	if !(trie.HasPrefix("nc.^") == true) {
		t.Fatal("^.cn")
	}
	if !(trie.HasPrefix("nc._") == true) {
		t.Fatal("_.cn")
	}
	if !(trie.HasPrefix("n") == false) {
		t.Fatal("n")
	}
	if !(trie.HasPrefix("n^") == false) {
		t.Fatal("^n")
	}
	if !(trie.HasPrefix("moc.cbatnetnoc^") == true) {
		t.Fatal("contentabc.com")
	}
}
