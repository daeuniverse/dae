/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package common

import "testing"

func TestParseGroupChain(t *testing.T) {
	tests := []struct {
		name      string
		link      string
		wantMatch bool
		wantErr   bool
	}{
		{name: "valid", link: "hk_to_us: group(HK) -> vmess://exit", wantMatch: true},
		{name: "ordinary node", link: "hk: vmess://node"},
		{name: "ordinary chain", link: "chain: tuic://entry -> vmess://exit"},
		{name: "group exit", link: "bad: vmess://entry -> group(US)", wantMatch: true, wantErr: true},
		{name: "group to group", link: "bad: group(HK) -> group(US)", wantMatch: true, wantErr: true},
		{name: "nested", link: "bad: group(HK) -> vmess://middle -> vmess://exit", wantMatch: true, wantErr: true},
		{name: "empty group", link: "bad: group() -> vmess://exit", wantMatch: true, wantErr: true},
		{name: "malformed group", link: "bad: group(HK -> vmess://exit", wantMatch: true, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, matched, err := ParseGroupChain(tt.link)
			if matched != tt.wantMatch {
				t.Fatalf("matched = %v, want %v", matched, tt.wantMatch)
			}
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.name == "valid" {
				if got.Name != "hk_to_us" || got.EntryGroup != "HK" || got.ExitLink != "vmess://exit" {
					t.Fatalf("unexpected parse result: %#v", got)
				}
			}
		})
	}
}
