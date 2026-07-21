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
		{name: "valid", link: "hk_to_us: vmess://endpoint -> group(HK)", wantMatch: true},
		{name: "ordinary node", link: "hk: vmess://node"},
		{name: "ordinary chain", link: "chain: vmess://endpoint -> tuic://relay"},
		{name: "ordinary long chain", link: "chain: vmess://endpoint -> tuic://relay-1 -> vless://relay-2"},
		{name: "group on endpoint side", link: "bad: group(US) -> vmess://relay", wantMatch: true, wantErr: true},
		{name: "group to group", link: "bad: group(HK) -> group(US)", wantMatch: true, wantErr: true},
		{name: "nested", link: "bad: vmess://endpoint -> vmess://relay -> group(HK)", wantMatch: true, wantErr: true},
		{name: "empty group", link: "bad: vmess://endpoint -> group()", wantMatch: true, wantErr: true},
		{name: "malformed group", link: "bad: vmess://endpoint -> group(HK", wantMatch: true, wantErr: true},
		{name: "empty endpoint", link: "bad: -> group(HK)", wantMatch: true, wantErr: true},
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
				if got.Name != "hk_to_us" || got.EntryGroup != "HK" || got.EndpointLink != "vmess://endpoint" {
					t.Fatalf("unexpected parse result: %#v", got)
				}
			}
		})
	}
}
