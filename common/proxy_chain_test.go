/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package common

import "testing"

func TestParseProxyChain(t *testing.T) {
	tests := []struct {
		name      string
		link      string
		wantMatch bool
		wantErr   bool
	}{
		{name: "single node", link: "node: vmess://one"},
		{name: "two nodes", link: "chain: tuic://entry -> vmess://exit", wantMatch: true},
		{name: "three nodes", link: "chain: tuic://a -> vmess://b -> vless://c", wantMatch: true, wantErr: true},
		{name: "empty entry", link: "chain: -> vmess://exit", wantMatch: true, wantErr: true},
		{name: "empty exit", link: "chain: tuic://entry ->", wantMatch: true, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, matched, err := ParseProxyChain(tt.link)
			if matched != tt.wantMatch {
				t.Fatalf("matched = %v, want %v", matched, tt.wantMatch)
			}
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.name == "two nodes" {
				if got.Name != "chain" || got.EntryLink != "tuic://entry" || got.ExitLink != "vmess://exit" {
					t.Fatalf("unexpected chain: %#v", got)
				}
			}
		})
	}
}
