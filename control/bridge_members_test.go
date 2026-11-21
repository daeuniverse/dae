/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"reflect"
	"testing"
)

func TestSelectBridgePortsPicksOnlyMembers(t *testing.T) {
	// A bridge forwards on its ports; the master itself only receives traffic
	// addressed to it. The observer therefore has to follow the ports.
	links := []bridgeLinkInfo{
		{name: "lan-home", index: 8},
		{name: "eth0", index: 5, master: 8},
		{name: "eth2.5", index: 9, master: 8},
		{name: "eth3", index: 6},
		{name: "wg0", index: 12},
	}
	got := selectBridgePorts(8, links)
	want := []string{"eth0", "eth2.5"}
	if len(got) != len(want) {
		t.Fatalf("ports = %+v, want %v", got, want)
	}
	for i, name := range want {
		if got[i].name != name {
			t.Fatalf("ports = %+v, want %v", got, want)
		}
	}
}

func TestSelectBridgePortsIgnoresSelfMembership(t *testing.T) {
	// Some layouts report the bridge as its own master; selecting it would stage
	// the same hook twice and make the log read as if a port were found.
	links := []bridgeLinkInfo{{name: "br0", index: 3, master: 3}}
	if got := selectBridgePorts(3, links); len(got) != 0 {
		t.Fatalf("ports = %+v, want none", got)
	}
}

func TestSelectBridgePortsIsStable(t *testing.T) {
	links := []bridgeLinkInfo{
		{name: "eth2.5", index: 9, master: 8},
		{name: "eth0", index: 5, master: 8},
	}
	first := selectBridgePorts(8, links)
	second := selectBridgePorts(8, links)
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("selection is not deterministic: %+v vs %+v", first, second)
	}
}
