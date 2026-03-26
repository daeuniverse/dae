/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
)

func TestUpdateConnStateJanitorPressureActivatesOnOverflow(t *testing.T) {
	state := updateConnStateJanitorPressure(connStateJanitorPressureState{}, true, 0)
	if !state.active {
		t.Fatal("expected pressure mode to activate on overflow")
	}
	if state.belowThresholdRounds != 0 {
		t.Fatalf("expected belowThresholdRounds to reset, got %d", state.belowThresholdRounds)
	}
}

func TestUpdateConnStateJanitorPressureActivatesOnUsage(t *testing.T) {
	state := updateConnStateJanitorPressure(connStateJanitorPressureState{}, false, connStateJanitorPressureEnterUsage)
	if !state.active {
		t.Fatal("expected pressure mode to activate on high usage")
	}
}

func TestUpdateConnStateJanitorPressureExitsAfterConsecutiveLowUsage(t *testing.T) {
	state := connStateJanitorPressureState{active: true}
	for i := 0; i < connStateJanitorPressureExitRounds-1; i++ {
		state = updateConnStateJanitorPressure(state, false, connStateJanitorPressureExitUsage-1)
		if !state.active {
			t.Fatalf("pressure mode exited too early at round %d", i+1)
		}
	}
	state = updateConnStateJanitorPressure(state, false, connStateJanitorPressureExitUsage-1)
	if state.active {
		t.Fatal("expected pressure mode to exit after enough low-usage rounds")
	}
	if state.belowThresholdRounds != 0 {
		t.Fatalf("expected belowThresholdRounds to reset after exit, got %d", state.belowThresholdRounds)
	}
}

func TestUpdateConnStateJanitorPressureResetsExitCountdown(t *testing.T) {
	state := connStateJanitorPressureState{
		active:               true,
		belowThresholdRounds: connStateJanitorPressureExitRounds - 1,
	}
	state = updateConnStateJanitorPressure(state, false, connStateJanitorPressureEnterUsage)
	if !state.active {
		t.Fatal("expected pressure mode to remain active")
	}
	if state.belowThresholdRounds != 0 {
		t.Fatalf("expected high usage to reset belowThresholdRounds, got %d", state.belowThresholdRounds)
	}
}

func TestDisablePinnedConnStateMaps(t *testing.T) {
	spec := &ebpf.CollectionSpec{
		Maps: map[string]*ebpf.MapSpec{
			"tcp_conn_state_map": {
				Name:    "tcp_conn_state_map",
				Pinning: ebpf.PinByName,
			},
			"udp_conn_state_map": {
				Name:    "udp_conn_state_map",
				Pinning: ebpf.PinByName,
			},
			"domain_routing_map": {
				Name:    "domain_routing_map",
				Pinning: ebpf.PinByName,
			},
		},
	}

	if err := disablePinnedConnStateMaps(spec); err != nil {
		t.Fatalf("disablePinnedConnStateMaps returned error: %v", err)
	}
	if got := spec.Maps["tcp_conn_state_map"].Pinning; got != ebpf.PinNone {
		t.Fatalf("tcp_conn_state_map pinning = %v, want %v", got, ebpf.PinNone)
	}
	if got := spec.Maps["udp_conn_state_map"].Pinning; got != ebpf.PinNone {
		t.Fatalf("udp_conn_state_map pinning = %v, want %v", got, ebpf.PinNone)
	}
	if got := spec.Maps["domain_routing_map"].Pinning; got != ebpf.PinByName {
		t.Fatalf("domain_routing_map pinning = %v, want %v", got, ebpf.PinByName)
	}
}

func TestCleanupPinnedConnStateMapFiles(t *testing.T) {
	pinPath := t.TempDir()
	for _, name := range []string{"tcp_conn_state_map", "udp_conn_state_map", "domain_routing_map"} {
		if err := os.WriteFile(filepath.Join(pinPath, name), []byte("x"), 0644); err != nil {
			t.Fatalf("write test pin file %s: %v", name, err)
		}
	}

	removed := cleanupPinnedConnStateMapFiles(nil, pinPath)
	if removed != 2 {
		t.Fatalf("cleanupPinnedConnStateMapFiles removed %d files, want 2", removed)
	}

	for _, name := range []string{"tcp_conn_state_map", "udp_conn_state_map"} {
		if _, err := os.Stat(filepath.Join(pinPath, name)); !os.IsNotExist(err) {
			t.Fatalf("expected %s to be removed, stat err=%v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(pinPath, "domain_routing_map")); err != nil {
		t.Fatalf("expected unrelated pin file to remain: %v", err)
	}
}
