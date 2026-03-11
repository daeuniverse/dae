/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package lifecycle

import (
	"testing"
)

func TestLifecycleState_String(t *testing.T) {
	tests := []struct {
		state    LifecycleState
		expected string
	}{
		{StateCreated, "Created"},
		{StateStarting, "Starting"},
		{StateRunning, "Running"},
		{StateReloading, "Reloading"},
		{StateStopping, "Stopping"},
		{StateStopped, "Stopped"},
		{LifecycleState(99), "Unknown(99)"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.state.String(); got != tt.expected {
				t.Errorf("String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestLifecycleState_CanTransitionTo(t *testing.T) {
	tests := []struct {
		name     string
		from     LifecycleState
		to       LifecycleState
		expected bool
	}{
		{"Created -> Starting", StateCreated, StateStarting, true},
		{"Created -> Stopped", StateCreated, StateStopped, true},
		{"Created -> Running", StateCreated, StateRunning, false},
		{"Starting -> Running", StateStarting, StateRunning, true},
		{"Starting -> Stopping", StateStarting, StateStopping, true},
		{"Starting -> Stopped", StateStarting, StateStopped, true},
		{"Running -> Reloading", StateRunning, StateReloading, true},
		{"Running -> Stopping", StateRunning, StateStopping, true},
		{"Running -> Stopped", StateRunning, StateStopped, true},
		{"Running -> Starting", StateRunning, StateStarting, false},
		{"Reloading -> Running", StateReloading, StateRunning, true},
		{"Reloading -> Stopping", StateReloading, StateStopping, true},
		{"Reloading -> Reloading", StateReloading, StateReloading, false},
		{"Stopping -> Stopped", StateStopping, StateStopped, true},
		{"Stopping -> Running", StateStopping, StateRunning, false},
		{"Stopped -> Starting", StateStopped, StateStarting, false}, // Terminal state
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.from.CanTransitionTo(tt.to); got != tt.expected {
				t.Errorf("CanTransitionTo() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestReloadType_String(t *testing.T) {
	tests := []struct {
		reloadType ReloadType
		expected   string
	}{
		{ReloadTypeConfigOnly, "config-only"},
		{ReloadTypeFull, "full"},
		{ReloadType(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.reloadType.String(); got != tt.expected {
				t.Errorf("String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestPhase(t *testing.T) {
	// Test that all expected phases are defined
	phases := []Phase{
		PhasePrecheck,
		PhasePrepare,
		PhaseAttach,
		PhaseActivate,
		PhaseValidating,
		PhaseCutover,
		PhaseDrainOld,
		PhaseStopAccepting,
		PhaseDrain,
		PhaseRelease,
		PhaseFinalCleanup,
	}

	for _, p := range phases {
		if p == "" {
			t.Errorf("Phase %v is empty", p)
		}
	}
}
