/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package lifecycle

import (
	"context"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

func TestNewLifecycleManager(t *testing.T) {
	log := logrus.New()
	cfg := &ManagerConfig{
		Log:           log,
		DrainTimeout:  30 * time.Second,
		CleanShutdown: false,
	}

	mgr := NewLifecycleManager(cfg)

	if mgr == nil {
		t.Fatal("NewLifecycleManager() returned nil")
	}

	if mgr.State() != StateCreated {
		t.Errorf("State = %v, want %v", mgr.State(), StateCreated)
	}

	if mgr.Generation() != nil {
		t.Errorf("Generation should be nil initially")
	}
}

func TestLifecycleManager_Transition(t *testing.T) {
	log := logrus.New()
	log.SetLevel(logrus.DebugLevel)
	mgr := NewLifecycleManager(&ManagerConfig{Log: log})

	tests := []struct {
		name     string
		from     LifecycleState
		to       LifecycleState
		wantErr  bool
		setup    func() // Setup function to establish initial state
	}{
		{
			name:    "Created -> Starting (valid)",
			from:    StateCreated,
			to:      StateStarting,
			wantErr: false,
			setup:   func() {},
		},
		{
			name:    "Created -> Running (invalid)",
			from:    StateCreated,
			to:      StateRunning,
			wantErr: true,
			setup:   func() {},
		},
		{
			name: "Starting -> Running (valid)",
			from: StateStarting,
			to:   StateRunning,
			wantErr: false,
			setup: func() {
				mgr.setState(StateStarting)
			},
		},
		{
			name: "Running -> Reloading (valid)",
			from: StateRunning,
			to:   StateReloading,
			wantErr: false,
			setup: func() {
				mgr.setState(StateRunning)
			},
		},
		{
			name: "Reloading -> Running (valid)",
			from: StateReloading,
			to:   StateRunning,
			wantErr: false,
			setup: func() {
				mgr.setState(StateReloading)
			},
		},
		{
			name: "Running -> Stopping (valid)",
			from: StateRunning,
			to:   StateStopping,
			wantErr: false,
			setup: func() {
				mgr.setState(StateRunning)
			},
		},
		{
			name: "Stopping -> Stopped (valid)",
			from: StateStopping,
			to:   StateStopped,
			wantErr: false,
			setup: func() {
				mgr.setState(StateStopping)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset to Created state
			mgr.setState(StateCreated)

			// Setup initial state if needed
			tt.setup()

			// Check we're in the expected from state
			if mgr.State() != tt.from {
				t.Fatalf("State before transition = %v, want %v", mgr.State(), tt.from)
			}

			// Attempt transition
			err := mgr.transition(tt.to)

			if (err != nil) != tt.wantErr {
				t.Errorf("transition() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// Check final state if transition should succeed
			if !tt.wantErr && mgr.State() != tt.to {
				t.Errorf("State after transition = %v, want %v", mgr.State(), tt.to)
			}
		})
	}
}

func TestLifecycleManager_Start_InvalidState(t *testing.T) {
	log := logrus.New()
	mgr := NewLifecycleManager(&ManagerConfig{Log: log})

	// Set to Running state (invalid for Start)
	mgr.setState(StateRunning)

	ctx := context.Background()
	req := &StartRequest{
		ConfigFile: "/test/config.dae",
	}

	_, err := mgr.Start(ctx, req)
	if err == nil {
		t.Error("Start() should return error when not in Created state")
	}
}

func TestLifecycleManager_Reload_InvalidState(t *testing.T) {
	log := logrus.New()
	mgr := NewLifecycleManager(&ManagerConfig{Log: log})

	// Keep in Created state (invalid for Reload)
	ctx := context.Background()
	req := &ReloadRequest{}

	_, err := mgr.Reload(ctx, req)
	if err == nil {
		t.Error("Reload() should return error when not in Running state")
	}
}

func TestLifecycleManager_Stop_InvalidState(t *testing.T) {
	log := logrus.New()
	mgr := NewLifecycleManager(&ManagerConfig{Log: log})

	// Keep in Created state (invalid for Stop)
	ctx := context.Background()
	err := mgr.Stop(ctx, StopModeGraceful)
	if err == nil {
		t.Error("Stop() should return error when not in Running or Reloading state")
	}
}

func TestSystemdNotifier(t *testing.T) {
	log := logrus.New()
	log.SetLevel(logrus.DebugLevel)

	tests := []struct {
		name    string
		enabled bool
	}{
		{
			name:    "disabled",
			enabled: false,
		},
		{
			name:    "enabled",
			enabled: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := &SystemdNotifier{
				log:     log,
				enabled: tt.enabled,
			}

			if n.Enabled() != tt.enabled {
				t.Errorf("Enabled() = %v, want %v", n.Enabled(), tt.enabled)
			}

			// These should not panic
			n.Ready()
			n.Reloading()
			n.Stopping()
			n.Status("test status")
			n.ExtendTimeout(10 * time.Second)
		})
	}
}

func TestStopMode_String(t *testing.T) {
	tests := []struct {
		mode    StopMode
		wantStr string
	}{
		{StopModeGraceful, "graceful"},
		{StopModeImmediate, "immediate"},
		{StopMode(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.wantStr, func(t *testing.T) {
			if got := tt.mode.String(); got != tt.wantStr {
				t.Errorf("String() = %v, want %v", got, tt.wantStr)
			}
		})
	}
}

func TestAttachmentType(t *testing.T) {
	tests := []struct {
		atype          AttachmentType
		expectedString string
	}{
		{AttachmentTypeTCX, "tcx"},
		{AttachmentTypeLegacyTC, "legacy_tc"},
	}

	for _, tt := range tests {
		t.Run(tt.expectedString, func(t *testing.T) {
			if string(tt.atype) != tt.expectedString {
				t.Errorf("AttachmentType = %v, want %v", tt.atype, tt.expectedString)
			}
		})
	}
}
