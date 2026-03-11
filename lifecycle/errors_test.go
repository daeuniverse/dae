/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2005, daeuniverse Organization <dae@v2raya.org>
 */

package lifecycle

import (
	"errors"
	"strings"
	"testing"
)

func TestLifecycleError(t *testing.T) {
	tests := []struct {
		name    string
		err     *LifecycleError
		wantErr string
	}{
		{
			name: "full error",
			err: &LifecycleError{
				Op:    "start",
				Phase: "precheck",
				ID:    "gen-123",
				Cause: errors.New("root cause"),
			},
			wantErr: "lifecycle error: op=start, phase=precheck, gen=gen-123: root cause",
		},
		{
			name: "minimal error",
			err: &LifecycleError{
				Cause: errors.New("something failed"),
			},
			wantErr: "lifecycle error: something failed",
		},
		{
			name:    "nil error",
			err:     nil,
			wantErr: "<nil>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.wantErr {
				t.Errorf("Error() = %v, want %v", got, tt.wantErr)
			}
		})
	}
}

func TestLifecycleError_Unwrap(t *testing.T) {
	cause := errors.New("root cause")
	err := &LifecycleError{Cause: cause}

	if unwrapped := errors.Unwrap(err); unwrapped != cause {
		t.Errorf("Unwrap() = %v, want %v", unwrapped, cause)
	}
}

func TestNewStartError(t *testing.T) {
	cause := errors.New("failed to bind port")
	err := NewStartError(PhaseAttach, "gen-456", cause)

	if err.Op != "start" {
		t.Errorf("Op = %v, want 'start'", err.Op)
	}
	if err.Phase != string(PhaseAttach) {
		t.Errorf("Phase = %v, want %v", err.Phase, PhaseAttach)
	}
	if err.ID != "gen-456" {
		t.Errorf("ID = %v, want 'gen-456'", err.ID)
	}
	if err.Cause != cause {
		t.Errorf("Cause = %v, want %v", err.Cause, cause)
	}
}

func TestReloadError(t *testing.T) {
	tests := []struct {
		name            string
		err             *ReloadError
		rollbackAttempt bool
		rollbackErr     error
		wantContains    []string
	}{
		{
			name: "with successful rollback",
			err: &ReloadError{
				LifecycleError: LifecycleError{
					Op:    "reload",
					Phase: "cutover",
					ID:    "gen-789",
					Cause: errors.New("cutover failed"),
				},
				RollbackAttempted: true,
			},
			wantContains: []string{"reload error", "rollback attempted", "rollback succeeded"},
		},
		{
			name: "with failed rollback",
			err: &ReloadError{
				LifecycleError: LifecycleError{
					Op:    "reload",
					Phase: "cutover",
					ID:    "gen-789",
					Cause: errors.New("cutover failed"),
				},
				RollbackAttempted: true,
				RollbackError:     errors.New("rollback also failed"),
			},
			wantContains: []string{"reload error", "rollback attempted", "rollback also failed"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.err.Error()
			for _, want := range tt.wantContains {
				if !strings.Contains(got, want) {
					t.Errorf("Error() = %v, want to contain %v", got, want)
				}
			}
		})
	}
}

func TestNewReloadError(t *testing.T) {
	cause := errors.New("config validation failed")
	rollbackErr := errors.New("rollback failed")
	err := NewReloadError(PhaseValidating, "gen-123", cause, rollbackErr, true)

	if err.Op != "reload" {
		t.Errorf("Op = %v, want 'reload'", err.Op)
	}
	if !err.RollbackAttempted {
		t.Errorf("RollbackAttempted = false, want true")
	}
	if err.RollbackError != rollbackErr {
		t.Errorf("RollbackError = %v, want %v", err.RollbackError, rollbackErr)
	}
}

func TestStopError(t *testing.T) {
	leaked := []string{"bpf_map", "tc_filter"}
	err := NewStopError(PhaseRelease, "gen-999", errors.New("cleanup failed"), leaked)

	got := err.Error()
	if !strings.Contains(got, "potentially leaked") {
		t.Errorf("Error() = %v, want to contain 'potentially leaked'", got)
	}
	if !strings.Contains(got, "bpf_map") {
		t.Errorf("Error() = %v, want to contain 'bpf_map'", got)
	}
}

func TestPrecheckError(t *testing.T) {
	checks := []string{"port_conflict", "permission_denied"}
	err := NewPrecheckError("gen-111", checks, errors.New("precheck failed"))

	got := err.Error()
	if !strings.Contains(got, "failed checks") {
		t.Errorf("Error() = %v, want to contain 'failed checks'", got)
	}
	if !strings.Contains(got, "port_conflict") {
		t.Errorf("Error() = %v, want to contain 'port_conflict'", got)
	}
}

func TestCompatibilityError(t *testing.T) {
	err := NewCompatibilityError("gen-222", "map schema incompatible", true, errors.New("incompatible"))

	if !err.Forceable {
		t.Errorf("Forceable = false, want true")
	}

	got := err.Error()
	if !strings.Contains(got, "reason:") {
		t.Errorf("Error() = %v, want to contain 'reason:'", got)
	}
	if !strings.Contains(got, "--force-state-reset") {
		t.Errorf("Error() = %v, want to contain '--force-state-reset'", got)
	}
}
