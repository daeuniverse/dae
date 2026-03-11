/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package lifecycle

import (
	"fmt"
	"strings"
)

// LifecycleError is the base error type for all lifecycle operations.
type LifecycleError struct {
	// Op is the operation being performed (Start, Reload, Stop).
	Op string

	// Phase is the specific phase where the error occurred.
	Phase string

	// ID is the generation ID.
	ID string

	// Cause is the underlying error.
	Cause error
}

func (e *LifecycleError) Error() string {
	if e == nil {
		return "<nil>"
	}
	var parts []string
	if e.Op != "" {
		parts = append(parts, fmt.Sprintf("op=%s", e.Op))
	}
	if e.Phase != "" {
		parts = append(parts, fmt.Sprintf("phase=%s", e.Phase))
	}
	if e.ID != "" {
		parts = append(parts, fmt.Sprintf("gen=%s", e.ID))
	}
	msg := "lifecycle error"
	if len(parts) > 0 {
		msg = "lifecycle error: " + strings.Join(parts, ", ")
	}
	if e.Cause != nil {
		msg += ": " + e.Cause.Error()
	}
	return msg
}

func (e *LifecycleError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// StartError represents an error during the Start operation.
type StartError struct {
	LifecycleError
}

func (e *StartError) Error() string {
	return fmt.Sprintf("start error: %s", e.LifecycleError.Error())
}

// NewStartError creates a new StartError.
func NewStartError(phase Phase, genID string, cause error) *StartError {
	return &StartError{
		LifecycleError: LifecycleError{
			Op:    "start",
			Phase: string(phase),
			ID:    genID,
			Cause: cause,
		},
	}
}

// ReloadError represents an error during the Reload operation.
type ReloadError struct {
	LifecycleError

	// RollbackAttempted indicates if a rollback was attempted.
	RollbackAttempted bool

	// RollbackError is the error from the rollback attempt, if any.
	RollbackError error
}

func (e *ReloadError) Error() string {
	msg := fmt.Sprintf("reload error: %s", e.LifecycleError.Error())
	if e.RollbackAttempted {
		msg += " (rollback attempted"
		if e.RollbackError != nil {
			msg += ", rollback also failed: " + e.RollbackError.Error()
		} else {
			msg += ", rollback succeeded"
		}
		msg += ")"
	}
	return msg
}

// NewReloadError creates a new ReloadError.
func NewReloadError(phase Phase, genID string, cause error, rollbackErr error, attempted bool) *ReloadError {
	return &ReloadError{
		LifecycleError: LifecycleError{
			Op:    "reload",
			Phase: string(phase),
			ID:    genID,
			Cause: cause,
		},
		RollbackAttempted: attempted,
		RollbackError:     rollbackErr,
	}
}

// StopError represents an error during the Stop operation.
type StopError struct {
	LifecycleError

	// ResourcesLeaked lists resources that may not have been properly cleaned up.
	ResourcesLeaked []string
}

func (e *StopError) Error() string {
	msg := fmt.Sprintf("stop error: %s", e.LifecycleError.Error())
	if len(e.ResourcesLeaked) > 0 {
		msg += fmt.Sprintf(" (potentially leaked: %v", e.ResourcesLeaked)
	}
	return msg
}

// NewStopError creates a new StopError.
func NewStopError(phase Phase, genID string, cause error, leaked []string) *StopError {
	return &StopError{
		LifecycleError:  LifecycleError{Op: "stop", Phase: string(phase), ID: genID, Cause: cause},
		ResourcesLeaked: leaked,
	}
}

// PrecheckError represents an error during the Precheck phase.
type PrecheckError struct {
	LifecycleError

	// ChecksFailed lists the specific checks that failed.
	ChecksFailed []string
}

func (e *PrecheckError) Error() string {
	msg := fmt.Sprintf("precheck error: %s", e.LifecycleError.Error())
	if len(e.ChecksFailed) > 0 {
		msg += fmt.Sprintf(" (failed checks: %v)", e.ChecksFailed)
	}
	return msg
}

// NewPrecheckError creates a new PrecheckError.
func NewPrecheckError(genID string, checks []string, cause error) *PrecheckError {
	return &PrecheckError{
		LifecycleError: LifecycleError{
			Op:    "start",
			Phase: string(PhasePrecheck),
			ID:    genID,
			Cause: cause,
		},
		ChecksFailed: checks,
	}
}

// CompatibilityError represents an error when config is incompatible with current state.
type CompatibilityError struct {
	LifecycleError

	// Reason explains why the config is incompatible.
	Reason string

	// Forceable indicates if --force-state-reset can bypass this error.
	Forceable bool
}

func (e *CompatibilityError) Error() string {
	msg := fmt.Sprintf("compatibility error: %s", e.LifecycleError.Error())
	if e.Reason != "" {
		msg += fmt.Sprintf(" (reason: %s", e.Reason)
	}
	if e.Forceable {
		msg += " (can be forced with --force-state-reset)"
	}
	return msg
}

// NewCompatibilityError creates a new CompatibilityError.
func NewCompatibilityError(genID string, reason string, forceable bool, cause error) *CompatibilityError {
	return &CompatibilityError{
		LifecycleError: LifecycleError{
			Op:    "reload",
			Phase: string(PhaseValidating),
			ID:    genID,
			Cause: cause,
		},
		Reason:    reason,
		Forceable: forceable,
	}
}
