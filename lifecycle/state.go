/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package lifecycle

import (
	"fmt"
)

// LifecycleState represents the current state of the lifecycle manager.
type LifecycleState int

const (
	StateCreated  LifecycleState = iota // Initial state
	StateStarting                       // PreCheck -> Prepare -> Attach -> Activate
	StateRunning                        // Serving, waiting for signals
	StateReloading                      // Validating -> Preparing -> Cutover -> DrainingOld
	StateStopping                       // StopAccepting -> Drain -> Release -> FinalCleanup
	StateStopped                        // Terminal state
)

// String returns the string representation of the state.
func (s LifecycleState) String() string {
	switch s {
	case StateCreated:
		return "Created"
	case StateStarting:
		return "Starting"
	case StateRunning:
		return "Running"
	case StateReloading:
		return "Reloading"
	case StateStopping:
		return "Stopping"
	case StateStopped:
		return "Stopped"
	default:
		return fmt.Sprintf("Unknown(%d)", s)
	}
}

// CanTransitionTo returns true if the state can transition to the target state.
func (s LifecycleState) CanTransitionTo(target LifecycleState) bool {
	switch s {
	case StateCreated:
		return target == StateStarting || target == StateStopped
	case StateStarting:
		return target == StateRunning || target == StateStopping || target == StateStopped
	case StateRunning:
		return target == StateReloading || target == StateStopping || target == StateStopped
	case StateReloading:
		return target == StateRunning || target == StateStopping || target == StateStopped
	case StateStopping:
		return target == StateStopped
	case StateStopped:
		return false // Terminal state
	default:
		return false
	}
}

// Phase represents a phase within a lifecycle operation.
type Phase string

const (
	// Start phases
	PhasePrecheck  Phase = "precheck"
	PhasePrepare   Phase = "prepare"
	PhaseAttach    Phase = "attach"
	PhaseActivate  Phase = "activate"

	// Reload phases
	PhaseValidating Phase = "validating"
	PhaseCutover    Phase = "cutover"
	PhaseDrainOld   Phase = "drain_old"

	// Stop phases
	PhaseStopAccepting Phase = "stop_accepting"
	PhaseDrain         Phase = "drain"
	PhaseRelease       Phase = "release"
	PhaseFinalCleanup  Phase = "final_cleanup"
)

// ReloadType indicates the type of reload operation.
type ReloadType int

const (
	ReloadTypeConfigOnly ReloadType = iota // Update routing maps only
	ReloadTypeFull                         // Rebuild BPF objects
)

func (r ReloadType) String() string {
	switch r {
	case ReloadTypeConfigOnly:
		return "config-only"
	case ReloadTypeFull:
		return "full"
	default:
		return "unknown"
	}
}
