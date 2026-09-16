/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@daeuniverse.org>
 */

package cmd

import (
	stderrors "errors"
	"testing"

	"github.com/daeuniverse/dae/control"
)

// TestServeExitTrackerActiveGenerationDeathIsFatal locks in the run-loop
// contract: an abnormal exit reported for the active generation surfaces as
// fatal, and consuming it leaves nothing behind.
func TestServeExitTrackerActiveGenerationDeathIsFatal(t *testing.T) {
	var tracker serveExitTracker
	active := &control.ControlPlane{}

	tracker.report(active, stderrors.New("serve exploded"))
	if err := tracker.fatalFor(active); err == nil {
		t.Fatal("fatalFor(active) = nil, want the reported error")
	}
	// The report is consumed: the same question asked again answers nil.
	if err := tracker.fatalFor(active); err != nil {
		t.Fatalf("fatalFor after consumption = %v, want nil", err)
	}
}

// TestServeExitTrackerStaleReportNeverMisfires locks in generation
// filtering: a report from a rolled-back candidate must never fire against a
// later active generation, even if the question is asked repeatedly.
func TestServeExitTrackerStaleReportNeverMisfires(t *testing.T) {
	var tracker serveExitTracker
	candidate := &control.ControlPlane{}
	nextGeneration := &control.ControlPlane{}

	tracker.report(candidate, stderrors.New("candidate serve failed"))
	if err := tracker.fatalFor(nextGeneration); err != nil {
		t.Fatalf("fatalFor(active) on stale report = %v, want nil", err)
	}
	// Consumed on first sight: a later generation with a coincidentally
	// reused pointer cannot be killed by the ancient report.
	if err := tracker.fatalFor(candidate); err != nil {
		t.Fatalf("fatalFor after stale consumption = %v, want nil", err)
	}
}

// TestServeExitTrackerIgnoresBenignExits locks in admission rules: nil
// errors (planned retirement via context cancellation) and nil planes are
// never recorded, and a newer report replaces an older one.
func TestServeExitTrackerIgnoresBenignExits(t *testing.T) {
	var tracker serveExitTracker
	active := &control.ControlPlane{}
	retired := &control.ControlPlane{}

	tracker.report(retired, nil)
	tracker.report(nil, stderrors.New("no plane"))
	if err := tracker.fatalFor(active); err != nil {
		t.Fatalf("benign reports surfaced = %v, want nil", err)
	}

	// Overwrite: the newest report wins the single slot. Asking about the
	// retired plane consumes the slot (stale question) without firing, and
	// the active plane's report still fires when asked again.
	tracker.report(retired, stderrors.New("older death"))
	tracker.report(active, stderrors.New("newer death"))
	if err := tracker.fatalFor(retired); err != nil {
		t.Fatalf("retired plane fired after overwrite = %v, want nil", err)
	}
	tracker.report(active, stderrors.New("newest death"))
	if err := tracker.fatalFor(active); err == nil {
		t.Fatal("report for the active plane was lost")
	}
}
