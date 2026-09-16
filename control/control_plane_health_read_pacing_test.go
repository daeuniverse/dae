/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	stderrors "errors"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

// TestDatapathCounterReadFailureIsPacedWithACount is the Q1 contract.
// checkBpfMapHealth runs on every janitor tick (5s). Its snapshot-read failure
// used to be an unpaced warning, so a read that kept failing produced one line
// per tick (~720/hour) with no transition behind it, and the line said nothing
// about how long the condition had lasted. It is now paced at 30s and every
// emitted line carries the number of failed reads it folded in.
//
// Time is injected through the now argument, so this test never sleeps.
func TestDatapathCounterReadFailureIsPacedWithACount(t *testing.T) {
	logger, out := newLogCapture(logrus.WarnLevel)
	c := &ControlPlane{}
	c.log = logger

	tick := 5 * time.Second
	now := time.Unix(1_800_000_000, 0)
	err := stderrors.New("failed to read bpf stats map: invalid argument")

	// First failure: always reported, with the count.
	c.logDatapathCounterReadFailure(now, err)
	lines := out.lines()
	if len(lines) != 1 {
		t.Fatalf("first failed read emitted %d line(s), want 1:\n%v", len(lines), lines)
	}
	if !strings.Contains(lines[0], "checkBpfMapHealth") || !strings.Contains(lines[0], "failures=1") {
		t.Fatalf("first failed read line = %q, want the error and failures=1", lines[0])
	}

	// The next five ticks are inside the cooldown: silently folded in.
	for i := 1; i <= 5; i++ {
		now = now.Add(tick)
		c.logDatapathCounterReadFailure(now, err)
	}
	if got := out.lines(); len(got) != 1 {
		t.Fatalf("five failures inside the cooldown emitted %d line(s) total, want 1:\n%v", len(got), got)
	}

	// Past the cooldown: one line, and it reports all six failed reads.
	now = now.Add(datapathCounterReadFailureCooldown)
	c.logDatapathCounterReadFailure(now, err)
	lines = out.lines()
	if len(lines) != 2 {
		t.Fatalf("failure after the cooldown emitted %d line(s) total, want 2:\n%v", len(lines), lines)
	}
	if !strings.Contains(lines[1], "failures=7") {
		t.Fatalf("paced line = %q, want failures=7 (the six folded in plus this one)", lines[1])
	}
	if !strings.Contains(lines[1], datapathCounterReadFailureCooldown.String()) {
		t.Fatalf("paced line = %q, want the pace stated so the line rate is predictable", lines[1])
	}
}

// TestDatapathCounterReadFailureKeepsTheErrorIdentity guards that pacing did
// not stop surfacing the actual cause: the operator has to see why the read
// failed, not just that it did.
func TestDatapathCounterReadFailureKeepsTheErrorIdentity(t *testing.T) {
	logger, out := newLogCapture(logrus.WarnLevel)
	c := &ControlPlane{}
	c.log = logger

	c.logDatapathCounterReadFailure(time.Unix(1_800_000_000, 0), stderrors.New("map lookup: permission denied"))
	lines := out.lines()
	if len(lines) != 1 {
		t.Fatalf("failed read emitted %d line(s), want 1", len(lines))
	}
	if !strings.Contains(lines[0], "map lookup: permission denied") {
		t.Fatalf("line = %q, want the underlying error verbatim", lines[0])
	}
}

// TestDatapathCounterReadFailureIsWarnNotLower keeps the level: a failed read
// hides every datapath counter, so it must not be demoted to info/debug while
// being paced.
func TestDatapathCounterReadFailureIsWarnNotLower(t *testing.T) {
	src := readPackageSource(t, "control_plane.go")
	if strings.Contains(src, `c.log.Warnf("checkBpfMapHealth: %v", snapshotErr)`) {
		t.Fatal("the unpaced datapath-counter read failure warning is back")
	}
	if !strings.Contains(src, "c.logDatapathCounterReadFailure(now, snapshotErr)") {
		t.Fatal("checkBpfMapHealth no longer reports the snapshot read failure")
	}
	if !strings.Contains(src, `c.log.Warnf("checkBpfMapHealth: %v (failures=%d, reporting at most one line per %v)"`) {
		t.Fatal("the read failure is no longer reported at warn with its failure count")
	}
}
