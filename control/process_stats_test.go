/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeProcStat lays out a /proc/<pid>/stat line with the given CPU ticks.
// comm is deliberately awkward: it can contain spaces and parentheses, which a
// front-to-back parse would misread.
func writeProcStat(t *testing.T, procSelf, comm string, utime, stime int64) {
	t.Helper()
	// Fields 3..15: state ppid pgrp session tty_nr tpgid flags minflt cminflt
	// majflt cmajflt utime stime. The trailing fields only need to exist.
	line := fmt.Sprintf(
		"12345 (%s) S 1 12345 12345 0 -1 4194560 100 0 5 0 %d %d 0 0 20 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0",
		comm, utime, stime,
	)
	if err := os.MkdirAll(procSelf, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(procSelf, "stat"), []byte(line+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestReadProcessCPUTime(t *testing.T) {
	procSelf := t.TempDir()
	// "a) b" is the pathological case: it contains a ')' that a forward scan
	// would treat as the end of comm.
	writeProcStat(t, procSelf, "a) b", 150, 50)

	cpu, ok := readProcessCPUTime(filepath.Join(procSelf, "stat"))
	if !ok {
		t.Fatal("reading the fixture failed")
	}
	// 200 ticks at USER_HZ=100 is two seconds of CPU time.
	if cpu != 2*time.Second {
		t.Fatalf("cpu time = %v, want 2s", cpu)
	}

	if _, ok := readProcessCPUTime(filepath.Join(procSelf, "missing")); ok {
		t.Fatal("a missing file must not parse")
	}
}

// TestProcessCPUPercentNeedsTwoSamples pins the contract rule: the value is a
// delta over the sampling interval, so one reading cannot produce a percentage.
func TestProcessCPUPercentNeedsTwoSamples(t *testing.T) {
	procSelf := t.TempDir()
	stats := newProcessCPUStats()
	stats.procSelf = procSelf

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	writeProcStat(t, procSelf, "dae", 100, 0)
	stats.sample(base)
	if got := stats.cpuPercent(); got != nil {
		t.Fatalf("first sample = %v, want nil (baseline only)", *got)
	}

	// +100 ticks (1s CPU) over 2s wall time is half a core: 50%.
	writeProcStat(t, procSelf, "dae", 200, 0)
	stats.sample(base.Add(2 * time.Second))
	got := stats.cpuPercent()
	if got == nil {
		t.Fatal("second sample must produce a percentage")
	}
	if delta := *got - 50; delta > 1e-9 || delta < -1e-9 {
		t.Fatalf("percent = %v, want 50", *got)
	}

	// A usage above one core is legal on a multi-core host.
	writeProcStat(t, procSelf, "dae", 500, 0)
	stats.sample(base.Add(3 * time.Second))
	got = stats.cpuPercent()
	if got == nil || *got < 299 || *got > 301 {
		t.Fatalf("percent = %v, want 300", got)
	}
}

// TestProcessCPUPercentClearsOnUnreadable keeps a stale number from outliving
// the data: an unreadable /proc must report unknown, not the last reading.
func TestProcessCPUPercentClearsOnUnreadable(t *testing.T) {
	procSelf := t.TempDir()
	stats := newProcessCPUStats()
	stats.procSelf = procSelf

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	writeProcStat(t, procSelf, "dae", 100, 0)
	stats.sample(base)
	writeProcStat(t, procSelf, "dae", 200, 0)
	stats.sample(base.Add(time.Second))
	if stats.cpuPercent() == nil {
		t.Fatal("expected a reading before the file disappears")
	}

	if err := os.Remove(filepath.Join(procSelf, "stat")); err != nil {
		t.Fatal(err)
	}
	stats.sample(base.Add(2 * time.Second))
	if got := stats.cpuPercent(); got != nil {
		t.Fatalf("percent after the file disappeared = %v, want nil", *got)
	}
}
