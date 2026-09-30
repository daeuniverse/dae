/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
)

func TestProcessAlive(t *testing.T) {
	if !processAlive(os.Getpid()) {
		t.Fatal("the current process must be reported alive")
	}
	if processAlive(1 << 30) {
		t.Fatal("a nonexistent pid must not be reported alive")
	}
	if processAlive(0) || processAlive(-1) {
		t.Fatal("non-positive pids must not be reported alive")
	}
}

func TestReadDaemonPIDFileErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := readDaemonPIDFile(filepath.Join(dir, "nope.pid")); err == nil {
		t.Fatal("readDaemonPIDFile() on a missing file = nil error, want failure")
	}
	bad := filepath.Join(dir, "bad.pid")
	if err := os.WriteFile(bad, []byte("not-a-pid"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readDaemonPIDFile(bad); err == nil {
		t.Fatal("readDaemonPIDFile() on a non-numeric pid = nil error, want failure")
	}
}

func TestEnsureDaemonAliveCleansStalePidFile(t *testing.T) {
	orig := setRunSignalProgress
	resetCalled := false
	setRunSignalProgress = func(code byte, _ string) error {
		resetCalled = true
		if code != consts.ReloadDone {
			t.Fatalf("progress reset code = %v, want ReloadDone", code)
		}
		return nil
	}
	t.Cleanup(func() { setRunSignalProgress = orig })

	pidPath := filepath.Join(t.TempDir(), "dae.pid")
	if err := os.WriteFile(pidPath, []byte("1073741824"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := ensureDaemonAliveAt(pidPath, 1<<30); err == nil {
		t.Fatal("ensureDaemonAliveAt() with a dead pid = nil error, want failure")
	}
	if _, err := os.Stat(pidPath); !os.IsNotExist(err) {
		t.Fatalf("stale pid file still present: %v", err)
	}
	if !resetCalled {
		t.Fatal("stale daemon cleanup did not reset the reload progress")
	}
}
