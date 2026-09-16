/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/sirupsen/logrus"
)

func testLogger() *logrus.Logger {
	log := logrus.New()
	log.SetOutput(io.Discard)
	return log
}

// TestEnsureBpfPinDirCreatesMissingDirectory is the happy path: an existing pin
// root with a missing app directory is created, and a second call is a no-op.
func TestEnsureBpfPinDirCreatesMissingDirectory(t *testing.T) {
	root := t.TempDir()
	pinPath := filepath.Join(root, consts.AppName)
	if err := ensureBpfPinDir(pinPath, testLogger()); err != nil {
		t.Fatalf("ensureBpfPinDir: %v", err)
	}
	info, err := os.Stat(pinPath)
	if err != nil || !info.IsDir() {
		t.Fatalf("pin directory not created: %v", err)
	}
	if err := ensureBpfPinDir(pinPath, testLogger()); err != nil {
		t.Fatalf("second ensureBpfPinDir: %v", err)
	}
}

// TestBpfPinDirErrorNamesMissingBpffs is the regression for the misleading
// container-only hint: when the pin root is not a bpffs mount, the message must
// name that fact and the mount command that fixes it.
func TestBpfPinDirErrorNamesMissingBpffs(t *testing.T) {
	mkdirErr := &os.PathError{Op: "mkdir", Path: "/sys/fs/bpf/dae", Err: os.ErrNotExist}
	err := bpfPinDirError("/sys/fs/bpf/dae", mkdirErr, false)
	msg := err.Error()
	if !strings.Contains(msg, consts.BpfPinRoot) || !strings.Contains(msg, "not a bpffs mount") {
		t.Fatalf("error %q does not name the missing bpffs mount at %s", msg, consts.BpfPinRoot)
	}
	if !strings.Contains(msg, "mount -t bpf bpffs") {
		t.Fatalf("error %q does not tell the user how to mount bpffs", msg)
	}
	// The raw mkdir cause stays in the chain so logs remain diagnosable, and the
	// container case is still mentioned as a secondary possibility.
	if !strings.Contains(msg, "mkdir /sys/fs/bpf/dae") || !strings.Contains(msg, "container") {
		t.Fatalf("error %q dropped the underlying mkdir error or the container hint", msg)
	}
}

// TestBpfPinDirErrorKeepsCauseWhenRootIsMounted covers the other branch: with
// bpffs in place the failure has a different cause (permissions, ENOTDIR, ...),
// so the message must carry only that cause - no mount advice and no container
// hint that would send the user after the wrong problem.
func TestBpfPinDirErrorKeepsCauseWhenRootIsMounted(t *testing.T) {
	mkdirErr := &os.PathError{Op: "mkdir", Path: "/sys/fs/bpf/dae", Err: os.ErrPermission}
	err := bpfPinDirError("/sys/fs/bpf/dae", mkdirErr, true)
	msg := err.Error()
	for _, unwanted := range []string{"not a bpffs mount", "container", "mount -t bpf"} {
		if strings.Contains(msg, unwanted) {
			t.Fatalf("error %q adds %q although bpffs is mounted and the failure is a permission error", msg, unwanted)
		}
	}
	if !strings.Contains(msg, "cannot create bpf pin directory") || !strings.Contains(msg, "permission denied") {
		t.Fatalf("error %q does not carry the real mkdir failure", msg)
	}
}

// TestEnsureBpfPinDirReportsRealFailure drives the helper through a genuine
// mkdir failure (a regular file in the path) to prove the wrapping is applied
// on the production path, not only in the message builder.
func TestEnsureBpfPinDirReportsRealFailure(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("write blocker: %v", err)
	}
	err := ensureBpfPinDir(filepath.Join(blocker, consts.AppName), testLogger())
	if err == nil {
		t.Fatal("expected an error when a path component is a regular file")
	}
	msg := err.Error()
	// The production path always wraps the raw mkdir cause, but the wrapper it
	// picks depends on the host's /sys/fs/bpf state. Assert against the same
	// source of truth instead of assuming a mounted pin root, so the test means
	// the same thing on a developer box, in a container and on a CI runner.
	if !strings.Contains(msg, "not a directory") || !strings.Contains(msg, consts.AppName) {
		t.Fatalf("error %q dropped the raw mkdir cause or the pin path", msg)
	}
	if isBpfPinRootMounted() {
		if !strings.Contains(msg, "cannot create bpf pin directory") {
			t.Fatalf("unexpected error with a mounted pin root: %v", err)
		}
		return
	}
	if !strings.Contains(msg, "not a bpffs mount") {
		t.Fatalf("unexpected error without a mounted pin root: %v", err)
	}
}

// TestBpfPinRootMountedFromFixtures pins the mount-table parser against fixed
// inputs, so a wrong path or fstype cannot pass unnoticed the way re-parsing
// /proc/mounts in the test would.
func TestBpfPinRootMountedFromFixtures(t *testing.T) {
	cases := []struct {
		name   string
		mounts string
		want   bool
	}{
		{"bpffs at the pin root", "bpf " + consts.BpfPinRoot + " bpf rw,relatime 0 0", true},
		{"bpffs among other mounts", "sysfs /sys sysfs rw 0 0\nbpf " + consts.BpfPinRoot + " bpf rw 0 0\ntmpfs /run tmpfs rw 0 0", true},
		{"tmpfs at the pin root", "tmpfs " + consts.BpfPinRoot + " tmpfs rw 0 0", false},
		{"bpffs elsewhere", "bpf /sys/fs/bpf-other bpf rw 0 0", false},
		{"prefix is not a match", "bpf " + consts.BpfPinRoot + "-x bpf rw 0 0", false},
		{"no mounts", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := bpfPinRootMountedFrom(tc.mounts); got != tc.want {
				t.Fatalf("bpfPinRootMountedFrom(%q) = %v, want %v", tc.mounts, got, tc.want)
			}
		})
	}
}
