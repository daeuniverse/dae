// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>

package cmd

import (
	"os"
	"path/filepath"
	"runtime/debug"
	"testing"
)

// memory.high throttles reclaim instead of capping the cgroup, so it must not
// pull GOMEMLIMIT down: systemd's MemoryHigh= would otherwise become a hard Go
// heap ceiling and drive the GC into back-to-back cycles.
func TestReadCgroupMemoryCeilingIgnoresMemoryHigh(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "memory.max"), []byte("1073741824\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "memory.high"), []byte("536870912\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if got, want := readCgroupMemoryCeiling(dir), int64(1073741824); got != want {
		t.Fatalf("readCgroupMemoryCeiling() = %d, want %d", got, want)
	}
}

func TestReadCgroupMemoryCeilingIgnoresUnlimitedAndInvalidValues(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "memory.max"), []byte("max\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if got := readCgroupMemoryCeiling(dir); got != 0 {
		t.Fatalf("readCgroupMemoryCeiling() = %d, want 0", got)
	}
}

func TestConfigureGcMemoryLimitRespectsExplicitEnvironment(t *testing.T) {
	const sentinel = int64(192 << 20)
	previous := debug.SetMemoryLimit(sentinel)
	t.Cleanup(func() { debug.SetMemoryLimit(previous) })
	t.Setenv("GOMEMLIMIT", "64MiB")

	configureGcMemoryLimit(nil)
	got := debug.SetMemoryLimit(sentinel)
	if got != sentinel {
		t.Fatalf("configureGcMemoryLimit() changed explicit limit to %d, want %d", got, sentinel)
	}
}

func TestDetectCgroupMemLimitUsesSmallestAncestorCeiling(t *testing.T) {
	root := t.TempDir()
	child := filepath.Join(root, "service", "worker")
	if err := os.MkdirAll(child, 0o700); err != nil {
		t.Fatal(err)
	}
	writeCgroupMemoryValue(t, root, "memory.max", "268435456\n")
	writeCgroupMemoryValue(t, filepath.Join(root, "service"), "memory.high", "1048576\n")
	writeCgroupMemoryValue(t, child, "memory.max", "536870912\n")

	if got, want := detectCgroupMemLimitFrom([]byte("0::/service/worker\n"), root), int64(268435456); got != want {
		t.Fatalf("detectCgroupMemLimitFrom() = %d, want %d", got, want)
	}
}

func writeCgroupMemoryValue(t *testing.T, dir, name, value string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestMinPositive(t *testing.T) {
	if got, want := minPositive(0, 512, -1, 256), int64(256); got != want {
		t.Fatalf("minPositive() = %d, want %d", got, want)
	}
	if got := minPositive(0, -1); got != 0 {
		t.Fatalf("minPositive() = %d, want 0", got)
	}
}
