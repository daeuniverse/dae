/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
)

// TestSysctlWatchReadFailureEmitsOneCorrectLine is the Q6 contract. The watch
// loop used to log the read error and then keep going with the empty string
// returned alongside it: it printed "has unexpected value , expected 1" (which
// reads as "the kernel has this setting empty") and then rewrote a file whose
// contents it had never read. One failed observation must now produce exactly
// one line, describing the read failure, and no rewrite.
func TestSysctlWatchReadFailureEmitsOneCorrectLine(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "no-such-sysctl")

	logger, hook := test.NewNullLogger()
	logger.SetLevel(logrus.TraceLevel)
	manager := &SysctlManager{log: logger, expectations: map[string]string{}}

	manager.handleWatchEvent(missing, "1")

	entries := hook.AllEntries()
	if len(entries) != 1 {
		t.Fatalf("failed read emitted %d entries, want exactly 1:\n%s", len(entries), formatEntries(entries))
	}
	entry := entries[0]
	if entry.Level != logrus.ErrorLevel {
		t.Fatalf("failed read level = %v, want error", entry.Level)
	}
	if !strings.Contains(entry.Message, "failed to read sysctl file") {
		t.Fatalf("failed read message = %q, want the read failure", entry.Message)
	}
	if strings.Contains(entry.Message, "unexpected value") {
		t.Fatalf("failed read also claimed an unexpected value: %q", entry.Message)
	}
}

// TestSysctlWatchRewriteStillFiresOnMismatch guards the behaviour the Q6 fix
// had to preserve: when the value is really readable and really differs, the
// loop still reports it and rewrites it.
func TestSysctlWatchRewriteStillFiresOnMismatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "forwarding")
	if err := os.WriteFile(path, []byte("0\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	logger, hook := test.NewNullLogger()
	logger.SetLevel(logrus.TraceLevel)
	manager := &SysctlManager{log: logger, expectations: map[string]string{}}

	manager.handleWatchEvent(path, "1")

	entries := hook.AllEntries()
	if len(entries) != 1 {
		t.Fatalf("mismatch emitted %d entries, want exactly 1 (the unexpected-value line):\n%s", len(entries), formatEntries(entries))
	}
	if entry := entries[0]; entry.Level != logrus.InfoLevel || !strings.Contains(entry.Message, "has unexpected value 0, expected 1") {
		t.Fatalf("mismatch line = %v %q, want the observed and expected values", entry.Level, entry.Message)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "1" {
		t.Fatalf("sysctl file = %q after the watch event, want \"1\"", string(got))
	}
}

// TestSysctlWatchMatchingValueIsSilent pins that a value the kernel already has
// right produces no line at all (the loop's only job is to correct drift).
func TestSysctlWatchMatchingValueIsSilent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "forwarding")
	if err := os.WriteFile(path, []byte("1"), 0o600); err != nil {
		t.Fatal(err)
	}

	logger, hook := test.NewNullLogger()
	logger.SetLevel(logrus.TraceLevel)
	manager := &SysctlManager{log: logger, expectations: map[string]string{}}

	manager.handleWatchEvent(path, "1")
	if got := len(hook.AllEntries()); got != 0 {
		t.Fatalf("matching value emitted %d entries, want 0:\n%s", got, formatEntries(hook.AllEntries()))
	}
}

func formatEntries(entries []*logrus.Entry) string {
	var b strings.Builder
	for _, entry := range entries {
		b.WriteString(entry.Level.String())
		b.WriteString(": ")
		b.WriteString(entry.Message)
		b.WriteByte('\n')
	}
	return b.String()
}
