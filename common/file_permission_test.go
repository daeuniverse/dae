/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package common

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTempFile(t *testing.T, mode os.FileMode) (string, os.FileInfo) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "x")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod temp file: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat temp file: %v", err)
	}
	return path, fi
}

func TestValidateFilePermissionNotTooOpen(t *testing.T) {
	_, fi0600 := writeTempFile(t, 0o600)
	if err := ValidateFilePermissionNotTooOpen("test-0600", fi0600); err != nil {
		t.Fatalf("0600 should pass: %v", err)
	}

	_, fi0640 := writeTempFile(t, 0o640)
	if err := ValidateFilePermissionNotTooOpen("test-0640", fi0640); err != nil {
		t.Fatalf("0640 should pass: %v", err)
	}

	_, fi0644 := writeTempFile(t, 0o644)
	if err := ValidateFilePermissionNotTooOpen("test-0644", fi0644); err == nil {
		t.Fatal("0644 should fail as too open")
	}
}

func TestValidateFilePermissionAllowed(t *testing.T) {
	_, fi0600 := writeTempFile(t, 0o600)
	if err := ValidateFilePermissionAllowed("key", fi0600, 0o600); err != nil {
		t.Fatalf("0600 should pass for key: %v", err)
	}
	if err := ValidateFilePermissionAllowed("key", fi0600, 0o640, 0o644); err == nil {
		t.Fatal("0600 should fail for cert-only allowed modes")
	}

	_, fi0640 := writeTempFile(t, 0o640)
	if err := ValidateFilePermissionAllowed("cert", fi0640, 0o640, 0o644); err != nil {
		t.Fatalf("0640 should pass for cert: %v", err)
	}

	_, fi0644 := writeTempFile(t, 0o644)
	if err := ValidateFilePermissionAllowed("cert", fi0644, 0o640, 0o644); err != nil {
		t.Fatalf("0644 should pass for cert: %v", err)
	}
}
