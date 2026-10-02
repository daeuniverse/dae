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

func TestValidateFilePermissionForbidden(t *testing.T) {
	for _, tc := range []struct {
		mode      os.FileMode
		forbidden os.FileMode
		wantErr   bool
	}{
		// Private key: no group/other access.
		{mode: 0o600, forbidden: 0o077},
		{mode: 0o400, forbidden: 0o077},
		{mode: 0o640, forbidden: 0o077, wantErr: true},
		{mode: 0o604, forbidden: 0o077, wantErr: true},
		// Certificate: no group/other write.
		{mode: 0o644, forbidden: 0o022},
		{mode: 0o640, forbidden: 0o022},
		{mode: 0o600, forbidden: 0o022},
		{mode: 0o444, forbidden: 0o022},
		{mode: 0o664, forbidden: 0o022, wantErr: true},
		{mode: 0o646, forbidden: 0o022, wantErr: true},
	} {
		path, fi := writeTempFile(t, tc.mode)
		err := ValidateFilePermissionForbidden(path, fi, tc.forbidden)
		if (err != nil) != tc.wantErr {
			t.Fatalf("mode %04o forbidden %04o: err = %v, wantErr %v", tc.mode, tc.forbidden, err, tc.wantErr)
		}
	}

	dir := t.TempDir()
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if err := ValidateFilePermissionForbidden(dir, fi, 0o077); err == nil {
		t.Fatal("a directory should be rejected")
	}
}
