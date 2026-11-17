/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGeoFileDigestTracksFileContent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "geoip.dat")
	if err := os.WriteFile(path, []byte("first"), 0o644); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	provider := &nativeAPIProvider{}
	first, err := provider.geoFileDigest(path, info)
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256([]byte("first"))
	if first != hex.EncodeToString(want[:]) {
		t.Fatalf("digest = %q, want sha256 of the file content", first)
	}
	// The cache must be keyed on size and mtime, so a rewrite is re-read
	// instead of reporting a stale fingerprint.
	if err := os.WriteFile(path, []byte("second"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Force a distinct mtime so the cache key changes even on filesystems with
	// coarse timestamp granularity.
	if err := os.Chtimes(path, info.ModTime().Add(time.Second), info.ModTime().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	updated, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := provider.geoFileDigest(path, updated)
	if err != nil {
		t.Fatal(err)
	}
	if second == first {
		t.Fatal("digest did not change after the file content changed")
	}
}
