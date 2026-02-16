/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package config

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestMarshal(t *testing.T) {
	abs, err := filepath.Abs("../example.dae")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(abs)
	if err != nil {
		t.Fatal(err)
	}
	tmpDir := t.TempDir()
	tmpInput := filepath.Join(tmpDir, "example.dae")
	if err = os.WriteFile(tmpInput, raw, 0600); err != nil {
		t.Fatal(err)
	}
	merger := NewMerger(tmpInput)
	sections, _, err := merger.Merge()
	if err != nil {
		t.Fatal(err)
	}
	conf1, err := New(sections)
	if err != nil {
		t.Fatal(err)
	}
	b, err := conf1.Marshal(2)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(b))
	// Read it again.
	tmpOutput := filepath.Join(tmpDir, "test.dae")
	if err = os.WriteFile(tmpOutput, b, 0600); err != nil {
		t.Fatal(err)
	}
	sections, _, err = NewMerger(tmpOutput).Merge()
	if err != nil {
		t.Fatal(err)
	}
	conf2, err := New(sections)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := conf2.Marshal(2)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(b, b2) {
		t.Fatalf("marshal should be idempotent after one round-trip\nfirst:\n%s\nsecond:\n%s", string(b), string(b2))
	}
}
