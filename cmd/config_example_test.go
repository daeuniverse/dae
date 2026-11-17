/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/config"
)

// copyConfigTree copies example-separated into a temp dir with the permissions
// dae demands, because a checkout carries 0644 and the merger refuses a file
// readable by others.
func copyConfigTree(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		defer func() { _ = in.Close() }()
		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, in); err != nil {
			_ = out.Close()
			return err
		}
		return out.Close()
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestExampleSeparatedSatisfiesManagedLayout keeps the shipped example honest:
// the documentation points at it as the tree the API accepts, so it has to pass
// the same gate the engine applies before enabling writes.
func TestExampleSeparatedSatisfiesManagedLayout(t *testing.T) {
	root := filepath.Join("..", "example-separated")
	if _, err := os.Stat(root); err != nil {
		t.Fatalf("example-separated is missing: %v", err)
	}
	dir := t.TempDir()
	copyConfigTree(t, root, dir)

	main := filepath.Join(dir, "config.dae")
	_, entries, err := config.NewMerger(main).Merge()
	if err != nil {
		t.Fatalf("the example does not merge: %v", err)
	}
	ok, reason := detectManagedLayout(main, entries)
	if !ok {
		t.Fatalf("the example does not satisfy the managed layout: %s", reason)
	}
}

// TestExampleSeparatedHasNoComments keeps the example copy-pasteable: the shipped
// tree documents every field in the docs pages instead of in the files.
func TestExampleSeparatedHasNoComments(t *testing.T) {
	root := filepath.Join("..", "example-separated")
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		body, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		for i, line := range strings.Split(string(body), "\n") {
			for _, ch := range line {
				if ch == '#' {
					t.Fatalf("%s:%d carries a comment: %s", path, i+1, line)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
