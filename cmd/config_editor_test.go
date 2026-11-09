/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMaskSourceRedactsListenerSecret(t *testing.T) {
	in := "api {\n  listen: '127.0.0.1:1'\n  secret: 'hunter2'\n}\n"
	out, masked := maskSource(in)
	if !masked {
		t.Fatalf("expected secret to be masked")
	}
	if strings.Contains(out, "hunter2") {
		t.Fatalf("secret leaked: %q", out)
	}
	if !strings.Contains(out, "secret: '<redacted>'") {
		t.Fatalf("unexpected masked content: %q", out)
	}
}

func TestMaskSourceLeavesPlainConfigUntouched(t *testing.T) {
	in := "global {\n  log_level: info\n}\n"
	out, masked := maskSource(in)
	if masked || out != in {
		t.Fatalf("plain config must not be masked: %q", out)
	}
}

func TestVisibleSourcesHidesAPIDae(t *testing.T) {
	dir := t.TempDir()
	e := &configEditor{mainPath: filepath.Join(dir, "config.dae"), baseDir: dir}
	all := []configSourceFile{
		{abs: e.mainPath, path: "config.dae"},
		{abs: filepath.Join(dir, "api.dae"), path: "api.dae"},
		{abs: filepath.Join(dir, "node.dae"), path: "node.dae"},
	}
	visible := e.visibleSources(all)
	if len(visible) != 2 {
		t.Fatalf("expected 2 visible sources, got %d", len(visible))
	}
	for _, s := range visible {
		if filepath.Base(s.abs) == "api.dae" {
			t.Fatalf("api.dae must be hidden")
		}
	}
	if msg := e.scrub("failed to parse " + filepath.Join(dir, "api.dae")); strings.Contains(msg, "api.dae") {
		t.Fatalf("hidden name leaked: %q", msg)
	}
}

func TestWriteFileAtomicReplacesContent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node.dae")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomic(path, []byte("new"), 0o600); err != nil {
		t.Fatalf("writeFileAtomic: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "new" {
		t.Fatalf("content = %q, err = %v", got, err)
	}
}

// newManagedTree lays out config.dae + api.dae + config.d/*.dae under a temp dir.
func newManagedTree(t *testing.T) (main string, sources []string) {
	t.Helper()
	root := t.TempDir()
	main = filepath.Join(root, "config.dae")
	api := filepath.Join(root, "api.dae")
	if err := os.WriteFile(main, []byte("include {\n  config.d/*.dae\n  api.dae\n}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(api, []byte("api {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "config.d"), 0o700); err != nil {
		t.Fatal(err)
	}
	sources = []string{main, api}
	for _, m := range managedConfigModules {
		p := filepath.Join(root, "config.d", m)
		if err := os.WriteFile(p, []byte(managedModuleFixture(m)), 0o600); err != nil {
			t.Fatal(err)
		}
		sources = append(sources, p)
	}
	return main, sources
}

func TestDetectManagedLayout(t *testing.T) {
	main, sources := newManagedTree(t)
	if ok, reason := detectManagedLayout(main, sources); !ok {
		t.Fatalf("standard tree should be managed, reason=%q", reason)
	}

	cases := []struct {
		name   string
		mutate func(t *testing.T, main string, sources []string) []string
	}{
		{"missing api.dae", func(t *testing.T, main string, sources []string) []string {
			_ = os.Remove(filepath.Join(filepath.Dir(main), "api.dae"))
			return sources
		}},
		{"missing module", func(t *testing.T, main string, sources []string) []string {
			_ = os.Remove(filepath.Join(filepath.Dir(main), "config.d", "dns.dae"))
			return sources[:len(sources)-1]
		}},
		{"extra source outside config.d", func(t *testing.T, main string, sources []string) []string {
			return append(sources, filepath.Join(filepath.Dir(main), "extra.dae"))
		}},
		{"nested include in module", func(t *testing.T, main string, sources []string) []string {
			p := filepath.Join(filepath.Dir(main), "config.d", "dns.dae")
			_ = os.WriteFile(p, []byte("include {\n  _: './x.dae'\n}\n"), 0o600)
			return sources
		}},
		{"extra section in entry", func(t *testing.T, main string, sources []string) []string {
			_ = os.WriteFile(main, []byte("global {}\ninclude {\n  _: './config.d/*.dae'\n  _: './api.dae'\n}\n"), 0o600)
			return sources
		}},
		{"section from two files", func(t *testing.T, main string, sources []string) []string {
			p := filepath.Join(filepath.Dir(main), "config.d", "global.dae")
			_ = os.WriteFile(p, []byte("global {}\ndns {}\n"), 0o600)
			return sources
		}},
		{"module readable by others", func(t *testing.T, main string, sources []string) []string {
			p := filepath.Join(filepath.Dir(main), "config.d", "dns.dae")
			if err := os.Chmod(p, 0o644); err != nil {
				t.Fatal(err)
			}
			return sources
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			main, sources := newManagedTree(t)
			sources = c.mutate(t, main, sources)
			if ok, reason := detectManagedLayout(main, sources); ok || reason != "layout_unmanaged" {
				t.Fatalf("expected unmanaged, got ok=%v reason=%q", ok, reason)
			}
		})
	}
}

func TestEntryAndHiddenSourcesAreNotWritable(t *testing.T) {
	root := t.TempDir()
	e := &configEditor{mainPath: filepath.Join(root, "config.dae"), baseDir: root}
	entry := configSourceFile{abs: e.mainPath, kind: "main"}
	module := configSourceFile{abs: filepath.Join(root, "config.d", "dns.dae"), kind: "include"}
	if e.sourceWritable(entry) {
		t.Fatalf("config.dae must be read-only")
	}
	if !e.sourceWritable(module) {
		t.Fatalf("config.d module must be writable")
	}
}

func TestMaskSourceIgnoresCommentsInsideTheApiBlock(t *testing.T) {
	// A "}" inside a comment used to end the block early, so the real secret
	// after it was returned verbatim by GET /config.
	in := "api {\n  # closing brace in a comment: }\n  secret: 'hunter2'\n}\n"
	out, masked := maskSource(in)
	if !masked || strings.Contains(out, "hunter2") {
		t.Fatalf("secret leaked: %q", out)
	}

	// A commented-out secret must not be what gets redacted.
	in = "api {\n  # secret: 'commented-out'\n  secret: 'hunter2'\n}\n"
	out, masked = maskSource(in)
	if !masked || strings.Contains(out, "hunter2") {
		t.Fatalf("live secret leaked: %q", out)
	}
	if !strings.Contains(out, "commented-out") {
		t.Fatalf("a comment must be left alone: %q", out)
	}

	// A quoted value containing a brace must not end the block either.
	in = "api {\n  note: 'a}b'\n  secret: 'hunter2'\n}\n"
	out, masked = maskSource(in)
	if !masked || strings.Contains(out, "hunter2") {
		t.Fatalf("secret after a quoted brace leaked: %q", out)
	}
}

func TestGetConfigRevisionMatchesTheGenerationFormula(t *testing.T) {
	// GET /config and runtime.generation.config_revision used different
	// algorithms, so a client could never tell whether disk was what the engine
	// had loaded. They are the same function now.
	main, _ := newManagedTree(t)
	e := newFlowEditor(t, main, true, &fakeConfigOperations{})

	got, err := e.GetConfig(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := e.buildCandidate(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Revision == "" {
		t.Fatal("revision must not be empty for a parseable tree")
	}
	if got.Revision != candidate.Revision() {
		t.Fatalf("revision = %q, want the generation formula %q", got.Revision, candidate.Revision())
	}
}
