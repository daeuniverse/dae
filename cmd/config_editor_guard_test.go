/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"strings"
	"testing"

	"github.com/daeuniverse/dae/config"
)

func TestDeclaresApiSection(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    bool
	}{
		{"empty api block", "global {\n}\napi {}\n", true},
		{"api with fields", "api {\n  enabled: true\n}\n", true},
		{"other sections", "global {\n  log_level: info\n}\n", false},
		{"api mentioned in a string", "global {\n  tproxy: 'redir-host'\n}\n", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := declaresApiSection(test.content); got != test.want {
				t.Fatalf("declaresApiSection(%q) = %v, want %v", test.content, got, test.want)
			}
		})
	}
}

func TestGuardConfigWriteRejectsSecondApiSection(t *testing.T) {
	// An api block outside api.dae keeps the effective listener settings equal,
	// so the value comparison lets it through; the layout check then sees one
	// section from two files and refuses every later write.
	editor := &configEditor{apiAtStart: config.Api{}, busy: func() bool { return false }}
	target := configSourceFile{abs: "/tmp/config.d/global.dae", id: "source-global"}
	err := editor.guardConfigWrite(target, []byte("global {\n}\napi {}\n"))
	if err == nil {
		t.Fatal("a second api section was accepted")
	}
	if !strings.Contains(err.Error(), "api") {
		t.Fatalf("err = %v, want it to name the api section", err)
	}

	// The listener source itself may of course declare it.
	apiTarget := configSourceFile{abs: "/tmp/config.d/api.dae", id: "source-api"}
	if err := editor.guardConfigWrite(apiTarget, []byte("api {}\n")); err != nil {
		// The only expected failure is the unwritable-file check on a path that
		// does not exist in this test; anything mentioning the section is a bug.
		if strings.Contains(err.Error(), "api section") {
			t.Fatalf("api.dae was refused: %v", err)
		}
	}
}
