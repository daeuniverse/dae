/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package config_parser

import (
	"strings"
	"testing"
)

func TestNewSectionItemUsesSectionType(t *testing.T) {
	item := NewSectionItem(&Section{Name: "routing"})

	if item.Type != ItemType_Section {
		t.Fatalf("expected item type %v, got %v", ItemType_Section, item.Type)
	}
}

func TestItemStringIncludesSectionType(t *testing.T) {
	item := NewSectionItem(&Section{Name: "routing"})

	got := item.String(false, false)
	if got == "" {
		t.Fatal("expected non-empty string representation")
	}
	if !strings.HasPrefix(got, "type: Section") {
		t.Fatalf("expected string to start with %q, got %q", "type: Section", got)
	}
}
