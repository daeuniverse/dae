/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/daeuniverse/dae/component/outbound"
	"github.com/sirupsen/logrus"
)

// A fetched body replaces the cached copy only when at least one of its links
// became a dialer. Otherwise a payload nobody can load would destroy the last
// good copy and leave the groups empty.
func TestPersistFetchedSubscriptionsKeepsCopyWhenNoLinkParsed(t *testing.T) {
	dir := t.TempDir()
	persistDir := filepath.Join(dir, "persist.d")
	if err := os.MkdirAll(persistDir, 0o700); err != nil {
		t.Fatalf("mkdir persist.d: %v", err)
	}
	const good = "vmess://c2VydmVyOjQ0Mwo=#good\n"
	if err := os.WriteFile(filepath.Join(persistDir, "subA.sub"), []byte(good), 0o600); err != nil {
		t.Fatalf("seed cache: %v", err)
	}

	fetched := []fetchedSubscription{
		{tag: "subA", cacheKey: "subA", payload: []byte("bogus://invalid\n")},
		{tag: "subB", cacheKey: "subB", payload: []byte("vmess://c2VydmVyOjQ0Mwo=#n\n")},
	}
	report := map[string]outbound.NodeParseCount{
		"subA": {Links: 1, Parsed: 0},
		"subB": {Links: 1, Parsed: 1},
	}

	rejected, err := persistFetchedSubscriptions(logrus.New(), dir, fetched, report)
	if err != nil {
		t.Fatalf("persist: %v", err)
	}
	if len(rejected) != 1 || rejected[0] != "subA" {
		t.Fatalf("rejected = %v, want [subA]", rejected)
	}
	if got, err := os.ReadFile(filepath.Join(persistDir, "subA.sub")); err != nil || string(got) != good {
		t.Fatalf("subA cache changed: got %q err=%v", string(got), err)
	}
	if _, err := os.Stat(filepath.Join(persistDir, "subB.sub")); err != nil {
		t.Fatalf("subB payload was not persisted: %v", err)
	}
}
