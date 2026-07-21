/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/daeuniverse/dae/config"
)

func TestRemoveStalePersistedSubscriptionsKeepsConfiguredFailedSubscription(t *testing.T) {
	dir := t.TempDir()
	persistDir := filepath.Join(dir, "persist.d")
	if err := os.MkdirAll(persistDir, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"current.sub", "stale.sub"} {
		if err := os.WriteFile(filepath.Join(persistDir, name), []byte("node"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	tags := configuredPersistSubscriptionTags([]config.KeyableString{
		"current:https-file://example.com/sub",
	})
	if err := removeStalePersistedSubscriptions(dir, tags); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(persistDir, "current.sub")); err != nil {
		t.Fatalf("configured cache was removed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(persistDir, "stale.sub")); !os.IsNotExist(err) {
		t.Fatalf("stale cache still exists: %v", err)
	}
}
