/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/daeuniverse/dae/common/subscription"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/config"
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

	rejected := persistFetchedSubscriptions(logrus.New(), dir, fetched, report)
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

// A successful Resolve must end as a cache file in persist.d: the payload and
// cache key travel through subscriptionResult into persistFetchedSubscriptions.
func TestResolvedSubscriptionIsPersisted(t *testing.T) {
	const body = "vmess://c2VydmVyOjQ0Mwo=#n\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	dir := t.TempDir()
	sub := "subA:" + srv.URL
	resolved, err := subscription.Resolve(logrus.New(), srv.Client(), dir, sub)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	result := newSubscriptionResult(config.KeyableString(sub), resolved, err, 0)
	if len(result.payload) == 0 || result.cacheKey == "" {
		t.Fatalf("payload/cacheKey dropped: %q %q", result.payload, result.cacheKey)
	}
	fetched := []fetchedSubscription{{tag: result.cacheKey, cacheKey: result.cacheKey, payload: result.payload}}
	persistFetchedSubscriptions(logrus.New(), dir, fetched, nil)
	got, err := os.ReadFile(filepath.Join(dir, "persist.d", result.cacheKey+".sub"))
	if err != nil || len(got) == 0 {
		t.Fatalf("cache file missing: %v", err)
	}
}
