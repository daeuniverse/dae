/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package subscription

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/sirupsen/logrus"
)

// TestResolveSubscription_PersistFileKeepsGoodCacheOnEmptyFetch verifies the
// core guard: when a persisted (cached) subscription already exists and a
// broken subscription server returns empty/garbage, the good cache is NOT
// overwritten. The previously-fetched nodes should still resolve on the
// fallback read path, so proxied traffic keeps working.
func TestResolveSubscription_PersistFileKeepsGoodCacheOnEmptyFetch(t *testing.T) {
	dir := t.TempDir()
	persistDir := filepath.Join(dir, "persist.d")
	if err := os.MkdirAll(persistDir, 0700); err != nil {
		t.Fatalf("mkdir persist.d: %v", err)
	}

	const cachedGood = "vmess://c2VydmVyOjQ0Mwo=#good-node\n"
	if err := os.WriteFile(filepath.Join(persistDir, "my.sub"), []byte(cachedGood), 0600); err != nil {
		t.Fatalf("seed cache: %v", err)
	}

	// A broken subscription server: it returns an HTTP 200 but a body that is
	// neither a valid SIP008 JSON nor a base64-encoded node list.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("this is not a valid subscription payload"))
	}))
	defer srv.Close()

	host := srv.URL[len("http://"):]
	url := "my:http-file://" + host
	client := srv.Client()

	// The payload is unusable, so the last good nodes must be kept: dropping
	// them would remove working nodes from the running generation.
	_, nodes, err := ResolveSubscription(logrus.New(), client, dir, url)
	if err != nil {
		t.Fatalf("a bad payload must fall back to the cache, got err=%v", err)
	}
	if len(nodes) != 1 {
		t.Fatalf("expected the 1 cached node, got %d: %v", len(nodes), nodes)
	}

	// The good cache must be intact.
	got, err := os.ReadFile(filepath.Join(persistDir, "my.sub"))
	if err != nil {
		t.Fatalf("read cache: %v", err)
	}
	if string(got) != cachedGood {
		t.Fatalf("cache was clobbered: got %q want %q", string(got), cachedGood)
	}
}

// TestResolveSubscription_KeepsCacheOnHTTPError verifies that an HTTP 500 is
// treated as a failed refresh rather than as an empty subscription.
func TestResolveSubscription_KeepsCacheOnHTTPError(t *testing.T) {
	dir := t.TempDir()
	persistDir := filepath.Join(dir, "persist.d")
	if err := os.MkdirAll(persistDir, 0700); err != nil {
		t.Fatalf("mkdir persist.d: %v", err)
	}
	const cachedGood = "vmess://c2VydmVyOjQ0Mwo=#good-node\n"
	if err := os.WriteFile(filepath.Join(persistDir, "subA.sub"), []byte(cachedGood), 0600); err != nil {
		t.Fatalf("seed cache: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("upstream broke"))
	}))
	defer srv.Close()

	tag, nodes, err := ResolveSubscription(logrus.New(), srv.Client(), dir, "subA:"+srv.URL)
	if err != nil {
		t.Fatalf("an HTTP 500 must fall back to the cache, got err=%v", err)
	}
	if tag != "subA" {
		t.Fatalf("tag = %q, want subA", tag)
	}
	if len(nodes) != 1 {
		t.Fatalf("expected the cached node, got %d", len(nodes))
	}
}

// TestResolveSubscription_CachesUntaggedSubscription verifies the common case:
// a plain http subscription with no tag still gets a cached copy, so the next
// failed refresh can keep its nodes.
func TestResolveSubscription_CachesUntaggedSubscription(t *testing.T) {
	dir := t.TempDir()
	payload := []byte(base64.StdEncoding.EncodeToString([]byte("vmess://c2VydmVyOjQ0Mwo=#node-a\n")))
	replies := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		replies++
		if replies > 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	}))
	defer srv.Close()

	tag, nodes, err := ResolveSubscription(logrus.New(), srv.Client(), dir, srv.URL)
	if err != nil || len(nodes) != 1 {
		t.Fatalf("first fetch: nodes=%v err=%v", nodes, err)
	}
	if tag != "" {
		t.Fatalf("untagged subscription reported tag %q", tag)
	}

	// The cache now exists under the URL-derived key.
	cacheKey := CacheKey("", srv.URL)
	if _, err := os.Stat(filepath.Join(dir, "persist.d", cacheKey+".sub")); err != nil {
		t.Fatalf("expected a cache at %s.sub: %v", cacheKey, err)
	}

	// The second resolve fails over to the cache instead of dropping the node.
	_, nodes, err = ResolveSubscription(logrus.New(), srv.Client(), dir, srv.URL)
	if err != nil || len(nodes) != 1 {
		t.Fatalf("second fetch: nodes=%v err=%v", nodes, err)
	}
}

// TestResolveSubscription_PersistFileOverwritesCacheOnValidFetch verifies the
// happy path: a valid fetch DOES update the persisted cache.
func TestResolveSubscription_PersistFileOverwritesCacheOnValidFetch(t *testing.T) {
	dir := t.TempDir()
	persistDir := filepath.Join(dir, "persist.d")
	if err := os.MkdirAll(persistDir, 0700); err != nil {
		t.Fatalf("mkdir persist.d: %v", err)
	}

	payload := []byte(base64.StdEncoding.EncodeToString([]byte("vmess://c2VydmVyOjQ0Mwo=#node-a\nvmess://c2VydmVyOjQ0Mwo=#node-b\n")))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	}))
	defer srv.Close()

	host := srv.URL[len("http://"):]
	url := "my:http-file://" + host
	_, nodes, err := ResolveSubscription(logrus.New(), srv.Client(), dir, url)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(nodes) != 2 {
		t.Fatalf("expected 2 nodes, got %d", len(nodes))
	}

	// Cache should now hold the new payload.
	got, err := os.ReadFile(filepath.Join(persistDir, "my.sub"))
	if err != nil {
		t.Fatalf("read cache: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("cache not updated: got %q want %q", string(got), string(payload))
	}
}
