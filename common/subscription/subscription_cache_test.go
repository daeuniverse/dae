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
	"strings"
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

	resolved, err := Resolve(logrus.New(), srv.Client(), dir, srv.URL)
	if err != nil || len(resolved.Nodes) != 1 {
		t.Fatalf("first fetch: nodes=%v err=%v", resolved.Nodes, err)
	}
	if resolved.Tag != "" {
		t.Fatalf("untagged subscription reported tag %q", resolved.Tag)
	}

	// The cache now exists under the URL-derived key, and only the caller writes
	// it: a payload the engine cannot load must never reach persist.d.
	cacheKey := CacheKey("", srv.URL)
	if resolved.CacheKey != cacheKey {
		t.Fatalf("cache key = %q, want %q", resolved.CacheKey, cacheKey)
	}
	if _, err := os.Stat(filepath.Join(dir, "persist.d", cacheKey+".sub")); !os.IsNotExist(err) {
		t.Fatalf("Resolve must not persist by itself: %v", err)
	}
	if err := PersistPayload(dir, resolved.CacheKey, resolved.Payload); err != nil {
		t.Fatalf("persist: %v", err)
	}

	// The second resolve fails over to the cache instead of dropping the node.
	fallback, err := Resolve(logrus.New(), srv.Client(), dir, srv.URL)
	if err != nil || len(fallback.Nodes) != 1 {
		t.Fatalf("second fetch: nodes=%v err=%v", fallback.Nodes, err)
	}
	if !fallback.CacheFallback {
		t.Fatalf("a failed fetch must report the cached fallback")
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
	resolved, err := Resolve(logrus.New(), srv.Client(), dir, url)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(resolved.Nodes) != 2 {
		t.Fatalf("expected 2 nodes, got %d", len(resolved.Nodes))
	}
	if err := PersistPayload(dir, resolved.CacheKey, resolved.Payload); err != nil {
		t.Fatalf("persist: %v", err)
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

// TestResolveSubscription_LoginPageDoesNotReplaceCache covers the case the old
// parser got wrong: an HTML login page contains "://" on its own line, so the
// previous line-level fallback counted the page as one node and persisted it
// over the last good copy.
func TestResolveSubscription_LoginPageDoesNotReplaceCache(t *testing.T) {
	dir := t.TempDir()
	persistDir := filepath.Join(dir, "persist.d")
	if err := os.MkdirAll(persistDir, 0700); err != nil {
		t.Fatalf("mkdir persist.d: %v", err)
	}
	const cachedGood = "vmess://c2VydmVyOjQ0Mwo=#good-node\n"
	if err := os.WriteFile(filepath.Join(persistDir, "subA.sub"), []byte(cachedGood), 0600); err != nil {
		t.Fatalf("seed cache: %v", err)
	}

	loginPage := []byte("<!DOCTYPE html><html><body>" +
		"<a href=\"https://accounts.example.com/login\">Sign in</a>" +
		"</body></html>")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(loginPage)
	}))
	defer srv.Close()

	resolved, err := Resolve(logrus.New(), srv.Client(), dir, "subA:"+srv.URL)
	if err != nil {
		t.Fatalf("a login page must fall back to the cache, got err=%v", err)
	}
	if len(resolved.Nodes) != 1 || resolved.Nodes[0] != "vmess://c2VydmVyOjQ0Mwo=#good-node" {
		t.Fatalf("expected the cached node, got %v", resolved.Nodes)
	}
	if !resolved.CacheFallback {
		t.Fatalf("a login page is a failed refresh, not a successful one")
	}
	if resolved.Payload != nil {
		t.Fatalf("a rejected payload must not be offered for persistence")
	}
	got, err := os.ReadFile(filepath.Join(persistDir, "subA.sub"))
	if err != nil {
		t.Fatalf("read cache: %v", err)
	}
	if string(got) != cachedGood {
		t.Fatalf("cache was clobbered: got %q want %q", string(got), cachedGood)
	}
}

func TestIsShareLinkLine(t *testing.T) {
	cases := []struct {
		line string
		want bool
	}{
		{"vmess://c2VydmVyOjQ0Mwo=#node", true},
		{"ss://YWVzLTI1Ni1nY206cHc@1.2.3.4:8388#n", true},
		{"socks5://u:p@1.2.3.4:1080", true},
		{"ss://a->socks5://b", true},
		{"<!DOCTYPE html>", false},
		{"<a href=\"https://accounts.example.com/login\">", false},
		{"  <a href=\"https://x\">", false},
		{"this is not a subscription", false},
		{"https://", false},
		{"://missing-scheme", false},
	}
	for _, tc := range cases {
		if got := isShareLinkLine(strings.TrimSpace(tc.line)); got != tc.want {
			t.Errorf("isShareLinkLine(%q) = %v, want %v", tc.line, got, tc.want)
		}
	}
}
