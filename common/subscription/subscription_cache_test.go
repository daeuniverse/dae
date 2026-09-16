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

	// ResolveSubscription should refuse to resolve (0 nodes) and therefore
	// NOT touch the persisted cache.
	_, nodes, err := ResolveSubscription(logrus.New(), client, dir, url)
	if err == nil {
		t.Fatalf("expected error for invalid subscription payload, got nodes=%v", nodes)
	}
	if len(nodes) != 0 {
		t.Fatalf("expected 0 nodes, got %d", len(nodes))
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
