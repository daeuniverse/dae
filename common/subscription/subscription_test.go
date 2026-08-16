package subscription

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
)

func TestResolveSubscriptionAsSIP008_SS2022KeepsRawPSK(t *testing.T) {
	const password = "RCF/0OOYmo6crue3LwlEyD8izLAbuUuyPic/vasJH/o="
	payload := []byte(`{
		"version": 1,
		"servers": [
			{
				"id": "n1",
				"remarks": "test",
				"server": "127.0.0.1",
				"server_port": 443,
				"password": "` + password + `",
				"method": "2022-blake3-aes-256-gcm",
				"plugin": "",
				"plugin_opts": ""
			}
		]
	}`)

	nodes, err := ResolveSubscriptionAsSIP008(logrus.New(), payload)
	if err != nil {
		t.Fatalf("ResolveSubscriptionAsSIP008: %v", err)
	}
	if len(nodes) != 1 {
		t.Fatalf("expected one node, got %d", len(nodes))
	}

	u, err := url.Parse(nodes[0])
	if err != nil {
		t.Fatalf("parse generated node: %v", err)
	}

	if _, hasPassword := u.User.Password(); hasPassword {
		t.Fatalf("expected canonical base64 userinfo, got %q", u.User.String())
	}

	decoded, err := base64.RawURLEncoding.DecodeString(u.User.Username())
	if err != nil {
		t.Fatalf("decode generated userinfo: %v", err)
	}

	if got, want := string(decoded), "2022-blake3-aes-256-gcm:"+password; got != want {
		t.Fatalf("unexpected decoded userinfo: got %q want %q", got, want)
	}
}

func encodeSubscription(nodes ...string) []byte {
	return []byte(base64.StdEncoding.EncodeToString([]byte(strings.Join(nodes, "\n"))))
}

func TestResolveSubscriptionPersistFallsBackOnInvalidResponse(t *testing.T) {
	configDir := t.TempDir()
	persistDir := filepath.Join(configDir, "persist.d")
	if err := os.MkdirAll(persistDir, 0700); err != nil {
		t.Fatal(err)
	}

	oldPayload := encodeSubscription("ss://old.example:443#old")
	persistPath := filepath.Join(persistDir, "locked.sub")
	if err := os.WriteFile(persistPath, oldPayload, 0600); err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("Subscribe refresh is locked. Unlock it in your dashboard before fetching the subscription"))
	}))
	defer server.Close()

	subscriptionURL := "locked:" + strings.Replace(server.URL, "http://", "http-file://", 1)
	tag, nodes, err := ResolveSubscription(logrus.New(), server.Client(), configDir, subscriptionURL)
	if err != nil {
		t.Fatalf("ResolveSubscription: %v", err)
	}
	if tag != "locked" {
		t.Fatalf("tag = %q, want locked", tag)
	}
	if len(nodes) != 1 || nodes[0] != "ss://old.example:443#old" {
		t.Fatalf("nodes = %#v, want persisted node", nodes)
	}

	got, err := os.ReadFile(persistPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, oldPayload) {
		t.Fatalf("persisted subscription was overwritten by invalid response: %q", got)
	}
}

func TestResolveSubscriptionPersistReplacesValidResponse(t *testing.T) {
	configDir := t.TempDir()
	persistDir := filepath.Join(configDir, "persist.d")
	if err := os.MkdirAll(persistDir, 0700); err != nil {
		t.Fatal(err)
	}

	persistPath := filepath.Join(persistDir, "valid.sub")
	if err := os.WriteFile(persistPath, encodeSubscription("ss://old.example:443#old"), 0600); err != nil {
		t.Fatal(err)
	}
	newPayload := encodeSubscription("ss://new.example:443#new")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(newPayload)
	}))
	defer server.Close()

	subscriptionURL := "valid:" + strings.Replace(server.URL, "http://", "http-file://", 1)
	_, nodes, err := ResolveSubscription(logrus.New(), server.Client(), configDir, subscriptionURL)
	if err != nil {
		t.Fatalf("ResolveSubscription: %v", err)
	}
	if len(nodes) != 1 || nodes[0] != "ss://new.example:443#new" {
		t.Fatalf("nodes = %#v, want new node", nodes)
	}

	got, err := os.ReadFile(persistPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, newPayload) {
		t.Fatalf("persisted subscription = %q, want %q", got, newPayload)
	}
	info, err := os.Stat(persistPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("persisted mode = %04o, want 0600", info.Mode().Perm())
	}
}

func TestResolveSubscriptionPersistFallsBackOnHTTPError(t *testing.T) {
	configDir := t.TempDir()
	persistDir := filepath.Join(configDir, "persist.d")
	if err := os.MkdirAll(persistDir, 0700); err != nil {
		t.Fatal(err)
	}

	oldPayload := encodeSubscription("ss://old.example:443#old")
	persistPath := filepath.Join(persistDir, "unavailable.sub")
	if err := os.WriteFile(persistPath, oldPayload, 0600); err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("temporarily unavailable"))
	}))
	defer server.Close()

	subscriptionURL := "unavailable:" + strings.Replace(server.URL, "http://", "http-file://", 1)
	tag, nodes, err := ResolveSubscription(logrus.New(), server.Client(), configDir, subscriptionURL)
	if err != nil {
		t.Fatalf("ResolveSubscription: %v", err)
	}
	if tag != "unavailable" {
		t.Fatalf("tag = %q, want unavailable", tag)
	}
	if len(nodes) != 1 || nodes[0] != "ss://old.example:443#old" {
		t.Fatalf("nodes = %#v, want persisted node", nodes)
	}

	got, err := os.ReadFile(persistPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, oldPayload) {
		t.Fatalf("persisted subscription changed after HTTP error: %q", got)
	}
}
