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

func TestValidateSubscriptionNodesSkipsInvalidChainWithoutLoggingLink(t *testing.T) {
	const secret = "uuid-password-token"
	var logs bytes.Buffer
	log := logrus.New()
	log.SetOutput(&logs)
	nodes := []string{
		"vmess://" + secret + "@a -> tuic://b -> vless://c",
		"vmess://valid",
	}

	valid := validateSubscriptionNodes(log, "remote", nodes)
	if len(valid) != 1 || valid[0] != nodes[1] {
		t.Fatalf("valid nodes = %#v", valid)
	}
	if strings.Contains(logs.String(), secret) || strings.Contains(logs.String(), nodes[0]) {
		t.Fatalf("log leaked node credentials: %s", logs.String())
	}
	if !strings.Contains(logs.String(), "skip invalid subscription node") {
		t.Fatalf("missing invalid-node log: %s", logs.String())
	}
}

func TestResolveSubscriptionKeepsPersistedNodesWhenRemoteHasNoValidNodes(t *testing.T) {
	dir := t.TempDir()
	persistDir := filepath.Join(dir, "persist.d")
	if err := os.MkdirAll(persistDir, 0700); err != nil {
		t.Fatal(err)
	}
	oldContent := encodeSubscription("vmess://old-valid")
	persistPath := filepath.Join(persistDir, "remote.sub")
	if err := os.WriteFile(persistPath, oldContent, 0600); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(encodeSubscription("vmess://a -> tuic://b -> vless://c"))
	}))
	defer server.Close()

	link := "remote:" + strings.Replace(server.URL, "http://", "http-file://", 1)
	tag, nodes, err := ResolveSubscription(logrus.New(), server.Client(), dir, link)
	if err != nil {
		t.Fatal(err)
	}
	if tag != "remote" || len(nodes) != 1 || nodes[0] != "vmess://old-valid" {
		t.Fatalf("tag = %q, nodes = %#v", tag, nodes)
	}
	got, err := os.ReadFile(persistPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, oldContent) {
		t.Fatal("invalid remote subscription overwrote the last valid cache")
	}
}
