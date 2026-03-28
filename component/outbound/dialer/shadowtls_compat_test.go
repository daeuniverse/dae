package dialer

import (
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
)

func TestNormalizeShadowTLSSIP003Plugin(t *testing.T) {
	tests := []struct {
		name         string
		plugin       string
		wantPlugin   string
		wantModified bool
	}{
		{
			name:         "convert skipVerify key",
			plugin:       "shadowtls;password=abc;skipVerify=true",
			wantPlugin:   "shadowtls;password=abc;allowInsecure=true",
			wantModified: true,
		},
		{
			name:         "convert allowInsecure flag",
			plugin:       "shadowtls;password=abc;allowInsecure",
			wantPlugin:   "shadowtls;password=abc;allowInsecure=true",
			wantModified: true,
		},
		{
			name:         "convert insecure flag",
			plugin:       "shadow-tls;password=abc;insecure",
			wantPlugin:   "shadow-tls;password=abc;insecure=true",
			wantModified: true,
		},
		{
			name:         "ignore non-shadowtls plugin",
			plugin:       "v2ray-plugin;mode=websocket",
			wantPlugin:   "v2ray-plugin;mode=websocket",
			wantModified: false,
		},
		{
			name:         "keep already explicit bool value",
			plugin:       "shadowtls;password=abc;allow_insecure=true",
			wantPlugin:   "shadowtls;password=abc;allow_insecure=true",
			wantModified: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotPlugin, gotModified := normalizeShadowTLSSIP003Plugin(tc.plugin)
			if gotModified != tc.wantModified {
				t.Fatalf("modified mismatch: got=%v want=%v", gotModified, tc.wantModified)
			}
			if gotPlugin != tc.wantPlugin {
				t.Fatalf("plugin mismatch: got=%q want=%q", gotPlugin, tc.wantPlugin)
			}
		})
	}
}

func TestNormalizeShadowTLSPluginOptions_StandardSSLink(t *testing.T) {
	link := "ss://YWVzLTEyOC1nY206cGFzcw@1.2.3.4:443?plugin=shadowtls%3Bpassword%3Dabc%3BskipVerify%3Dtrue#node"
	normalized := normalizeShadowTLSPluginOptions(link)

	u, err := url.Parse(normalized)
	if err != nil {
		t.Fatalf("parse normalized link: %v", err)
	}
	plugin := u.Query().Get("plugin")
	if !strings.Contains(plugin, "allowInsecure=true") {
		t.Fatalf("expected allowInsecure in plugin, got: %q", plugin)
	}
	if strings.Contains(strings.ToLower(plugin), "skipverify") {
		t.Fatalf("skipVerify should be normalized away, got: %q", plugin)
	}
}

func TestNormalizeShadowTLSPluginOptions_Base64WholeLink(t *testing.T) {
	payload := "aes-128-gcm:pass@1.2.3.4:443/?plugin=shadowtls%3Bpassword%3Dabc%3BskipVerify%3Dtrue"
	link := "ss://" + base64.RawURLEncoding.EncodeToString([]byte(payload)) + "#node"

	normalized := normalizeShadowTLSPluginOptions(link)
	if normalized == link {
		t.Fatal("expected base64 whole-link to be normalized")
	}

	u, err := url.Parse(normalized)
	if err != nil {
		t.Fatalf("parse normalized link: %v", err)
	}
	plugin := u.Query().Get("plugin")
	if !strings.Contains(plugin, "allowInsecure=true") {
		t.Fatalf("expected allowInsecure in plugin, got: %q", plugin)
	}
}
