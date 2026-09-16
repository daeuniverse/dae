package subscription

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"testing"

	"github.com/daeuniverse/outbound/dialer/shadowsocks"
	"github.com/sirupsen/logrus"
)

func TestResolveSubscriptionAsSIP008PreservesPlugin(t *testing.T) {
	for _, tc := range []struct {
		name       string
		plugin     string
		opts       string
		wantQuery  string
		wantPlugin string
	}{
		{name: "obfs", plugin: "obfs-local", opts: "obfs=tls;obfs-host=example.com", wantQuery: "obfs-local;obfs=tls;obfs-host=example.com", wantPlugin: "simple-obfs"},
		{name: "plugin_only", plugin: "v2ray-plugin", wantQuery: "v2ray-plugin", wantPlugin: "v2ray-plugin"},
		{name: "no_plugin"},
		{name: "orphan_options", opts: "obfs=tls"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload, err := json.Marshal(sip008{Version: 1, Servers: []sip008Server{{
				Id: "test-node", Remarks: "test", Server: "127.0.0.1", ServerPort: 443,
				Password: "password", Method: "aes-128-gcm", Plugin: tc.plugin, PluginOpts: tc.opts,
			}}})
			if err != nil {
				t.Fatal(err)
			}
			nodes, err := ResolveSubscriptionAsSIP008(logrus.New(), payload)
			if err != nil || len(nodes) != 1 {
				t.Fatalf("resolve: nodes=%v err=%v", nodes, err)
			}
			u, err := url.Parse(nodes[0])
			if err != nil {
				t.Fatal(err)
			}
			if got := u.Query().Get("plugin"); got != tc.wantQuery {
				t.Errorf("plugin query=%q, want %q", got, tc.wantQuery)
			}
			parsed, err := shadowsocks.ParseSSURL(nodes[0])
			if err != nil {
				t.Fatal(err)
			}
			if parsed.Plugin.Name != tc.wantPlugin {
				t.Errorf("outbound plugin=%q, want %q", parsed.Plugin.Name, tc.wantPlugin)
			}
			if tc.name == "obfs" && (parsed.Plugin.Opts.Obfs != "tls" || parsed.Plugin.Opts.Host != "example.com") {
				t.Errorf("plugin options lost: %+v", parsed.Plugin.Opts)
			}
		})
	}
}

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
