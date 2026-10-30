/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/pkg/config_parser"
)

func parseAPIConfig(t *testing.T, extra string) *Config {
	t.Helper()
	sections, err := config_parser.Parse(`
global {}
routing {
    fallback: direct
}
` + extra)
	if err != nil {
		t.Fatal(err)
	}
	conf, err := New(sections)
	if err != nil {
		t.Fatal(err)
	}
	return conf
}

func TestApiSectionDecode(t *testing.T) {
	conf := parseAPIConfig(t, `
api {
    enabled: true
    listen: '127.0.0.1:19527'
    secret: 'operator-token-123456'
    allow_origins: 'http://localhost:3000,https://panel.example'
    allowed_hosts: 'panel.example,panel.example:443'
}
`)
	if !conf.Api.Enabled {
		t.Fatal("api.enabled not decoded")
	}
	if got, want := conf.Api.Listen, "127.0.0.1:19527"; got != want {
		t.Fatalf("api.listen = %q, want %q", got, want)
	}
	if got, want := conf.Api.Secret, "operator-token-123456"; got != want {
		t.Fatalf("api.secret = %q, want %q", got, want)
	}
	if len(conf.Api.AllowOrigins) != 2 {
		t.Fatalf("api.allow_origins = %#v", conf.Api.AllowOrigins)
	}
	if len(conf.Api.AllowedHosts) != 2 {
		t.Fatalf("api.allowed_hosts = %#v", conf.Api.AllowedHosts)
	}
}

func TestApiSectionDefaultsWhenAbsent(t *testing.T) {
	conf := parseAPIConfig(t, "")
	if conf.Api.Enabled {
		t.Fatal("api should be disabled when the section is absent")
	}
	if got, want := conf.Api.Listen, "127.0.0.1:9527"; got != want {
		t.Fatalf("default api.listen = %q, want %q", got, want)
	}
	if conf.Api.AllowAnonymousLoopback {
		t.Fatal("allow_anonymous_loopback should default to false")
	}
}

func TestApiValidate(t *testing.T) {
	tests := []struct {
		name    string
		api     Api
		wantErr string
	}{
		{
			name: "disabled ignores invalid fields",
			api:  Api{Listen: "not-an-address"},
		},
		{
			name: "loopback with secret",
			api: Api{
				Enabled: true,
				Listen:  "127.0.0.1:9527",
				Secret:  "operator-token-123456",
			},
		},
		{
			name: "loopback anonymous requires explicit flag",
			api: Api{
				Enabled: true,
				Listen:  "127.0.0.1:9527",
			},
			wantErr: "allow_anonymous_loopback",
		},
		{
			name: "loopback anonymous allowed",
			api: Api{
				Enabled:                true,
				Listen:                 "127.0.0.1:9527",
				AllowAnonymousLoopback: true,
			},
		},
		{
			name: "non-loopback requires secret",
			api: Api{
				Enabled:                true,
				Listen:                 "192.0.2.10:9527",
				AllowAnonymousLoopback: true,
			},
			wantErr: "non-loopback listener requires secret",
		},
		{
			name: "wildcard requires secret",
			api: Api{
				Enabled: true,
				Listen:  "0.0.0.0:9527",
			},
			wantErr: "allow_anonymous_loopback",
		},
		{
			name: "non-loopback with secret",
			api: Api{
				Enabled: true,
				Listen:  "192.0.2.10:9527",
				Secret:  "operator-token-123456",
			},
		},
		{
			name: "hostname rejected",
			api: Api{
				Enabled: true,
				Listen:  "localhost:9527",
				Secret:  "operator-token-123456",
			},
			wantErr: "numeric IP",
		},
		{
			name: "bad secret character",
			api: Api{
				Enabled: true,
				Listen:  "127.0.0.1:9527",
				Secret:  "bad secret",
			},
			wantErr: "visible ASCII",
		},
		{
			name: "wildcard origin rejected",
			api: Api{
				Enabled: true,
				Listen:  "127.0.0.1:9527",
				Secret:  "operator-token-123456",
				AllowOrigins: []string{
					"https://*.example",
				},
			},
			wantErr: "wildcard origins",
		},
		{
			name: "origin with path rejected",
			api: Api{
				Enabled: true,
				Listen:  "127.0.0.1:9527",
				Secret:  "operator-token-123456",
				AllowOrigins: []string{
					"https://panel.example/ui",
				},
			},
			wantErr: "must not have a path",
		},
		{
			name: "allowed host with path rejected",
			api: Api{
				Enabled: true,
				Listen:  "127.0.0.1:9527",
				Secret:  "operator-token-123456",
				AllowedHosts: []string{
					"panel.example/path",
				},
			},
			wantErr: "scheme, path",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.api.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate() error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestApiWarnings(t *testing.T) {
	api := Api{
		Enabled: true,
		Listen:  "192.0.2.10:9527",
		Secret:  "short-token",
	}
	warnings := strings.Join(api.Warnings(), "\n")
	if !strings.Contains(warnings, "non-loopback") {
		t.Fatalf("warnings missing non-loopback advisory: %q", warnings)
	}
	if !strings.Contains(warnings, "shorter than 16 bytes") {
		t.Fatalf("warnings missing short secret advisory: %q", warnings)
	}
}

func TestConfigRevision(t *testing.T) {
	conf1 := parseAPIConfig(t, "")
	conf2 := parseAPIConfig(t, "")
	if conf1.Revision() == "" {
		t.Fatal("revision must not be empty")
	}
	if conf1.Revision() != conf2.Revision() {
		t.Fatal("identical configs should have the same revision")
	}

	conf3 := parseAPIConfig(t, `
api {
    enabled: true
    listen: '127.0.0.1:19527'
    secret: 'operator-token-123456'
}
`)
	if conf1.Revision() == conf3.Revision() {
		t.Fatal("different configs should have different revisions")
	}
}

func TestConfigMarshalRoundTripKeepsApiEnabled(t *testing.T) {
	conf := parseAPIConfig(t, `
api {
    enabled: true
    listen: '127.0.0.1:19527'
    secret: 'operator-token-123456'
    allow_origins: 'http://localhost:3000'
}
`)
	b, err := conf.Marshal(2)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "api {") {
		t.Fatalf("enabled api section is missing from marshalled config:\n%s", string(b))
	}
	sections, err := config_parser.Parse(string(b))
	if err != nil {
		t.Fatal(err)
	}
	roundTrip, err := New(sections)
	if err != nil {
		t.Fatal(err)
	}
	if !roundTrip.Api.Enabled {
		t.Fatal("api must stay enabled after marshal round-trip")
	}
	if roundTrip.Api.Listen != "127.0.0.1:19527" || roundTrip.Api.Secret != "operator-token-123456" {
		t.Fatalf("api round-trip = %#v", roundTrip.Api)
	}
	if len(roundTrip.Api.AllowOrigins) != 1 || roundTrip.Api.AllowOrigins[0] != "http://localhost:3000" {
		t.Fatalf("api.allow_origins round-trip = %#v", roundTrip.Api.AllowOrigins)
	}
}

func TestConfigMarshalRoundTripKeepsApiDisabled(t *testing.T) {
	conf := parseAPIConfig(t, "")
	b, err := conf.Marshal(2)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "api {") {
		t.Fatalf("disabled api section should be omitted from marshalled config:\n%s", string(b))
	}
	sections, err := config_parser.Parse(string(b))
	if err != nil {
		t.Fatal(err)
	}
	roundTrip, err := New(sections)
	if err != nil {
		t.Fatal(err)
	}
	if roundTrip.Api.Enabled {
		t.Fatal("api must stay disabled after marshal round-trip")
	}
}

func TestApiUIValidation(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<!doctype html>"), 0o644); err != nil {
		t.Fatal(err)
	}
	base := Api{Enabled: true, Listen: "127.0.0.1:9527", AllowAnonymousLoopback: true, UI: dir}
	if err := base.Validate(); err != nil {
		t.Fatalf("valid ui dir rejected: %v", err)
	}

	if err := func() error { invalid := base; invalid.UI = "dist"; return invalid.Validate() }(); err == nil {
		t.Fatal("a relative ui path must be rejected")
	}
	// A directory that is missing or has no index.html is a startup warning,
	// never a configuration error: the proxy must keep running without a UI.
	for name, ui := range map[string]string{
		"missing dir":    filepath.Join(dir, "missing"),
		"file not a dir": filepath.Join(dir, "index.html"),
		"empty dir":      t.TempDir(),
	} {
		tolerated := base
		tolerated.UI = ui
		if err := tolerated.Validate(); err != nil {
			t.Fatalf("%s (%q) must be tolerated: %v", name, ui, err)
		}
	}

	disabled := Api{UI: "/definitely/not/here"}
	if err := disabled.Validate(); err != nil {
		t.Fatalf("a disabled listener must not validate ui: %v", err)
	}
}

func TestApiSectionDecodesUI(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<!doctype html>"), 0o644); err != nil {
		t.Fatal(err)
	}
	conf := parseAPIConfig(t, `
api {
    enabled: true
    listen: '127.0.0.1:19527'
    allow_anonymous_loopback: true
    ui: '`+dir+`'
}
`)
	if conf.Api.UI != dir {
		t.Fatalf("api.ui = %q, want %q", conf.Api.UI, dir)
	}
}
