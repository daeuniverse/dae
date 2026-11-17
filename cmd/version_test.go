/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"runtime"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/config"
)

func TestResolveBuildMetadata(t *testing.T) {
	info := &debug.BuildInfo{
		Main: debug.Module{Version: "(devel)"},
		Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "0123456789abcdef0123456789abcdef01234567"},
			{Key: "vcs.time", Value: "2026-10-30T12:00:00Z"},
		},
	}

	released := resolveBuildMetadata("0.9.0-rc.9", info)
	if released.Version != "0.9.0-rc.9" {
		t.Fatalf("version = %q, want the linker value", released.Version)
	}
	if released.Revision != "0123456789abcdef0123456789abcdef01234567" {
		t.Fatalf("revision = %q", released.Revision)
	}
	if released.Target != runtime.GOOS+"/"+runtime.GOARCH {
		t.Fatalf("target = %q", released.Target)
	}
	if released.BuildTime != "2026-10-30T12:00:00Z" {
		t.Fatalf("build time = %q", released.BuildTime)
	}

	fromGit := resolveBuildMetadata("unknown", info)
	if fromGit.Version != "git-0123456789ab" {
		t.Fatalf("source build version = %q", fromGit.Version)
	}

	fromModule := resolveBuildMetadata("", &debug.BuildInfo{Main: debug.Module{Version: "v0.1.2"}})
	if fromModule.Version != "v0.1.2" {
		t.Fatalf("module build version = %q", fromModule.Version)
	}

	bare := resolveBuildMetadata("", nil)
	if bare.Version != "unknown" {
		t.Fatalf("bare build version = %q", bare.Version)
	}

	dirty := resolveBuildMetadata("unknown", &debug.BuildInfo{
		Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "0123456789abcdef0123456789abcdef01234567"},
			{Key: "vcs.modified", Value: "true"},
		},
	})
	if dirty.Version != "git-0123456789ab-dirty" {
		t.Fatalf("dirty build version = %q", dirty.Version)
	}
}

func TestBuildMetadataMatchesConfigVersion(t *testing.T) {
	if config.Version != build.Version {
		t.Fatalf("dae -v reports %q but the API would report %q", build.Version, config.Version)
	}
}

func TestNativeAPIConfigMatchesCommandLine(t *testing.T) {
	conf, err := emptyConfig()
	if err != nil {
		t.Fatal(err)
	}
	conf.Api.Enabled = true
	conf.Api.Secret = "operator-token-123456"
	conf.Api.UI = "/tmp/ignored"

	cfg := nativeAPIConfig(conf)
	if cfg.EngineVersion != build.Version {
		t.Fatalf("api engine.version = %q, want %q", cfg.EngineVersion, build.Version)
	}
	if cfg.EngineVersion != config.Version {
		t.Fatalf("api engine.version = %q, want config.Version %q", cfg.EngineVersion, config.Version)
	}
	if cfg.BuildRevision != build.Revision || cfg.BuildTarget == "" || cfg.BuildBuiltAt != build.BuildTime {
		t.Fatalf("build metadata not wired: %#v", cfg)
	}
	// `dae -v` prints the same version on its first line.
	if first := strings.SplitN(rootCmd.Version, "\n", 2)[0]; first != cfg.EngineVersion {
		t.Fatalf("dae -v prints %q, the API reports %q", first, cfg.EngineVersion)
	}
	if cfg.Listen != conf.Api.Listen || cfg.Secret != conf.Api.Secret || cfg.UI != conf.Api.UI {
		t.Fatalf("listener settings not wired: %#v", cfg)
	}
}
