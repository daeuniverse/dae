/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"runtime"
	"runtime/debug"
	"strings"
)

// buildMetadata is the single source of truth for the engine identity: `dae -v`
// prints it and the native API reports it, so a frontend never disagrees with
// the command line.
type buildMetadata struct {
	Version   string
	Revision  string
	Target    string
	BuildTime string
}

func resolveBuildMetadata(ldflagVersion string, info *debug.BuildInfo) buildMetadata {
	meta := buildMetadata{
		Version:  normalizeVersion(ldflagVersion),
		Target:   runtime.GOOS + "/" + runtime.GOARCH,
		Revision: buildSetting(info, "vcs.revision"),
	}
	if info != nil {
		meta.BuildTime = buildSetting(info, "vcs.time")
	}
	if meta.Version == "" {
		meta.Version = versionFromBuildInfo(info, meta.Revision)
	}
	if meta.Version == "" {
		meta.Version = "unknown"
	}
	return meta
}

func normalizeVersion(value string) string {
	value = strings.TrimSpace(value)
	if value == "unknown" {
		return ""
	}
	return value
}

// versionFromBuildInfo covers builds that skip the linker flag, such as
// `go build` or `go install`: a module version wins over the VCS revision.
func versionFromBuildInfo(info *debug.BuildInfo, revision string) string {
	if info != nil && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	if revision == "" {
		return ""
	}
	short := revision
	if len(short) > 12 {
		short = short[:12]
	}
	version := "git-" + short
	if info != nil && buildSetting(info, "vcs.modified") == "true" {
		version += "-dirty"
	}
	return version
}

func buildSetting(info *debug.BuildInfo, key string) string {
	if info == nil {
		return ""
	}
	for _, setting := range info.Settings {
		if setting.Key == key {
			return setting.Value
		}
	}
	return ""
}

var build = func() buildMetadata {
	info, _ := debug.ReadBuildInfo()
	return resolveBuildMetadata(Version, info)
}()
