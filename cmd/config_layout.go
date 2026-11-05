/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"github.com/daeuniverse/dae/config"
)

// managedConfigModules are the files a managed config.d layout must provide.
var managedConfigModules = []string{"global.dae", "subscription.dae", "node.dae", "group.dae", "routing.dae", "dns.dae"}

var (
	includeBlockPattern   = regexp.MustCompile(`(?s)\binclude\s*\{[^}]*\}`)
	includeKeywordPattern = regexp.MustCompile(`(?m)^\s*include\s*\{`)
	commentPattern        = regexp.MustCompile(`(?m)#.*$`)
)

func sectionBlockPattern(section string) *regexp.Regexp {
	return regexp.MustCompile(`(?m)^[ \t]*` + regexp.QuoteMeta(section) + `[ \t]*\{[ \t]*(?:#[^\r\n]*)?\r?$`)
}

// detectManagedLayout reports whether the tree rooted at mainPath follows the
// managed layout, and the reason when it does not. sources are the files the
// merger reached.
func detectManagedLayout(mainPath string, sources []string) (bool, string) {
	const unmanaged = "layout_unmanaged"
	mainPath = filepath.Clean(mainPath)
	if filepath.Base(mainPath) != "config.dae" {
		return false, unmanaged
	}
	raw, err := os.ReadFile(mainPath)
	if err != nil {
		return false, unmanaged
	}
	body := string(raw)
	blocks := includeBlockPattern.FindAllString(body, -1)
	if len(blocks) != 1 || !strings.Contains(blocks[0], "config.d/*.dae") || !strings.Contains(blocks[0], "api.dae") {
		return false, unmanaged
	}
	rest := commentPattern.ReplaceAllString(includeBlockPattern.ReplaceAllString(body, ""), "")
	if strings.TrimSpace(rest) != "" {
		return false, unmanaged
	}

	root := filepath.Dir(mainPath)
	configDir := filepath.Join(root, "config.d")
	apiPath := filepath.Join(root, "api.dae")
	if _, err := os.Stat(apiPath); err != nil {
		return false, unmanaged
	}
	seen := map[string]bool{}
	for _, s := range sources {
		abs, err := filepath.Abs(s)
		if err != nil {
			return false, unmanaged
		}
		if abs == mainPath {
			continue
		}
		if abs == apiPath {
			seen[abs] = true
			continue
		}
		if filepath.Dir(abs) != configDir || filepath.Ext(abs) != ".dae" {
			return false, unmanaged
		}
		content, err := os.ReadFile(abs)
		if err != nil || includeKeywordPattern.Match(content) {
			return false, unmanaged
		}
		seen[abs] = true
	}
	if !seen[apiPath] {
		return false, unmanaged
	}
	for _, m := range managedConfigModules {
		if !seen[filepath.Join(configDir, m)] {
			return false, unmanaged
		}
	}
	// One section name must come from exactly one file, so a write to one
	// source cannot silently change the meaning of another.
	_, origins, err := config.NewMerger(mainPath).MergeWithOrigins()
	if err != nil {
		return false, unmanaged
	}
	for _, occurrences := range origins {
		files := map[string]bool{}
		for _, o := range occurrences {
			files[o.File] = true
		}
		if len(files) > 1 {
			return false, unmanaged
		}
	}
	// Writes create .bak and temp files in config.d, so the directory must be writable.
	if syscall.Access(configDir, 2) != nil {
		return false, unmanaged
	}
	return true, ""
}
