/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"testing"

	"github.com/daeuniverse/dae/component/nativeapi"
	"github.com/stretchr/testify/require"
)

// tolerance belongs to the latency-testing policy only. The contract rejects a
// changed non-null tolerance when the patch leaves the policy non-URLTest.
func TestApplyGroupConfigPatchRejectsToleranceOnNonURLTestPolicy(t *testing.T) {
	document := nativeapi.GroupConfigDocument{
		Policy: nativeapi.GroupPolicy{Kind: "selector", Native: "select(0)"},
	}
	_, _, err := applyGroupConfigPatch(document, []nativeapi.GroupConfigPatchOperation{{
		Op: "add", Path: "/config/tolerance", Value: groupPatchJSON(60),
	}})
	require.Equal(t, "unsupported_value", flowAPIError(t, err).Code)

	// Removing an inherited tolerance is allowed: the resulting value is null.
	document.Config.Tolerance = intPointer(60)
	_, changed, err := applyGroupConfigPatch(document, []nativeapi.GroupConfigPatchOperation{{
		Op: "remove", Path: "/config/tolerance",
	}})
	require.NoError(t, err)
	require.True(t, changed)
}

// Inserting a missing option must not disturb the block: the closing brace keeps
// its indentation and no whitespace-only line appears.
func TestWriteGroupConfigOptionsInsertsWithoutBreakingIndentation(t *testing.T) {
	source := []byte("group {\n" +
		"    sel {\n" +
		"        policy: select\n" +
		"        check_interval: 1500ms\n" +
		"    }\n" +
		"}\n")
	// Only tolerance changed: check_interval must be left exactly as written, so
	// the whole-second projection cannot turn 1500ms into 1s.
	out, err := writeGroupConfigOptions(source, "sel", nativeapi.GroupConfig{
		CheckInterval: intPointer(1),
		Tolerance:     intPointer(60),
	}, groupConfigWrite{tolerance: true})
	require.NoError(t, err)
	require.Equal(t, "group {\n"+
		"    sel {\n"+
		"        policy: select\n"+
		"        check_interval: 1500ms\n"+
		"        check_tolerance: 60ms\n"+
		"    }\n"+
		"}\n", string(out))
}

func TestGroupBlockPatternMatchesCommentAndCRLF(t *testing.T) {
	require.True(t, groupBlockPattern.MatchString("group { # upstream groups\n"))
	require.True(t, groupBlockPattern.MatchString("group {\r\n"))
	require.True(t, groupBlockPattern.MatchString("  group {\n"))
	require.False(t, groupBlockPattern.MatchString("group min {\n"))
}

// The layout check allows the group section in any config.d file, so the patch
// must follow the declaring file instead of assuming group.dae.
func TestGroupSourceFollowsDeclaringFile(t *testing.T) {
	editor := &configEditor{baseDir: "/tmp/tree"}
	extra := configSourceFile{
		kind: "include",
		abs:  "/tmp/tree/config.d/extra.dae",
		raw:  []byte("group {\n    sel {\n        policy: select\n    }\n}\n"),
	}
	groupFile := configSourceFile{
		kind: "include",
		abs:  "/tmp/tree/config.d/group.dae",
		raw:  []byte("group {\n    other {\n        policy: min\n    }\n}\n"),
	}
	target, err := editor.groupSource([]configSourceFile{groupFile, extra}, "sel")
	require.NoError(t, err)
	require.Equal(t, extra.abs, target.abs)
}
