/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/component/nativeapi"
	"github.com/stretchr/testify/require"
)

func groupPatchJSON(value int) json.RawMessage {
	raw, _ := json.Marshal(value)
	return raw
}

func TestApplyGroupConfigPatch(t *testing.T) {
	document := nativeapi.GroupConfigDocument{
		Config: nativeapi.GroupConfig{
			CheckInterval: intPointer(15),
			Tolerance:     intPointer(50),
		},
	}
	updated, changed, err := applyGroupConfigPatch(document, []nativeapi.GroupConfigPatchOperation{
		{Op: "test", Path: "/config/check_interval", Value: groupPatchJSON(15)},
		{Op: "copy", From: "/config/check_interval", Path: "/config/tolerance"},
		{Op: "move", From: "/config/tolerance", Path: "/config/check_interval"},
	})
	require.NoError(t, err)
	require.True(t, changed)
	require.Equal(t, 15, *updated.Config.CheckInterval)
	require.Nil(t, updated.Config.Tolerance)
}

func TestApplyGroupConfigPatchRejectsUnsupportedAndInvalidValues(t *testing.T) {
	document := nativeapi.GroupConfigDocument{}
	_, _, err := applyGroupConfigPatch(document, []nativeapi.GroupConfigPatchOperation{
		{Op: "replace", Path: "/config/interrupt_connections", Value: groupPatchJSON(1)},
	})
	require.Equal(t, "unsupported_value", flowAPIError(t, err).Code)

	_, _, err = applyGroupConfigPatch(document, []nativeapi.GroupConfigPatchOperation{
		{Op: "replace", Path: "/config/check_interval", Value: groupPatchJSON(0)},
	})
	require.Equal(t, "unsupported_value", flowAPIError(t, err).Code)

	document.Config.Tolerance = intPointer(10_000_000_000)
	_, _, err = applyGroupConfigPatch(document, []nativeapi.GroupConfigPatchOperation{
		{Op: "copy", From: "/config/tolerance", Path: "/config/check_interval"},
	})
	require.Equal(t, "unsupported_value", flowAPIError(t, err).Code)
}

func TestWriteGroupConfigOptionsPreservesCommentsAndAddsMissingOptions(t *testing.T) {
	source := []byte("group {\n" +
		"    proxy {\n" +
		"        policy: min\n" +
		"        check_interval: 30s # interval\n" +
		"        check_tolerance: 50ms # tolerance\n" +
		"    }\n" +
		"}\n")
	updated, err := writeGroupConfigOptions(source, "proxy", nativeapi.GroupConfig{
		CheckInterval: intPointer(60),
	}, groupConfigWrite{checkInterval: true, tolerance: true})
	require.NoError(t, err)
	require.Equal(t, "group {\n"+
		"    proxy {\n"+
		"        policy: min\n"+
		"        check_interval: 60s # interval\n"+
		"        # tolerance\n"+
		"    }\n"+
		"}\n", string(updated))

	added, err := writeGroupConfigOptions([]byte("group {\n    proxy {\n        policy: min\n    }\n}\n"), "proxy", nativeapi.GroupConfig{
		CheckInterval: intPointer(20),
		Tolerance:     intPointer(40),
	}, groupConfigWrite{checkInterval: true, tolerance: true})
	require.NoError(t, err)
	require.True(t, strings.Contains(string(added), "        check_interval: 20s\n"))
	require.True(t, strings.Contains(string(added), "        check_tolerance: 40ms\n"))
}

func TestConfigEditorPatchGroupConfigCommitsAndReplays(t *testing.T) {
	main, _ := newManagedTree(t)
	groupPath := filepath.Join(filepath.Dir(main), "config.d", groupSourceName)
	groupSource := "group {\n    proxy {\n        policy: random\n        check_interval: 30s\n    }\n}\n"
	require.NoError(t, os.WriteFile(groupPath, []byte(groupSource), 0o600))

	operations := &fakeConfigOperations{}
	editor := newFlowEditor(t, main, true, operations)
	sources, err := editor.loadSources()
	require.NoError(t, err)
	revision := editor.sourceRevision(sources)

	request := nativeapi.GroupConfigPatchRequest{
		IfMatch:        `"` + revision + `"`,
		IdempotencyKey: "group-patch-1",
		Operations: []nativeapi.GroupConfigPatchOperation{{
			Op:    "replace",
			Path:  "/config/check_interval",
			Value: groupPatchJSON(60),
		}},
	}
	current := nativeapi.GroupConfigDocument{Config: nativeapi.GroupConfig{CheckInterval: intPointer(30)}}
	_, _, accepted, err := editor.PatchGroupConfig(context.Background(), "proxy", current, revision, request, nil)
	require.NoError(t, err)
	require.NotNil(t, accepted)
	require.Equal(t, nativeapi.OperationKindGroupUpdate, accepted.Kind)
	require.Equal(t, 1, operations.calls)

	updated, err := os.ReadFile(groupPath)
	require.NoError(t, err)
	require.Contains(t, string(updated), "check_interval: 60s")

	_, _, replay, err := editor.PatchGroupConfig(context.Background(), "proxy", current, revision, request, nil)
	require.NoError(t, err)
	require.Equal(t, accepted.OperationID, replay.OperationID)
	require.Equal(t, 1, operations.calls)

	conflict := request
	conflict.Operations = []nativeapi.GroupConfigPatchOperation{{
		Op: "replace", Path: "/config/check_interval", Value: groupPatchJSON(90),
	}}
	_, _, _, err = editor.PatchGroupConfig(context.Background(), "proxy", current, revision, conflict, nil)
	require.Equal(t, "idempotency_conflict", flowAPIError(t, err).Code)

	stale := request
	stale.IdempotencyKey = "group-patch-2"
	_, _, _, err = editor.PatchGroupConfig(context.Background(), "proxy", current, revision, stale, nil)
	require.Equal(t, "stale_revision", flowAPIError(t, err).Code)
	require.Equal(t, 1, operations.calls)
}

func intPointer(value int) *int {
	return &value
}
