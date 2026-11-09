/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/daeuniverse/dae/component/nativeapi"
)

const groupSourceName = "group.dae"

// groupBlockPattern matches the opening of the group section.
var groupBlockPattern = sectionBlockPattern("group")

func (e *configEditor) GroupConfigPatchAvailable() bool {
	return e != nil && e.ConfigCapabilities().Writable
}

func (e *configEditor) PatchGroupConfig(
	ctx context.Context,
	groupName string,
	current nativeapi.GroupConfigDocument,
	activeRevision string,
	request nativeapi.GroupConfigPatchRequest,
	resolve func() (any, error),
) (nativeapi.GroupConfigDocument, string, *nativeapi.OperationAccepted, error) {
	if err := ctx.Err(); err != nil {
		return nativeapi.GroupConfigDocument{}, "", nil, err
	}
	if e == nil {
		return nativeapi.GroupConfigDocument{}, "", nil, nativeapi.NewAPIError(404, "capability_not_supported", "group configuration patch is not supported by this engine")
	}
	fingerprintBytes, err := json.Marshal(request.Operations)
	if err != nil {
		return nativeapi.GroupConfigDocument{}, "", nil, err
	}
	fingerprint := rawSHA256([]byte("group_update\x00" + groupName + "\x00" + request.IfMatch + "\x00" + string(fingerprintBytes)))

	e.mu.Lock()
	defer e.mu.Unlock()

	all, err := e.loadSources()
	if err != nil {
		return nativeapi.GroupConfigDocument{}, "", nil, err
	}
	if ok, _ := e.layoutOK(all); !ok {
		return nativeapi.GroupConfigDocument{}, "", nil, nativeapi.NewAPIError(404, "capability_not_supported", "group configuration patch is not supported by this engine")
	}
	target, err := e.groupSource(all, groupName)
	if err != nil || !e.sourceWritable(target) {
		return nativeapi.GroupConfigDocument{}, "", nil, nativeapi.NewAPIError(404, "capability_not_supported", "managed group configuration source is unavailable")
	}
	if accepted, replayed, err := e.replaySourceUpdate(nativeapi.OperationKindGroupUpdate, sourceUpdateScope(target.abs, fingerprint), request.IdempotencyKey); err != nil || replayed {
		return nativeapi.GroupConfigDocument{}, "", &accepted, err
	}

	revision, err := parseGroupIfMatch(request.IfMatch)
	if err != nil {
		return nativeapi.GroupConfigDocument{}, "", nil, err
	}
	currentRevision := e.sourceRevision(all)
	if revision != activeRevision || currentRevision != activeRevision {
		return nativeapi.GroupConfigDocument{}, "", nil, &nativeapi.APIError{
			Status: 412, Code: "stale_revision",
			Message: "the resource changed; fetch it again before retrying",
		}
	}
	updated, changed, err := applyGroupConfigPatch(current, request.Operations)
	if err != nil {
		return nativeapi.GroupConfigDocument{}, "", nil, err
	}
	if !changed {
		return current, currentRevision, nil, nil
	}
	content, err := writeGroupConfigOptions(target.raw, groupName, updated.Config, groupConfigDiff(current.Config, updated.Config))
	if err != nil {
		return nativeapi.GroupConfigDocument{}, "", nil, err
	}
	accepted, err := e.commitSourceUpdate(
		ctx, target, content, nativeapi.OperationKindGroupUpdate,
		request.IdempotencyKey, fingerprint, resolve,
	)
	if err != nil {
		return nativeapi.GroupConfigDocument{}, "", nil, err
	}
	return nativeapi.GroupConfigDocument{}, "", &accepted, nil
}

// groupSource returns the managed source that declares the group block. The
// layout check allows the group section to live in any config.d file, so a
// fixed group.dae target advertised a capability the write could not honour.
func (e *configEditor) groupSource(all []configSourceFile, groupName string) (configSourceFile, error) {
	for _, candidate := range all {
		if !e.sourceWritable(candidate) {
			continue
		}
		if _, _, _, err := findGroupBlock(string(candidate.raw), groupName); err == nil {
			return candidate, nil
		}
	}
	return findSourceByPath(all, filepath.Join(e.baseDir, "config.d", groupSourceName))
}

// groupConfigWrite names the options a patch actually changed. Writing an
// unchanged option projects it back through the contract's unit: check_interval
// is whole seconds, so a 1500ms value would become 1s even when the patch only
// touched tolerance.
type groupConfigWrite struct {
	checkInterval bool
	tolerance     bool
}

func groupConfigDiff(before, after nativeapi.GroupConfig) groupConfigWrite {
	return groupConfigWrite{
		checkInterval: !reflect.DeepEqual(before.CheckInterval, after.CheckInterval),
		tolerance:     !reflect.DeepEqual(before.Tolerance, after.Tolerance),
	}
}

func findSourceByPath(all []configSourceFile, target string) (configSourceFile, error) {
	target = filepath.Clean(target)
	for _, source := range all {
		if filepath.Clean(source.abs) == target {
			return source, nil
		}
	}
	return configSourceFile{}, errors.New("managed group source not found")
}

func parseGroupIfMatch(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nativeapi.NewAPIError(428, "precondition_required", "If-Match is required")
	}
	if strings.HasPrefix(value, "W/") || strings.Contains(value, ",") || value == "*" {
		return "", nativeapi.NewAPIError(400, "invalid_request", "If-Match must contain one strong configuration revision")
	}
	revision, err := strconv.Unquote(value)
	if err != nil || revision == "" {
		return "", nativeapi.NewAPIError(400, "invalid_request", "If-Match must be a quoted configuration revision")
	}
	return revision, nil
}

func applyGroupConfigPatch(
	document nativeapi.GroupConfigDocument,
	operations []nativeapi.GroupConfigPatchOperation,
) (nativeapi.GroupConfigDocument, bool, error) {
	updated := document
	for _, operation := range operations {
		if !isGroupPatchPath(operation.Path) {
			return nativeapi.GroupConfigDocument{}, false, &nativeapi.APIError{
				Status: 422, Code: "unsupported_value",
				Message: "the requested group configuration path is not mutable by this engine",
			}
		}
		switch operation.Op {
		case "add", "replace":
			value, err := parseGroupPatchInteger(operation.Value, operation.Path)
			if err != nil {
				return nativeapi.GroupConfigDocument{}, false, err
			}
			setGroupPatchValue(&updated.Config, operation.Path, value)
		case "remove":
			setGroupPatchValue(&updated.Config, operation.Path, nil)
		case "test":
			value, err := parseGroupPatchInteger(operation.Value, operation.Path)
			if err != nil {
				return nativeapi.GroupConfigDocument{}, false, err
			}
			if !reflect.DeepEqual(groupPatchValue(updated.Config, operation.Path), value) {
				return nativeapi.GroupConfigDocument{}, false, &nativeapi.APIError{
					Status: 409, Code: "state_conflict",
					Message: "JSON Patch test operation failed",
				}
			}
		case "copy", "move":
			if !isGroupPatchPath(operation.From) {
				return nativeapi.GroupConfigDocument{}, false, &nativeapi.APIError{
					Status: 422, Code: "unsupported_value",
					Message: "the requested group configuration path is not mutable by this engine",
				}
			}
			sourceValue := groupPatchValue(updated.Config, operation.From)
			var value *int
			if sourceValue != nil {
				raw, err := json.Marshal(*sourceValue)
				if err != nil {
					return nativeapi.GroupConfigDocument{}, false, err
				}
				value, err = parseGroupPatchInteger(raw, operation.Path)
				if err != nil {
					return nativeapi.GroupConfigDocument{}, false, err
				}
			}
			setGroupPatchValue(&updated.Config, operation.Path, value)
			if operation.Op == "move" && operation.From != operation.Path {
				setGroupPatchValue(&updated.Config, operation.From, nil)
			}
		default:
			return nativeapi.GroupConfigDocument{}, false, &nativeapi.APIError{
				Status: 400, Code: "invalid_request",
				Message: "unsupported JSON Patch operation",
			}
		}
	}
	// The contract judges tolerance against the policy the patch results in:
	// only the latency-testing policy has one. A non-null tolerance that this
	// patch changed on any other policy is unsupported. An empty Kind means the
	// caller did not project a policy (tests do this), so it is not judged.
	if updated.Config.Tolerance != nil &&
		!reflect.DeepEqual(updated.Config.Tolerance, document.Config.Tolerance) &&
		document.Policy.Kind != "" && document.Policy.Kind != "urltest" {
		return nativeapi.GroupConfigDocument{}, false, &nativeapi.APIError{
			Status: 422, Code: "unsupported_value",
			Message: "tolerance applies only to the urltest policy",
		}
	}
	return updated, !reflect.DeepEqual(updated.Config, document.Config), nil
}

func isGroupPatchPath(path string) bool {
	return path == "/config/check_interval" || path == "/config/tolerance"
}

func parseGroupPatchInteger(raw json.RawMessage, path string) (*int, error) {
	if len(raw) == 0 {
		return nil, &nativeapi.APIError{Status: 400, Code: "invalid_request", Message: "JSON Patch operation requires value"}
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, nil
	}
	var value int64
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, &nativeapi.APIError{Status: 422, Code: "unsupported_value", Message: "group configuration value must be an integer or null"}
	}
	if path == "/config/check_interval" {
		if value < 1 || value > math.MaxInt64/int64(time.Second) {
			return nil, &nativeapi.APIError{Status: 422, Code: "unsupported_value", Message: "check_interval must be a positive number of seconds"}
		}
	} else if value < 0 || value > math.MaxInt64/int64(time.Millisecond) {
		return nil, &nativeapi.APIError{Status: 422, Code: "unsupported_value", Message: "tolerance must be a non-negative number of milliseconds"}
	}
	if value > int64(int(^uint(0)>>1)) {
		return nil, &nativeapi.APIError{Status: 422, Code: "unsupported_value", Message: "group configuration value is too large"}
	}
	converted := int(value)
	return &converted, nil
}

func groupPatchValue(config nativeapi.GroupConfig, path string) *int {
	if path == "/config/check_interval" {
		return config.CheckInterval
	}
	return config.Tolerance
}

func setGroupPatchValue(config *nativeapi.GroupConfig, path string, value *int) {
	if path == "/config/check_interval" {
		config.CheckInterval = value
	} else {
		config.Tolerance = value
	}
}

func writeGroupConfigOptions(raw []byte, groupName string, groupConfig nativeapi.GroupConfig, write groupConfigWrite) ([]byte, error) {
	text := string(raw)
	for _, option := range []struct {
		key   string
		value *int
		unit  string
		apply bool
	}{
		{key: "check_interval", value: groupConfig.CheckInterval, unit: "s", apply: write.checkInterval},
		{key: "check_tolerance", value: groupConfig.Tolerance, unit: "ms", apply: write.tolerance},
	} {
		if !option.apply {
			continue
		}
		var rendered *string
		if option.value != nil {
			value := strconv.Itoa(*option.value) + option.unit
			rendered = &value
		}
		var err error
		text, err = setGroupConfigLine(text, groupName, option.key, rendered)
		if err != nil {
			return nil, err
		}
	}
	return []byte(text), nil
}

func setGroupConfigLine(text, groupName, key string, value *string) (string, error) {
	open, close, childIndent, err := findGroupBlock(text, groupName)
	if err != nil {
		return "", err
	}
	type edit struct {
		start int
		end   int
		text  string
	}
	var edits []edit
	offset := open + 1
	body := text[open+1 : close]
	for _, line := range strings.SplitAfter(body, "\n") {
		if name, ok := nodeLineKey(line); ok && name == key {
			replacement := ""
			if value != nil {
				replacement = renderGroupOptionLine(line, key, *value)
			} else if comment := inlineComment(line); comment != "" {
				indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
				replacement = indent + comment + "\n"
			}
			edits = append(edits, edit{start: offset, end: offset + len(line), text: replacement})
		}
		offset += len(line)
	}
	if len(edits) == 0 && value != nil {
		indent := childIndent + "    "
		newline := "\n"
		if strings.Contains(body, "\r\n") {
			newline = "\r\n"
		}
		insertion := indent + key + ": " + *value + newline
		// Insert after the last non-blank line instead of at the closing brace:
		// the brace's own leading indentation is part of text[:close], so
		// appending there left a whitespace-only line and shifted the brace.
		insertAt := -1
		offset := open + 1
		for _, line := range strings.SplitAfter(body, "\n") {
			if strings.TrimSpace(line) != "" {
				insertAt = offset + len(line)
			}
			offset += len(line)
		}
		if insertAt < 0 {
			return text[:open+1] + newline + insertion + text[open+1:], nil
		}
		if text[insertAt-1] != '\n' {
			return text[:insertAt] + newline + insertion + text[insertAt:], nil
		}
		return text[:insertAt] + insertion + text[insertAt:], nil
	}
	for i := len(edits) - 1; i >= 0; i-- {
		item := edits[i]
		text = text[:item.start] + item.text + text[item.end:]
	}
	return text, nil
}

func renderGroupOptionLine(line, key, value string) string {
	newline := ""
	content := line
	if strings.HasSuffix(content, "\n") {
		newline = "\n"
		content = strings.TrimSuffix(content, "\n")
	}
	if strings.HasSuffix(content, "\r") {
		newline = "\r\n"
		content = strings.TrimSuffix(content, "\r")
	}
	colon := strings.IndexByte(content, ':')
	comment := inlineComment(content)
	commentSuffix := ""
	if comment != "" {
		commentIndex := strings.Index(content, comment)
		commentSuffix = " " + comment
		if commentIndex > colon+1 {
			preceding := content[colon+1 : commentIndex]
			if len(strings.TrimSpace(preceding)) == 0 {
				commentSuffix = preceding + comment
			}
		}
	}
	indent := content[:len(content)-len(strings.TrimLeft(content, " \t"))]
	return indent + key + ": " + value + commentSuffix + newline
}

func inlineComment(line string) string {
	var quote byte
	for index := 0; index < len(line); index++ {
		switch {
		case quote != 0:
			if line[index] == quote {
				quote = 0
			}
		case line[index] == '\'' || line[index] == '"':
			quote = line[index]
		case line[index] == '#':
			return strings.TrimRight(line[index:], "\r\n")
		}
	}
	return ""
}

func findGroupBlock(text, groupName string) (open, close int, childIndent string, err error) {
	outer := groupBlockPattern.FindStringIndex(text)
	if outer == nil {
		return 0, 0, "", &nativeapi.APIError{Status: 404, Code: "resource_not_found", Message: "group configuration block not found"}
	}
	outerOpen := strings.IndexByte(text[outer[0]:outer[1]], '{') + outer[0]
	outerClose := matchingBrace(text, outerOpen)
	if outerClose < 0 {
		return 0, 0, "", fmt.Errorf("malformed group configuration block")
	}
	offset := outerOpen + 1
	for _, line := range strings.SplitAfter(text[outerOpen+1:outerClose], "\n") {
		trimmed := strings.TrimSpace(strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r"))
		if comment := inlineComment(trimmed); comment != "" {
			trimmed = strings.TrimSpace(strings.TrimSuffix(trimmed, comment))
		}
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") && strings.HasSuffix(trimmed, "{") {
			name := strings.TrimSpace(strings.TrimSuffix(trimmed, "{"))
			if len(name) >= 2 && ((name[0] == '\'' && name[len(name)-1] == '\'') || (name[0] == '"' && name[len(name)-1] == '"')) {
				name = name[1 : len(name)-1]
			}
			if name == groupName {
				open = offset + strings.Index(line, "{")
				close = matchingBrace(text, open)
				if close < 0 {
					return 0, 0, "", fmt.Errorf("malformed group block for %q", groupName)
				}
				childIndent = line[:len(line)-len(strings.TrimLeft(line, " \t"))]
				return open, close, childIndent, nil
			}
		}
		offset += len(line)
	}
	return 0, 0, "", &nativeapi.APIError{Status: 404, Code: "resource_not_found", Message: "group not found in managed configuration"}
}
