/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/component/nativeapi"
	"github.com/daeuniverse/dae/config"
)

// flowGlobalRel is the writable module every flow test edits.
const (
	flowGlobalRel   = "config.d/global.dae"
	flowValidGlobal = "global {\n  log_level: info\n}\n"
)

// managedModuleFixture returns a minimal valid body for each managed module.
// Each module must contribute a section, otherwise the merger does not report it.
func managedModuleFixture(name string) string {
	switch name {
	case "global.dae":
		return "global {}\n"
	case "routing.dae":
		return "routing {\n  fallback: direct\n}\n"
	default:
		return name[:len(name)-len(".dae")] + " {}\n"
	}
}

type fakeConfigOperations struct {
	calls int
	err   error
	// resolver records the body the last queued operation would report, so a
	// test can assert it was installed with the operation rather than after it.
	resolver func() (any, error)
	replays  map[string]fakeConfigReplay
}

type fakeConfigReplay struct {
	kind     string
	scope    string
	accepted nativeapi.OperationAccepted
}

func (f *fakeConfigOperations) ReplayOperation(kind, scope, idempotencyKey string) (nativeapi.OperationAccepted, bool, error) {
	if idempotencyKey == "" {
		return nativeapi.OperationAccepted{}, false, nil
	}
	previous, ok := f.replays[idempotencyKey]
	if !ok {
		return nativeapi.OperationAccepted{}, false, nil
	}
	if previous.kind != kind || previous.scope != scope {
		return nativeapi.OperationAccepted{}, false, nativeapi.NewAPIError(409, "idempotency_conflict",
			"idempotency key was used with a different request")
	}
	return previous.accepted, true, nil
}

func (f *fakeConfigOperations) StartOperationWithResult(ctx context.Context, kind, scope, idempotencyKey string, resolve func() (any, error)) (nativeapi.OperationAccepted, error) {
	f.calls++
	f.resolver = resolve
	if f.err != nil {
		return nativeapi.OperationAccepted{}, f.err
	}
	accepted := nativeapi.OperationAccepted{
		OperationID: fmt.Sprintf("op-%d", f.calls),
		Kind:        kind,
		Status:      "queued",
		Href:        fmt.Sprintf("/api/v1/operations/op-%d", f.calls),
	}
	if idempotencyKey != "" {
		if f.replays == nil {
			f.replays = map[string]fakeConfigReplay{}
		}
		f.replays[idempotencyKey] = fakeConfigReplay{kind: kind, scope: scope, accepted: accepted}
	}
	return accepted, nil
}

// newFlowEditor mirrors production startup: the api block is read from api.dae
// and passed as the start-up snapshot, so the candidate api must match it.
func newFlowEditor(t *testing.T, main string, enabled bool, ops operationQueue) *configEditor {
	t.Helper()
	return newFlowEditorWithReload(t, main, enabled, ops, nil)
}

func newFlowEditorWithReload(t *testing.T, main string, enabled bool, ops operationQueue, reload *reloadManager) *configEditor {
	t.Helper()
	apiBody := "api {\n  secret: 'flow-secret'\n  config_write: false\n}\n"
	if enabled {
		// config_write requires a listener secret, so the fixture always sets one.
		apiBody = "api {\n  secret: 'flow-secret'\n  config_write: true\n}\n"
	}
	if err := os.WriteFile(filepath.Join(filepath.Dir(main), "api.dae"), []byte(apiBody), 0o600); err != nil {
		t.Fatal(err)
	}
	sections, _, err := config.NewMerger(main).Merge()
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.New(sections)
	if err != nil {
		t.Fatal(err)
	}
	e, err := newConfigEditor(main, cfg.Api, ops, reload, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func flowAPIError(t *testing.T, err error) *nativeapi.APIError {
	t.Helper()
	var apiErr *nativeapi.APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *nativeapi.APIError, got %v", err)
	}
	return apiErr
}

// flowSource returns the loaded source at rel (relative to the config dir).
func flowSource(t *testing.T, e *configEditor, rel string) configSourceFile {
	t.Helper()
	all, err := e.loadSources()
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range all {
		if s.path == rel {
			return s
		}
	}
	t.Fatalf("source %s not loaded", rel)
	return configSourceFile{}
}

func TestConfigCapabilitiesReportLayoutAndHidden(t *testing.T) {
	main, _ := newManagedTree(t)

	caps := newFlowEditor(t, main, true, &fakeConfigOperations{}).ConfigCapabilities()
	if !caps.Writable || caps.Layout != "managed" || caps.LayoutReason != "" {
		t.Fatalf("managed tree with writes enabled: %+v", caps)
	}
	if len(caps.HiddenSources) != 1 || caps.HiddenSources[0] != hiddenConfigSourceName {
		t.Fatalf("hidden sources = %v", caps.HiddenSources)
	}

	caps = newFlowEditor(t, main, false, &fakeConfigOperations{}).ConfigCapabilities()
	if caps.Writable || caps.LayoutReason != "writes_disabled" {
		t.Fatalf("writes disabled: %+v", caps)
	}
}

func TestConfigGetConfigHidesAPIDaeAndMarksEntryReadOnly(t *testing.T) {
	main, _ := newManagedTree(t)
	e := newFlowEditor(t, main, true, &fakeConfigOperations{})

	result, err := e.GetConfig(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// The entry plus every managed module; api.dae is not part of the set.
	if want := 1 + len(managedConfigModules); len(result.Sources) != want {
		t.Fatalf("sources = %d, want %d", len(result.Sources), want)
	}
	for _, s := range result.Sources {
		if s.Path == "api.dae" {
			t.Fatal("api.dae must not be listed")
		}
		if s.Path == "config.dae" && (s.Writable || s.ReadOnlyReason != "entry_source") {
			t.Fatalf("config.dae must be read-only with reason entry_source: %+v", s)
		}
		if strings.HasPrefix(s.Path, "config.d/") && (!s.Writable || s.ReadOnlyReason != "") {
			t.Fatalf("module must be writable: %+v", s)
		}
	}
}

func TestConfigReplaceWritesBackupAndQueuesReload(t *testing.T) {
	main, _ := newManagedTree(t)
	ops := &fakeConfigOperations{}
	e := newFlowEditor(t, main, true, ops)
	target := flowSource(t, e, flowGlobalRel)

	_, err := e.ReplaceConfigSource(context.Background(), nativeapi.ReplaceConfigSourceRequest{
		SourceID: target.id,
		IfMatch:  rawSHA256(target.raw),
		Content:  flowValidGlobal,
	})
	if err != nil {
		t.Fatal(err)
	}
	if ops.calls != 1 {
		t.Fatalf("StartOperation calls = %d, want 1", ops.calls)
	}
	if got, _ := os.ReadFile(target.abs); string(got) != flowValidGlobal {
		t.Fatalf("source not replaced: %q", got)
	}
	if bak, _ := os.ReadFile(target.abs + ".bak"); string(bak) != string(target.raw) {
		t.Fatalf("backup does not hold the previous bytes: %q", bak)
	}
}

func TestConfigReplaceRejectsStaleRevision(t *testing.T) {
	main, _ := newManagedTree(t)
	ops := &fakeConfigOperations{}
	e := newFlowEditor(t, main, true, ops)
	target := flowSource(t, e, flowGlobalRel)

	_, err := e.ReplaceConfigSource(context.Background(), nativeapi.ReplaceConfigSourceRequest{
		SourceID: target.id,
		IfMatch:  "stale",
		Content:  flowValidGlobal,
	})
	if apiErr := flowAPIError(t, err); apiErr.Status != 412 || apiErr.Code != nativeapi.CodeStaleRevision {
		t.Fatalf("got %d %s, want 412 stale_revision", apiErr.Status, apiErr.Code)
	}
	if ops.calls != 0 {
		t.Fatal("stale write must not queue a reload")
	}
}

func TestConfigReplaceSyntaxErrorReturnsLocatedDiagnostics(t *testing.T) {
	main, _ := newManagedTree(t)
	e := newFlowEditor(t, main, true, &fakeConfigOperations{})
	target := flowSource(t, e, flowGlobalRel)

	_, err := e.ReplaceConfigSource(context.Background(), nativeapi.ReplaceConfigSourceRequest{
		SourceID: target.id,
		IfMatch:  rawSHA256(target.raw),
		Content:  "global {\n",
	})
	apiErr := flowAPIError(t, err)
	if apiErr.Status != 422 {
		t.Fatalf("status = %d, want 422", apiErr.Status)
	}
	details, _ := apiErr.Details.(map[string]any)
	diags, _ := details["diagnostics"].([]nativeapi.ConfigDiagnostic)
	if len(diags) == 0 || diags[0].Line == nil {
		t.Fatalf("expected a diagnostic with a line: %+v", diags)
	}
	if got, _ := os.ReadFile(target.abs); string(got) != string(target.raw) {
		t.Fatal("rejected write must not change the file")
	}
}

func TestConfigValidateSyntaxModeSkipsMerge(t *testing.T) {
	main, _ := newManagedTree(t)
	e := newFlowEditor(t, main, true, &fakeConfigOperations{})
	target := flowSource(t, e, flowGlobalRel)

	bad := "global {\n"
	result, err := e.ValidateConfig(context.Background(), nativeapi.ConfigValidationRequest{
		Mode:    "syntax",
		Sources: []nativeapi.ConfigValidationSource{{ID: target.id, Content: &bad}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Valid || len(result.Diagnostics) == 0 || result.Diagnostics[0].Line == nil {
		t.Fatalf("syntax mode must report a located error: %+v", result)
	}
}

func TestConfigHiddenSourceIsNotReferenceable(t *testing.T) {
	main, _ := newManagedTree(t)
	e := newFlowEditor(t, main, true, &fakeConfigOperations{})
	content := "api {}\n"

	_, err := e.ValidateConfig(context.Background(), nativeapi.ConfigValidationRequest{
		Mode:    "full",
		Sources: []nativeapi.ConfigValidationSource{{ID: sourceIDFor("api.dae"), Content: &content}},
	})
	if apiErr := flowAPIError(t, err); apiErr.Status != 400 {
		t.Fatalf("hidden id: status = %d, want 400", apiErr.Status)
	}

	_, err = e.ValidateConfig(context.Background(), nativeapi.ConfigValidationRequest{
		Mode:    "full",
		Sources: []nativeapi.ConfigValidationSource{{Path: "api.dae", Content: &content}},
	})
	if apiErr := flowAPIError(t, err); apiErr.Status != 400 {
		t.Fatalf("hidden path: status = %d, want 400", apiErr.Status)
	}

	_, err = e.ReplaceConfigSource(context.Background(), nativeapi.ReplaceConfigSourceRequest{
		SourceID: sourceIDFor("api.dae"),
		Content:  content,
	})
	if apiErr := flowAPIError(t, err); apiErr.Status != 404 {
		t.Fatalf("hidden replace: status = %d, want 404", apiErr.Status)
	}
}

func TestConfigReplaceRestoresFileWhenReloadFails(t *testing.T) {
	main, _ := newManagedTree(t)
	ops := &fakeConfigOperations{err: errors.New("reload refused")}
	e := newFlowEditor(t, main, true, ops)
	target := flowSource(t, e, flowGlobalRel)

	_, err := e.ReplaceConfigSource(context.Background(), nativeapi.ReplaceConfigSourceRequest{
		SourceID: target.id,
		IfMatch:  rawSHA256(target.raw),
		Content:  flowValidGlobal,
	})
	if err == nil {
		t.Fatal("expected the reload error to propagate")
	}
	if got, _ := os.ReadFile(target.abs); string(got) != string(target.raw) {
		t.Fatalf("file not restored after failed reload: %q", got)
	}
}

func TestConfigReplaceStoresSubmittedBytesVerbatim(t *testing.T) {
	main, _ := newManagedTree(t)
	e := newFlowEditor(t, main, true, &fakeConfigOperations{})
	target := flowSource(t, e, flowGlobalRel)
	// Comments and unusual spacing must survive: the daemon never rewrites text.
	body := "# leading comment\nglobal {\n\tlog_level: info   # trailing\n}\n"

	_, err := e.ReplaceConfigSource(context.Background(), nativeapi.ReplaceConfigSourceRequest{
		SourceID: target.id,
		IfMatch:  rawSHA256(target.raw),
		Content:  body,
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(target.abs)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != body {
		t.Fatalf("stored bytes were rewritten:\n%q\nwant\n%q", got, body)
	}
}

func TestConfigReplaceDisabledWritesNothing(t *testing.T) {
	main, _ := newManagedTree(t)
	ops := &fakeConfigOperations{}
	e := newFlowEditor(t, main, false, ops)
	target := flowSource(t, e, flowGlobalRel)

	_, err := e.ReplaceConfigSource(context.Background(), nativeapi.ReplaceConfigSourceRequest{
		SourceID: target.id,
		IfMatch:  rawSHA256(target.raw),
		Content:  flowValidGlobal,
	})
	if apiErr := flowAPIError(t, err); apiErr.Status != 403 {
		t.Fatalf("status = %d, want 403", apiErr.Status)
	}
	if ops.calls != 0 {
		t.Fatal("disabled writes must not queue a reload")
	}
	if _, statErr := os.Stat(target.abs + ".bak"); statErr == nil {
		t.Fatal("disabled writes must not create a backup")
	}
	if got, _ := os.ReadFile(target.abs); string(got) != string(target.raw) {
		t.Fatal("disabled writes must not change the file")
	}
}

func TestConfigReplaceReplaysIdempotentRequest(t *testing.T) {
	main, _ := newManagedTree(t)
	ops := &fakeConfigOperations{}
	e := newFlowEditor(t, main, true, ops)
	target := flowSource(t, e, flowGlobalRel)
	req := nativeapi.ReplaceConfigSourceRequest{
		SourceID:       target.id,
		IfMatch:        rawSHA256(target.raw),
		IdempotencyKey: "key-1",
		Content:        flowValidGlobal,
	}

	first, err := e.ReplaceConfigSource(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	second, err := e.ReplaceConfigSource(context.Background(), req)
	if err != nil {
		t.Fatalf("replay must succeed: %v", err)
	}
	if first.OperationID != second.OperationID {
		t.Fatalf("replay returned a different operation: %q vs %q", first.OperationID, second.OperationID)
	}
	if ops.calls != 1 {
		t.Fatalf("a replay must not queue a second reload, calls = %d", ops.calls)
	}
}

func TestConfigReplaceRejectsReusedKeyWithDifferentBody(t *testing.T) {
	main, _ := newManagedTree(t)
	ops := &fakeConfigOperations{}
	e := newFlowEditor(t, main, true, ops)
	target := flowSource(t, e, flowGlobalRel)

	_, err := e.ReplaceConfigSource(context.Background(), nativeapi.ReplaceConfigSourceRequest{
		SourceID:       target.id,
		IfMatch:        rawSHA256(target.raw),
		IdempotencyKey: "key-1",
		Content:        flowValidGlobal,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.ReplaceConfigSource(context.Background(), nativeapi.ReplaceConfigSourceRequest{
		SourceID:       target.id,
		IfMatch:        rawSHA256(target.raw),
		IdempotencyKey: "key-1",
		Content:        "global {\n  log_level: warn\n}\n",
	})
	if apiErr := flowAPIError(t, err); apiErr.Status != 409 || apiErr.Code != "idempotency_conflict" {
		t.Fatalf("got %d %s, want 409 idempotency_conflict", apiErr.Status, apiErr.Code)
	}
	if ops.calls != 1 {
		t.Fatalf("conflicting replay must not queue a reload, calls = %d", ops.calls)
	}
}

func TestConfigReplaceRejectsWhileReloadRuns(t *testing.T) {
	main, _ := newManagedTree(t)
	ops := &fakeConfigOperations{}
	reload := &reloadManager{}
	reload.reloadActive.Store(true)
	e := newFlowEditorWithReload(t, main, true, ops, reload)
	target := flowSource(t, e, flowGlobalRel)

	_, err := e.ReplaceConfigSource(context.Background(), nativeapi.ReplaceConfigSourceRequest{
		SourceID: target.id,
		IfMatch:  rawSHA256(target.raw),
		Content:  flowValidGlobal,
	})
	apiErr := flowAPIError(t, err)
	if apiErr.Status != 409 || apiErr.Code != "state_conflict" {
		t.Fatalf("got %d %s, want 409 state_conflict", apiErr.Status, apiErr.Code)
	}
	if ops.calls != 0 {
		t.Fatal("a busy reload must not queue another one")
	}
	if got, _ := os.ReadFile(target.abs); string(got) != string(target.raw) {
		t.Fatal("a rejected write must not change the file")
	}
}

func TestConfigReplaceSemanticFailureReturns422(t *testing.T) {
	main, _ := newManagedTree(t)
	ops := &fakeConfigOperations{}
	e := newFlowEditor(t, main, true, ops)
	// The module parses, so only the semantic pass can reject it.
	target := flowSource(t, e, "config.d/dns.dae")
	bad := "dns {\n  fixed_domain_ttl {\n    'example.com'\n  }\n}\n"

	_, err := e.ReplaceConfigSource(context.Background(), nativeapi.ReplaceConfigSourceRequest{
		SourceID: target.id,
		IfMatch:  rawSHA256(target.raw),
		Content:  bad,
	})
	apiErr := flowAPIError(t, err)
	if apiErr.Status != 422 {
		t.Fatalf("status = %d, want 422", apiErr.Status)
	}
	details, _ := apiErr.Details.(map[string]any)
	if diags, _ := details["diagnostics"].([]nativeapi.ConfigDiagnostic); len(diags) == 0 {
		t.Fatalf("expected diagnostics: %+v", apiErr.Details)
	}
	if ops.calls != 0 {
		t.Fatal("an invalid candidate must not queue a reload")
	}
	if got, _ := os.ReadFile(target.abs); string(got) != string(target.raw) {
		t.Fatal("an invalid candidate must not change the file")
	}
}

func TestConfigValidateRejectsDuplicateSources(t *testing.T) {
	main, _ := newManagedTree(t)
	e := newFlowEditor(t, main, true, &fakeConfigOperations{})
	content := "global {}\n"

	_, err := e.ValidateConfig(context.Background(), nativeapi.ConfigValidationRequest{
		Mode: "full",
		Sources: []nativeapi.ConfigValidationSource{
			{Path: flowGlobalRel, Content: &content},
			{Path: flowGlobalRel, Content: &content},
		},
	})
	if apiErr := flowAPIError(t, err); apiErr.Status != 400 {
		t.Fatalf("status = %d, want 400", apiErr.Status)
	}
}

func TestConfigReplaceRejectsDNSRoutingCLIWouldReject(t *testing.T) {
	main, _ := newManagedTree(t)
	ops := &fakeConfigOperations{}
	e := newFlowEditor(t, main, true, ops)
	target := flowSource(t, e, "config.d/dns.dae")
	// Parses and decodes cleanly: only the DNS routing dry-run rejects it, so
	// the API would otherwise store a candidate the daemon cannot start with.
	bad := "dns {\n  routing {\n    request {\n      fallback: nope\n    }\n  }\n}\n"

	_, err := e.ReplaceConfigSource(context.Background(), nativeapi.ReplaceConfigSourceRequest{
		SourceID: target.id,
		IfMatch:  rawSHA256(target.raw),
		Content:  bad,
	})
	if apiErr := flowAPIError(t, err); apiErr.Status != 422 {
		t.Fatalf("status = %d, want 422", apiErr.Status)
	}
	if ops.calls != 0 {
		t.Fatal("an invalid candidate must not queue a reload")
	}
	if got, _ := os.ReadFile(target.abs); string(got) != string(target.raw) {
		t.Fatal("an invalid candidate must not change the file")
	}
}

func TestConfigGetConfigSourceHidesAPIDae(t *testing.T) {
	main, _ := newManagedTree(t)
	e := newFlowEditor(t, main, true, &fakeConfigOperations{})

	_, _, err := e.GetConfigSource(context.Background(), sourceIDFor("api.dae"))
	if apiErr := flowAPIError(t, err); apiErr.Status != 404 || apiErr.Code != "resource_not_found" {
		t.Fatalf("got %d %s, want 404 resource_not_found", apiErr.Status, apiErr.Code)
	}
}

func TestConfigGetConfigMasksListenerSecret(t *testing.T) {
	// An unmanaged single file holds the listener secret in a visible source.
	// Writes are enabled, so only the layout gate can make it read-only.
	dir := t.TempDir()
	main := filepath.Join(dir, "config.dae")
	body := "global {}\napi {\n  listen: '127.0.0.1:1'\n  secret: 'hunter2'\n  config_write: true\n}\nrouting {\n  fallback: direct\n}\n"
	if err := os.WriteFile(main, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	sections, _, err := config.NewMerger(main).Merge()
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.New(sections)
	if err != nil {
		t.Fatal(err)
	}
	e, err := newConfigEditor(main, cfg.Api, &fakeConfigOperations{}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	result, err := e.GetConfig(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !result.SecretsRedacted {
		t.Fatal("the listener secret must be reported as redacted")
	}
	for _, s := range result.Sources {
		if strings.Contains(s.Content, "hunter2") {
			t.Fatalf("secret leaked in %s: %q", s.Path, s.Content)
		}
		if s.Writable || s.ReadOnlyReason != "layout_unmanaged" {
			t.Fatalf("an unmanaged tree must be read-only with layout_unmanaged: %+v", s)
		}
	}
}

func TestConfigReplaceRejectsCandidateLayoutLockout(t *testing.T) {
	main, _ := newManagedTree(t)
	e := newFlowEditor(t, main, true, &fakeConfigOperations{})
	target := flowSource(t, e, flowGlobalRel)

	// dns.dae already declares the dns section. Adding a second one here is
	// semantically valid (the merger concatenates items) but would make the
	// origin check report layout_unmanaged and lock every later write out.
	content := "global {\n  log_level: info\n}\ndns {}\n"
	_, err := e.ReplaceConfigSource(context.Background(), nativeapi.ReplaceConfigSourceRequest{
		SourceID: target.id,
		IfMatch:  rawSHA256(target.raw),
		Content:  content,
	})
	if apiErr := flowAPIError(t, err); apiErr.Status != 422 || apiErr.Code != "unsupported_value" {
		t.Fatalf("got %d %s, want 422 unsupported_value", apiErr.Status, apiErr.Code)
	}
	if got, _ := os.ReadFile(target.abs); string(got) != string(target.raw) {
		t.Fatalf("rejected layout changed the source: %q", got)
	}
}
