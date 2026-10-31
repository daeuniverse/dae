/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package nativeapi

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

type fakeOperationProvider struct {
	operations map[string]Operation
	startErr   error

	startedKind string
	startedKey  string
}

func newFakeOperationProvider() *fakeOperationProvider {
	return &fakeOperationProvider{operations: map[string]Operation{}}
}

func (p *fakeOperationProvider) StartOperation(ctx context.Context, kind, idempotencyKey string) (OperationAccepted, error) {
	p.startedKind, p.startedKey = kind, idempotencyKey
	if p.startErr != nil {
		return OperationAccepted{}, p.startErr
	}
	return OperationAccepted{
		OperationID: "op-test",
		Kind:        kind,
		Status:      OperationStatusQueued,
		Href:        BasePath + "/operations/op-test",
	}, nil
}

func (p *fakeOperationProvider) GetOperation(ctx context.Context, operationID string) (Operation, bool, error) {
	operation, ok := p.operations[operationID]
	return operation, ok, nil
}

func TestStartOperationAccepted(t *testing.T) {
	provider := newFakeOperationProvider()
	server := newTestServer(t, Config{AllowAnonymousLoopback: true}, fakeRuntimeProvider{runtime: testRuntime()})
	server.SetOperationProvider(provider)

	response := doRequestWithBody(server, http.MethodPost, "/api/v1/operations/reload", "", "")
	if response.Code != http.StatusAccepted {
		t.Fatalf("status = %d: %s", response.Code, response.Body.String())
	}
	if provider.startedKind != OperationKindReload {
		t.Fatalf("kind = %q", provider.startedKind)
	}
	if got, want := response.Header().Get("Location"), BasePath+"/operations/op-test"; got != want {
		t.Fatalf("Location = %q, want %q", got, want)
	}
	if got := response.Header().Get("Retry-After"); got != "1" {
		t.Fatalf("Retry-After = %q", got)
	}
	body := decodeJSON(t, response)
	if body["status"] != OperationStatusQueued || body["href"] != response.Header().Get("Location") {
		t.Fatalf("body = %#v", body)
	}

	suspend := doRequestWithBody(server, http.MethodPost, "/api/v1/operations/suspend", "application/json", "{}")
	if suspend.Code != http.StatusAccepted || provider.startedKind != OperationKindSuspend {
		t.Fatalf("suspend status = %d kind = %q", suspend.Code, provider.startedKind)
	}
}

func TestStartOperationIdempotencyHeaderAndConflicts(t *testing.T) {
	provider := &fakeOperationProvider{
		startErr: NewAPIError(http.StatusConflict, codeStateConflict, "a reload is already in progress"),
	}
	server := newTestServer(t, Config{AllowAnonymousLoopback: true}, fakeRuntimeProvider{runtime: testRuntime()})
	server.SetOperationProvider(provider)

	conflict := doRequestWithBody(server, http.MethodPost, "/api/v1/operations/reload", "", "")
	if conflict.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", conflict.Code)
	}

	badBody := doRequestWithBody(server, http.MethodPost, "/api/v1/operations/reload", "application/json", `{"x":1}`)
	if badBody.Code != http.StatusBadRequest {
		t.Fatalf("non-empty body status = %d, want 400", badBody.Code)
	}

	badType := doRequestWithBody(server, http.MethodPost, "/api/v1/operations/reload", "text/plain", `{}`)
	if badType.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("bad content-type status = %d, want 415", badType.Code)
	}

	method := doRequest(server, http.MethodGet, "/api/v1/operations/reload", "127.0.0.1:1234", nil)
	if method.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET start status = %d, want 405", method.Code)
	}
	if allow := method.Header().Get("Allow"); allow != "POST" {
		t.Fatalf("Allow = %q", allow)
	}
}

func TestGetOperationStatus(t *testing.T) {
	provider := newFakeOperationProvider()
	provider.operations["op-run"] = Operation{
		OperationID: "op-run",
		Kind:        OperationKindReload,
		Status:      OperationStatusRunning,
		CreatedAt:   "2026-01-01T00:00:00Z",
	}
	provider.operations["op-done"] = Operation{
		OperationID: "op-done",
		Kind:        OperationKindReload,
		Status:      OperationStatusSucceeded,
		CreatedAt:   "2026-01-01T00:00:00Z",
		FinishedAt:  strPtr("2026-01-01T00:00:01Z"),
		Result:      ReloadResult{},
	}
	server := newTestServer(t, Config{AllowAnonymousLoopback: true}, fakeRuntimeProvider{runtime: testRuntime()})
	server.SetOperationProvider(provider)
	remote := "127.0.0.1:1234"

	running := doRequest(server, http.MethodGet, "/api/v1/operations/op-run", remote, nil)
	if running.Code != http.StatusOK {
		t.Fatalf("running status = %d", running.Code)
	}
	if got := running.Header().Get("Retry-After"); got != "1" {
		t.Fatalf("running Retry-After = %q", got)
	}

	done := doRequest(server, http.MethodGet, "/api/v1/operations/op-done", remote, nil)
	if done.Code != http.StatusOK {
		t.Fatalf("done status = %d", done.Code)
	}
	if got := done.Header().Get("Retry-After"); got != "" {
		t.Fatalf("terminal Retry-After = %q, want none", got)
	}

	missing := doRequest(server, http.MethodGet, "/api/v1/operations/op-missing", remote, nil)
	if missing.Code != http.StatusNotFound {
		t.Fatalf("missing status = %d, want 404", missing.Code)
	}
	if got := decodeJSON(t, missing)["error"].(map[string]any)["code"]; got != codeResourceNotFound {
		t.Fatalf("missing error code = %v", got)
	}
}

func TestOperationStoreReplayAndRetention(t *testing.T) {
	store := NewOperationStore(time.Minute, 2)
	accepted, replayed, err := store.Accept(OperationKindReload, "key-1")
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	if replayed {
		t.Fatal("first accept must not be a replay")
	}
	replay, replayed, err := store.Accept(OperationKindReload, "key-1")
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if !replayed {
		t.Fatal("second accept must report a replay")
	}
	if replay.OperationID != accepted.OperationID {
		t.Fatalf("replay created %q, want %q", replay.OperationID, accepted.OperationID)
	}
	if _, _, err := store.Accept(OperationKindSuspend, "key-1"); err == nil {
		t.Fatal("key reuse with another kind must conflict")
	} else {
		apiErr := err.(*APIError)
		if apiErr.Status != http.StatusConflict || apiErr.Code != codeIdempotencyConflict {
			t.Fatalf("conflict = %#v", apiErr)
		}
	}

	store.Start(accepted.OperationID)
	running, ok := store.Get(accepted.OperationID)
	if !ok || running.Status != OperationStatusRunning || running.StartedAt == nil {
		t.Fatalf("running operation = %#v", running)
	}
	store.Succeed(accepted.OperationID, ReloadResult{})
	done, _ := store.Get(accepted.OperationID)
	if done.Status != OperationStatusSucceeded || done.FinishedAt == nil {
		t.Fatalf("done operation = %#v", done)
	}

	// Age the finished operation past retention.
	past := time.Now().Add(-2 * time.Minute)
	store.mu.Lock()
	store.operations[accepted.OperationID].finishedAt = &past
	store.mu.Unlock()
	if _, ok := store.Get(accepted.OperationID); ok {
		t.Fatal("expired operation must be evicted")
	}
	if _, _, err := store.Accept(OperationKindReload, "key-1"); err != nil {
		t.Fatalf("accept after expiry: %v", err)
	}
}

func TestOperationStoreKeepsUnfinishedOperations(t *testing.T) {
	store := NewOperationStore(time.Nanosecond, 1)
	accepted, _, err := store.Accept(OperationKindReload, "")
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	time.Sleep(2 * time.Millisecond)
	if _, ok := store.Get(accepted.OperationID); !ok {
		t.Fatal("unfinished operation must not be evicted")
	}
}

func TestOperationStoreFail(t *testing.T) {
	store := NewOperationStore(time.Minute, 4)
	accepted, _, _ := store.Accept(OperationKindReload, "")
	store.Fail(accepted.OperationID, &SafeError{Code: "reload_rejected", Message: "boom"})
	operation, ok := store.Get(accepted.OperationID)
	if !ok || operation.Status != OperationStatusFailed || operation.Error == nil {
		t.Fatalf("failed operation = %#v", operation)
	}
	if operation.Error.Code != "reload_rejected" {
		t.Fatalf("error code = %q", operation.Error.Code)
	}
	// A late success must not resurrect a terminal operation.
	store.Succeed(accepted.OperationID, nil)
	operation, _ = store.Get(accepted.OperationID)
	if operation.Status != OperationStatusFailed {
		t.Fatalf("terminal status changed to %q", operation.Status)
	}
}

type fakeTrafficProvider struct {
	history TrafficHistory
	err     error

	windowSeconds int
	maxPoints     int
}

func (p *fakeTrafficProvider) TrafficHistory(ctx context.Context, windowSeconds, maxPoints int) (TrafficHistory, error) {
	p.windowSeconds, p.maxPoints = windowSeconds, maxPoints
	return p.history, p.err
}

func TestTrafficHistoryParametersAndShape(t *testing.T) {
	provider := &fakeTrafficProvider{history: TrafficHistory{
		ObservedAt:          "2026-01-01T00:00:00Z",
		WindowSeconds:       DefaultTrafficHistoryWindow,
		SampledEverySeconds: 1,
		Samples: []TrafficHistorySample{{
			SampledAt:              "2026-01-01T00:00:00Z",
			UploadBytesPerSecond:   strPtr("10"),
			DownloadBytesPerSecond: strPtr("20"),
		}},
	}}
	server := newTestServer(t, Config{AllowAnonymousLoopback: true}, fakeRuntimeProvider{runtime: testRuntime()})
	server.SetTrafficHistoryProvider(provider)
	remote := "127.0.0.1:1234"

	response := doRequest(server, http.MethodGet, "/api/v1/runtime/traffic/history", remote, nil)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", response.Code, response.Body.String())
	}
	if provider.windowSeconds != DefaultTrafficHistoryWindow || provider.maxPoints != DefaultTrafficHistoryPoints {
		t.Fatalf("defaults = %d, %d", provider.windowSeconds, provider.maxPoints)
	}
	var body map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["window_seconds"] != float64(DefaultTrafficHistoryWindow) {
		t.Fatalf("window_seconds = %#v", body["window_seconds"])
	}
	samples := body["samples"].([]any)
	first := samples[0].(map[string]any)
	if first["upload_bytes_per_second"] != "10" || first["connections"] != nil {
		t.Fatalf("sample = %#v", first)
	}

	limited := doRequest(server, http.MethodGet, "/api/v1/runtime/traffic/history?window_seconds=60&max_points=10", remote, nil)
	if limited.Code != http.StatusOK {
		t.Fatalf("limited status = %d", limited.Code)
	}
	if provider.windowSeconds != 60 || provider.maxPoints != 10 {
		t.Fatalf("parsed = %d, %d", provider.windowSeconds, provider.maxPoints)
	}

	for _, query := range []string{
		"window_seconds=0",
		"window_seconds=-1",
		"window_seconds=abc",
		"window_seconds=3601",
		"max_points=0",
		"max_points=181",
	} {
		bad := doRequest(server, http.MethodGet, "/api/v1/runtime/traffic/history?"+query, remote, nil)
		if bad.Code != http.StatusBadRequest {
			t.Fatalf("%s status = %d, want 400", query, bad.Code)
		}
	}
}
