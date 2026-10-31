/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package nativeapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
)

type fakeRuntimeProvider struct {
	runtime Runtime
	err     error
}

func (p fakeRuntimeProvider) SnapshotRuntime(ctx context.Context, detail string) (Runtime, error) {
	if p.err != nil {
		return Runtime{}, p.err
	}
	return p.runtime, nil
}

func newTestServer(t *testing.T, cfg Config, provider RuntimeProvider) *Server {
	t.Helper()
	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:9527"
	}
	server, err := NewServer(cfg, provider, logrus.New())
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func doRequest(server *Server, method, path, remoteAddr string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	req.Host = "127.0.0.1:9527"
	if remoteAddr != "" {
		req.RemoteAddr = remoteAddr
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, req)
	return recorder
}

func decodeJSON(t *testing.T, recorder *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v\n%s", err, recorder.Body.String())
	}
	return body
}

func testRuntime() Runtime {
	pid := uint32(123)
	cpu := 1.5
	one := "1"
	return Runtime{
		ObservedAt: "2026-01-01T00:00:00Z",
		InstanceID: "instance-test",
		Lifecycle: Lifecycle{
			State:         "running",
			StartedAt:     &one,
			UptimeSeconds: &one,
		},
		Generation: Generation{
			ActiveID:       "gen-test",
			ConfigRevision: &one,
			State:          "active",
			ActivatedAt:    &one,
		},
		Datapath: DatapathSummary{
			Kind:       "ebpf",
			State:      "active",
			Visibility: "partial",
			Ebpf:       nil,
		},
		Traffic: TrafficSummary{
			Scope:        "visible",
			ObservedBy:   "userspace",
			CounterSince: &one,
			SampledAt:    &one,
			Connections: Connections{
				TCP:   uint64Ptr(1),
				UDP:   uint64Ptr(2),
				Total: uint64Ptr(3),
			},
			Bytes: Bytes{
				Upload:   strPtr("10"),
				Download: strPtr("20"),
			},
			Rates: &Rates{
				WindowSeconds:          1,
				UploadBytesPerSecond:   strPtr("1"),
				DownloadBytesPerSecond: strPtr("2"),
			},
		},
		Process: Process{
			Pid:        &pid,
			CPUPercent: &cpu,
		},
	}
}

func strPtr(value string) *string    { return &value }
func uint64Ptr(value uint64) *uint64 { return &value }

func TestDiscoveryPublicAndFull(t *testing.T) {
	server := newTestServer(t, Config{
		Secret: "operator-token-123456",
	}, fakeRuntimeProvider{runtime: testRuntime()})

	public := doRequest(server, http.MethodGet, "/api", "192.0.2.1:1234", nil)
	if public.Code != http.StatusOK {
		t.Fatalf("public discovery status = %d, want 200: %s", public.Code, public.Body.String())
	}
	body := decodeJSON(t, public)
	if body["name"] != APIName {
		t.Fatalf("name = %v", body["name"])
	}
	if _, ok := body["status"]; ok {
		t.Fatal("public discovery must not expose status")
	}
	links := body["links"].(map[string]any)
	if len(links) != 2 {
		t.Fatalf("public links = %#v, want auth_setup/auth_login only", links)
	}

	full := doRequest(server, http.MethodGet, "/api", "192.0.2.1:1234", map[string]string{
		"Authorization": "Bearer operator-token-123456",
	})
	if full.Code != http.StatusOK {
		t.Fatalf("full discovery status = %d: %s", full.Code, full.Body.String())
	}
	fullBody := decodeJSON(t, full)
	if fullBody["status"] != APIStatus {
		t.Fatalf("status = %v", fullBody["status"])
	}
	fullLinks := fullBody["links"].(map[string]any)
	for _, key := range []string{"version", "capabilities", "runtime", "config", "operations"} {
		if _, ok := fullLinks[key]; !ok {
			t.Fatalf("full links missing %q: %#v", key, fullLinks)
		}
	}
}

func TestAuthentication(t *testing.T) {
	server := newTestServer(t, Config{
		Secret: "operator-token-123456",
	}, fakeRuntimeProvider{runtime: testRuntime()})

	unauthorized := doRequest(server, http.MethodGet, "/api/v1/version", "192.0.2.1:1234", nil)
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", unauthorized.Code)
	}
	if got := unauthorized.Header().Get("WWW-Authenticate"); got != "Bearer" {
		t.Fatalf("WWW-Authenticate = %q", got)
	}

	invalid := doRequest(server, http.MethodGet, "/api", "192.0.2.1:1234", map[string]string{
		"Authorization": "Bearer wrong",
	})
	if invalid.Code != http.StatusUnauthorized {
		t.Fatalf("invalid discovery credential status = %d, want 401", invalid.Code)
	}

	version := doRequest(server, http.MethodGet, "/api/v1/version", "192.0.2.1:1234", map[string]string{
		"Authorization": "Bearer operator-token-123456",
	})
	if version.Code != http.StatusOK {
		t.Fatalf("authorized version status = %d: %s", version.Code, version.Body.String())
	}
	body := decodeJSON(t, version)
	engine := body["engine"].(map[string]any)
	if engine["name"] != EngineName {
		t.Fatalf("engine.name = %v", engine["name"])
	}
}

func TestAnonymousLoopback(t *testing.T) {
	server := newTestServer(t, Config{
		AllowAnonymousLoopback: true,
	}, fakeRuntimeProvider{runtime: testRuntime()})

	full := doRequest(server, http.MethodGet, "/api", "127.0.0.1:1234", nil)
	if full.Code != http.StatusOK {
		t.Fatalf("anonymous loopback discovery status = %d", full.Code)
	}
	body := decodeJSON(t, full)
	if body["status"] != APIStatus {
		t.Fatalf("anonymous loopback discovery should be full view, got %#v", body)
	}
	auth := body["auth"].(map[string]any)
	if auth["anonymous_loopback"] != true {
		t.Fatalf("auth.anonymous_loopback = %v", auth["anonymous_loopback"])
	}

	runtimeResponse := doRequest(server, http.MethodGet, "/api/v1/runtime", "127.0.0.1:1234", nil)
	if runtimeResponse.Code != http.StatusOK {
		t.Fatalf("anonymous loopback runtime status = %d: %s", runtimeResponse.Code, runtimeResponse.Body.String())
	}

	rejected := doRequest(server, http.MethodGet, "/api/v1/runtime", "192.0.2.1:1234", nil)
	if rejected.Code != http.StatusUnauthorized {
		t.Fatalf("non-loopback anonymous status = %d, want 401", rejected.Code)
	}
}

func TestVersionCapabilitiesAndRuntime(t *testing.T) {
	server := newTestServer(t, Config{
		AllowAnonymousLoopback: true,
		EngineVersion:          "test-version",
	}, fakeRuntimeProvider{runtime: testRuntime()})
	remote := "127.0.0.1:1234"

	version := doRequest(server, http.MethodGet, "/api/v1/version", remote, nil)
	if version.Code != http.StatusOK {
		t.Fatalf("version status = %d", version.Code)
	}
	versionBody := decodeJSON(t, version)
	api := versionBody["api"].(map[string]any)
	if api["name"] != APIName || api["major"] != float64(APIMajor) {
		t.Fatalf("api = %#v", api)
	}
	engine := versionBody["engine"].(map[string]any)
	if engine["version"] != "test-version" {
		t.Fatalf("engine.version = %v", engine["version"])
	}

	capabilities := doRequest(server, http.MethodGet, "/api/v1/capabilities", remote, nil)
	if capabilities.Code != http.StatusOK {
		t.Fatalf("capabilities status = %d", capabilities.Code)
	}
	capBody := decodeJSON(t, capabilities)
	resources := capBody["resources"].(map[string]any)
	runtimeResource := resources["runtime"].(map[string]any)
	if runtimeResource["available"] != true {
		t.Fatalf("runtime capability = %#v", runtimeResource)
	}

	runtimeResponse := doRequest(server, http.MethodGet, "/api/v1/runtime?detail=full", remote, nil)
	if runtimeResponse.Code != http.StatusOK {
		t.Fatalf("runtime status = %d: %s", runtimeResponse.Code, runtimeResponse.Body.String())
	}
	runtimeBody := decodeJSON(t, runtimeResponse)
	if runtimeBody["instance_id"] != "instance-test" {
		t.Fatalf("instance_id = %v", runtimeBody["instance_id"])
	}
	process := runtimeBody["process"].(map[string]any)
	if process["pid"] != float64(123) {
		t.Fatalf("process.pid = %v", process["pid"])
	}
	traffic := runtimeBody["traffic"].(map[string]any)
	bytes := traffic["bytes"].(map[string]any)
	if bytes["upload"] != "10" {
		t.Fatalf("bytes.upload should be a decimal string, got %#v", bytes["upload"])
	}

	invalidDetail := doRequest(server, http.MethodGet, "/api/v1/runtime?detail=live", remote, nil)
	if invalidDetail.Code != http.StatusBadRequest {
		t.Fatalf("invalid detail status = %d, want 400", invalidDetail.Code)
	}
}

func TestUnavailableAndMethodNotAllowed(t *testing.T) {
	server := newTestServer(t, Config{AllowAnonymousLoopback: true}, fakeRuntimeProvider{runtime: testRuntime()})
	remote := "127.0.0.1:1234"

	unavailable := doRequest(server, http.MethodGet, "/api/v1/groups", remote, nil)
	if unavailable.Code != http.StatusNotFound {
		t.Fatalf("unavailable status = %d, want 404", unavailable.Code)
	}
	body := decodeJSON(t, unavailable)
	errorBody := body["error"].(map[string]any)
	if errorBody["code"] != codeCapabilityNotSupported {
		t.Fatalf("error.code = %v", errorBody["code"])
	}
	if body["request_id"] == nil {
		t.Fatal("error response must include request_id")
	}

	method := doRequest(server, http.MethodPost, "/api/v1/runtime", remote, nil)
	if method.Code != http.StatusMethodNotAllowed {
		t.Fatalf("method status = %d, want 405", method.Code)
	}
	if allow := method.Header().Get("Allow"); !strings.Contains(allow, "GET") {
		t.Fatalf("Allow = %q", allow)
	}
}

// Contract resources that are known but have no implementation plan must not
// fall into the generic resource_not_found bucket.
func TestKnownUnimplementedResourcesReportCapability(t *testing.T) {
	server := newTestServer(t, Config{AllowAnonymousLoopback: true}, fakeRuntimeProvider{runtime: testRuntime()})
	remote := "127.0.0.1:1234"

	for _, path := range []string{
		"/api/v1/providers",
		"/api/v1/providers/inline",
		"/api/v1/geodata",
		"/api/v1/rules",
		"/api/v1/dns/cache",
		"/api/v1/flows",
		"/api/v1/connections",
		"/api/v1/events",
		"/api/v1/logs",
		"/api/v1/probes",
		"/api/v1/runtime/memory",
		"/api/v1/runtime/memory/history",
		"/api/v1/runtime/outbounds",
		"/api/v1/runtime/settings",
		"/api/v1/datapath",
		"/api/v1/routing/trace",
		"/api/v1/auth",
		"/api/v1/auth/login",
	} {
		method := http.MethodGet
		if path == "/api/v1/probes" {
			method = http.MethodPost
		}
		response := doRequest(server, method, path, remote, nil)
		if response.Code != http.StatusNotFound {
			t.Fatalf("%s status = %d, want 404", path, response.Code)
		}
		if got := decodeJSON(t, response)["error"].(map[string]any)["code"]; got != codeCapabilityNotSupported {
			t.Fatalf("%s error code = %v, want %s", path, got, codeCapabilityNotSupported)
		}
	}
}

func TestHostOriginAndPreflight(t *testing.T) {
	server := newTestServer(t, Config{
		AllowAnonymousLoopback: true,
		AllowOrigins:           []string{"https://panel.example"},
		AllowedHosts:           []string{"panel.example"},
	}, fakeRuntimeProvider{runtime: testRuntime()})
	remote := "127.0.0.1:1234"

	badHost := httptest.NewRequest(http.MethodGet, "/api", nil)
	badHost.Host = "evil.example"
	badHost.RemoteAddr = remote
	badHostRecorder := httptest.NewRecorder()
	server.ServeHTTP(badHostRecorder, badHost)
	if badHostRecorder.Code != http.StatusForbidden {
		t.Fatalf("bad host status = %d, want 403", badHostRecorder.Code)
	}

	allowedHost := httptest.NewRequest(http.MethodGet, "/api", nil)
	allowedHost.Host = "panel.example"
	allowedHost.RemoteAddr = remote
	allowedHostRecorder := httptest.NewRecorder()
	server.ServeHTTP(allowedHostRecorder, allowedHost)
	if allowedHostRecorder.Code != http.StatusOK {
		t.Fatalf("allowed host status = %d: %s", allowedHostRecorder.Code, allowedHostRecorder.Body.String())
	}

	crossSite := doRequest(server, http.MethodGet, "/api", remote, map[string]string{
		"Sec-Fetch-Site": "cross-site",
	})
	if crossSite.Code != http.StatusForbidden {
		t.Fatalf("cross-site status = %d, want 403", crossSite.Code)
	}

	preflight := doRequest(server, http.MethodOptions, "/api/v1/runtime", remote, map[string]string{
		"Origin":                         "https://panel.example",
		"Access-Control-Request-Method":  "GET",
		"Access-Control-Request-Headers": "authorization",
	})
	if preflight.Code != http.StatusNoContent {
		t.Fatalf("preflight status = %d: %s", preflight.Code, preflight.Body.String())
	}
	if got := preflight.Header().Get("Access-Control-Allow-Origin"); got != "https://panel.example" {
		t.Fatalf("Access-Control-Allow-Origin = %q", got)
	}

	// The state-changing P1 routes always preflight across origins, so the
	// allowed method list must cover them.
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		writePreflight := doRequest(server, http.MethodOptions, "/api/v1/groups/g_1/selection", remote, map[string]string{
			"Origin":                         "https://panel.example",
			"Access-Control-Request-Method":  method,
			"Access-Control-Request-Headers": "authorization, content-type",
		})
		if writePreflight.Code != http.StatusNoContent {
			t.Fatalf("%s preflight status = %d: %s", method, writePreflight.Code, writePreflight.Body.String())
		}
		if allow := writePreflight.Header().Get("Access-Control-Allow-Methods"); !strings.Contains(allow, method) {
			t.Fatalf("%s missing from Access-Control-Allow-Methods %q", method, allow)
		}
	}

	rejected := doRequest(server, http.MethodOptions, "/api/v1/runtime", remote, map[string]string{
		"Origin":                        "https://panel.example",
		"Access-Control-Request-Method": "TRACE",
	})
	if rejected.Code != http.StatusForbidden {
		t.Fatalf("unknown method preflight status = %d, want 403", rejected.Code)
	}
}

func TestCommonResponseHeaders(t *testing.T) {
	server := newTestServer(t, Config{AllowAnonymousLoopback: true}, fakeRuntimeProvider{runtime: testRuntime()})
	response := doRequest(server, http.MethodGet, "/api/v1/runtime", "127.0.0.1:1234", nil)
	if got := response.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q", got)
	}
	if got := response.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("X-Content-Type-Options = %q", got)
	}
}

func TestRequestSizeLimits(t *testing.T) {
	server := newTestServer(t, Config{AllowAnonymousLoopback: true}, fakeRuntimeProvider{runtime: testRuntime()})
	remote := "127.0.0.1:1234"

	longTarget := doRequest(server, http.MethodGet, "/api/v1/version?x="+strings.Repeat("a", defaultMaxRequestTargetBytes), remote, nil)
	if longTarget.Code != http.StatusBadRequest {
		t.Fatalf("long target status = %d, want 400", longTarget.Code)
	}
	if code := errorCode(t, longTarget); code != codeInvalidRequest {
		t.Fatalf("long target error.code = %q", code)
	}

	bigHeaders := doRequest(server, http.MethodGet, "/api/v1/version", remote, map[string]string{
		"X-Pad": strings.Repeat("b", defaultMaxHeaderBytes),
	})
	if bigHeaders.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("big header status = %d, want 413", bigHeaders.Code)
	}
	if code := errorCode(t, bigHeaders); code != codeRequestTooLarge {
		t.Fatalf("big header error.code = %q", code)
	}

	bigBody := httptest.NewRequest(http.MethodPost, "/api/v1/runtime", strings.NewReader(strings.Repeat("c", defaultMaxJSONBodyBytes+1)))
	bigBody.Host = "127.0.0.1:9527"
	bigBody.RemoteAddr = remote
	bigBodyRecord := httptest.NewRecorder()
	server.ServeHTTP(bigBodyRecord, bigBody)
	if bigBodyRecord.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("big body status = %d, want 413", bigBodyRecord.Code)
	}
	if body := decodeJSON(t, bigBodyRecord); body["request_id"] == nil {
		t.Fatal("error response must include request_id")
	}
}

func errorCode(t *testing.T, recorder *httptest.ResponseRecorder) string {
	t.Helper()
	body := decodeJSON(t, recorder)
	errorBody, ok := body["error"].(map[string]any)
	if !ok {
		t.Fatalf("response has no error object: %s", recorder.Body.String())
	}
	code, _ := errorBody["code"].(string)
	return code
}

func TestRequestLogging(t *testing.T) {
	logger, hook := test.NewNullLogger()
	logger.SetLevel(logrus.DebugLevel)
	server, err := NewServer(Config{AllowAnonymousLoopback: true}, fakeRuntimeProvider{runtime: testRuntime()}, logger)
	if err != nil {
		t.Fatal(err)
	}
	remote := "127.0.0.1:1234"

	if response := doRequest(server, http.MethodGet, "/api/v1/runtime", remote, nil); response.Code != http.StatusOK {
		t.Fatalf("runtime status = %d", response.Code)
	}
	entries := hook.AllEntries()
	if len(entries) != 1 {
		t.Fatalf("log entries = %d, want 1", len(entries))
	}
	entry := entries[0]
	if entry.Level != logrus.DebugLevel {
		t.Fatalf("level = %v, want debug", entry.Level)
	}
	for field, want := range map[string]any{
		"method":    http.MethodGet,
		"route":     "/api/v1/runtime",
		"status":    200,
		"remote_ip": "127.0.0.1",
	} {
		if got := entry.Data[field]; got != want {
			t.Fatalf("%s = %v, want %v", field, got, want)
		}
	}
	if entry.Data["request_id"] == nil {
		t.Fatal("access log must carry request_id")
	}

	hook.Reset()
	if response := doRequest(server, http.MethodGet, "/api/v1/groups/team-hk", remote, nil); response.Code != http.StatusNotFound {
		t.Fatalf("groups status = %d", response.Code)
	}
	entries = hook.AllEntries()
	if len(entries) != 1 || entries[0].Level != logrus.InfoLevel {
		t.Fatalf("refusal must log one info entry, got %#v", entries)
	}
	if got := entries[0].Data["route"]; got != "/api/v1/groups/{group_id}" {
		t.Fatalf("route = %v, want the resource prefix", got)
	}
	if got := entries[0].Data["error_code"]; got != codeCapabilityNotSupported {
		t.Fatalf("error_code = %v", got)
	}

	hook.Reset()
	if response := doRequest(server, http.MethodGet, "/definitely/not/ours", remote, nil); response.Code != http.StatusNotFound {
		t.Fatalf("unmatched status = %d", response.Code)
	}
	if got := hook.AllEntries()[0].Data["route"]; got != "<unmatched>" {
		t.Fatalf("unmatched route = %v", got)
	}
}

func TestRequestLoggingKeepsSecretsOut(t *testing.T) {
	const secret = "operator-token-should-never-appear"
	logger, hook := test.NewNullLogger()
	logger.SetLevel(logrus.DebugLevel)
	server, err := NewServer(Config{Secret: secret}, fakeRuntimeProvider{runtime: testRuntime()}, logger)
	if err != nil {
		t.Fatal(err)
	}
	remote := "127.0.0.1:1234"

	doRequest(server, http.MethodGet, "/api/v1/runtime", remote, map[string]string{"Authorization": "Bearer " + secret})
	doRequest(server, http.MethodGet, "/api/v1/runtime", remote, map[string]string{"Authorization": "Bearer wrong-" + secret})
	entries := hook.AllEntries()
	if len(entries) != 2 {
		t.Fatalf("log entries = %d, want 2", len(entries))
	}
	if entries[0].Level != logrus.DebugLevel || entries[1].Level != logrus.InfoLevel {
		t.Fatalf("levels = %v, %v", entries[0].Level, entries[1].Level)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Message, secret) {
			t.Fatalf("log message leaks the secret: %q", entry.Message)
		}
		for key, value := range entry.Data {
			if strings.Contains(fmt.Sprint(value), secret) {
				t.Fatalf("log field %q leaks the secret", key)
			}
		}
	}
}

func TestAccessSummary(t *testing.T) {
	logger, hook := test.NewNullLogger()
	server, err := NewServer(Config{AllowAnonymousLoopback: true}, fakeRuntimeProvider{runtime: testRuntime()}, logger)
	if err != nil {
		t.Fatal(err)
	}
	remote := "127.0.0.1:1234"
	doRequest(server, http.MethodGet, "/api/v1/runtime", remote, nil)
	doRequest(server, http.MethodGet, "/api/v1/version", remote, nil)
	doRequest(server, http.MethodGet, "/api/v1/groups", remote, nil)

	hook.Reset()
	server.reportAccessSummary()
	entries := hook.AllEntries()
	if len(entries) != 1 || entries[0].Level != logrus.InfoLevel {
		t.Fatalf("summary entries = %#v", entries)
	}
	if got := entries[0].Data["served"]; got != uint64(2) {
		t.Fatalf("served = %v, want 2", got)
	}
	if got := entries[0].Data["refused"]; got != uint64(1) {
		t.Fatalf("refused = %v, want 1", got)
	}

	hook.Reset()
	server.reportAccessSummary()
	if len(hook.AllEntries()) != 0 {
		t.Fatalf("idle window must stay silent, got %#v", hook.AllEntries())
	}
}

func TestServerStartStopLogging(t *testing.T) {
	logger, hook := test.NewNullLogger()
	server, err := NewServer(Config{Listen: "127.0.0.1:19699", AllowAnonymousLoopback: true}, fakeRuntimeProvider{runtime: testRuntime()}, logger)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Start(); err != nil {
		t.Skipf("listen failed, likely a busy port: %v", err)
	}
	if err := server.Shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	stopped := false
	for _, entry := range hook.AllEntries() {
		if entry.Level == logrus.InfoLevel && entry.Message == "Native API listener stopped" {
			stopped = true
		}
	}
	if !stopped {
		t.Fatal("shutdown must log that the listener stopped")
	}
}

func writeUIFile(t *testing.T, dir, name, body string) {
	t.Helper()
	full := filepath.Join(dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func newUITree(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeUIFile(t, dir, "index.html", "<!doctype html><title>dae ui</title>")
	writeUIFile(t, dir, "assets/app-1a2b.js", "console.log('app')")
	if err := os.MkdirAll(filepath.Join(dir, "assets"), 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestUIServing(t *testing.T) {
	dir := newUITree(t)
	server := newTestServer(t, Config{Secret: "operator-token-123456", UI: dir}, fakeRuntimeProvider{runtime: testRuntime()})
	remote := "127.0.0.1:1234"

	index := doRequest(server, http.MethodGet, "/ui/", remote, nil)
	if index.Code != http.StatusOK {
		t.Fatalf("ui index status = %d", index.Code)
	}
	if !strings.Contains(index.Body.String(), "dae ui") {
		t.Fatalf("ui index body = %q", index.Body.String())
	}
	if got := index.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/html") {
		t.Fatalf("ui index Content-Type = %q", got)
	}
	if got := index.Header().Get("Cache-Control"); got != "no-cache" {
		t.Fatalf("ui index Cache-Control = %q", got)
	}

	for _, path := range []string{"/ui", "/"} {
		redirect := doRequest(server, http.MethodGet, path, remote, nil)
		if redirect.Code != http.StatusFound {
			t.Fatalf("%s status = %d, want 302", path, redirect.Code)
		}
		if got := redirect.Header().Get("Location"); got != "/ui/" {
			t.Fatalf("%s Location = %q", path, got)
		}
	}

	asset := doRequest(server, http.MethodGet, "/ui/assets/app-1a2b.js", remote, nil)
	if asset.Code != http.StatusOK || !strings.Contains(asset.Body.String(), "console.log") {
		t.Fatalf("asset status = %d body = %q", asset.Code, asset.Body.String())
	}
	if got := asset.Header().Get("Cache-Control"); !strings.Contains(got, "immutable") {
		t.Fatalf("asset Cache-Control = %q", got)
	}

	spa := doRequest(server, http.MethodGet, "/ui/activity", remote, nil)
	if spa.Code != http.StatusOK || !strings.Contains(spa.Body.String(), "dae ui") {
		t.Fatalf("spa fallback status = %d body = %q", spa.Code, spa.Body.String())
	}
	if got := spa.Header().Get("X-Native-UI-Fallback"); got != "index" {
		t.Fatalf("spa fallback marker = %q", got)
	}

	for _, path := range []string{"/ui/assets/missing-9f8e.js", "/ui/assets/", "/ui/../api/v1/runtime"} {
		missing := doRequest(server, http.MethodGet, path, remote, nil)
		if missing.Code != http.StatusNotFound {
			t.Fatalf("%s status = %d, want 404", path, missing.Code)
		}
		if strings.Contains(missing.Body.String(), "dae ui") {
			t.Fatalf("%s must not fall back to HTML", path)
		}
	}

	api := doRequest(server, http.MethodGet, "/api/v1/runtime", remote, nil)
	if api.Code != http.StatusUnauthorized {
		t.Fatalf("api status = %d, want 401: the UI being public must not unlock the API", api.Code)
	}
}

func TestUIHostCheckApplies(t *testing.T) {
	dir := newUITree(t)
	server := newTestServer(t, Config{AllowAnonymousLoopback: true, UI: dir}, fakeRuntimeProvider{runtime: testRuntime()})

	req := httptest.NewRequest(http.MethodGet, "/ui/", nil)
	req.Host = "evil.example"
	req.RemoteAddr = "127.0.0.1:1234"
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("ui host check status = %d, want 403", recorder.Code)
	}
}

func TestUIBrokenStillServes(t *testing.T) {
	logger, hook := test.NewNullLogger()
	dir := t.TempDir()
	server, err := NewServer(Config{UI: dir}, fakeRuntimeProvider{runtime: testRuntime()}, logger)
	if err != nil {
		t.Fatalf("a UI without index.html must not stop the listener: %v", err)
	}
	remote := "127.0.0.1:1234"

	warned := false
	for _, entry := range hook.AllEntries() {
		if entry.Level == logrus.WarnLevel && strings.Contains(entry.Message, "index.html") {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("an unusable UI directory must log a warning, got %#v", hook.AllEntries())
	}

	if got := doRequest(server, http.MethodGet, "/ui/", remote, nil); got.Code != http.StatusNotFound {
		t.Fatalf("/ui/ status = %d, want 404", got.Code)
	}
	redirect := doRequest(server, http.MethodGet, "/", remote, nil)
	if redirect.Code != http.StatusFound || redirect.Header().Get("Location") != "/ui/" {
		t.Fatalf("/ status = %d location = %q", redirect.Code, redirect.Header().Get("Location"))
	}
	// The API keeps working even though the UI does not exist.
	if got := doRequest(server, http.MethodGet, "/api", remote, nil); got.Code != http.StatusOK {
		t.Fatalf("/api status = %d", got.Code)
	}
}

func TestNonAPIPathsRedirectToUI(t *testing.T) {
	dir := newUITree(t)
	server := newTestServer(t, Config{Secret: "operator-token-123456", UI: dir}, fakeRuntimeProvider{runtime: testRuntime()})
	remote := "127.0.0.1:1234"

	for _, path := range []string{"/", "/activity", "/settings/backend", "/nothing/here"} {
		response := doRequest(server, http.MethodGet, path, remote, nil)
		if response.Code != http.StatusFound {
			t.Fatalf("%s status = %d, want 302 (never 401)", path, response.Code)
		}
		if got := response.Header().Get("Location"); got != "/ui/" {
			t.Fatalf("%s Location = %q", path, got)
		}
	}

	// API paths still authenticate.
	if got := doRequest(server, http.MethodGet, "/api/v1/runtime", remote, nil); got.Code != http.StatusUnauthorized {
		t.Fatalf("/api/v1/runtime status = %d, want 401", got.Code)
	}
	if got := doRequest(server, http.MethodGet, "/api", remote, nil); got.Code != http.StatusOK {
		t.Fatalf("/api status = %d, want the public discovery", got.Code)
	}
}

func TestNonAPIPathsWithoutUIAreNotFound(t *testing.T) {
	server := newTestServer(t, Config{Secret: "operator-token-123456"}, fakeRuntimeProvider{runtime: testRuntime()})
	remote := "127.0.0.1:1234"

	for _, path := range []string{"/", "/ui", "/ui/", "/activity"} {
		response := doRequest(server, http.MethodGet, path, remote, nil)
		if response.Code != http.StatusNotFound {
			t.Fatalf("%s status = %d, want 404 (never 401)", path, response.Code)
		}
	}
}

func TestVersionReportsBuildMetadata(t *testing.T) {
	server := newTestServer(t, Config{
		AllowAnonymousLoopback: true,
		EngineVersion:          "0.9.0-rc.9",
		BuildRevision:          "0123456789abcdef0123456789abcdef01234567",
		BuildTarget:            "linux/amd64",
		BuildBuiltAt:           "2026-10-30T12:00:00Z",
	}, fakeRuntimeProvider{runtime: testRuntime()})

	body := decodeJSON(t, doRequest(server, http.MethodGet, "/api/v1/version", "127.0.0.1:1234", nil))
	engine, ok := body["engine"].(map[string]any)
	if !ok || engine["version"] != "0.9.0-rc.9" {
		t.Fatalf("engine = %#v", body["engine"])
	}
	build, ok := body["build"].(map[string]any)
	if !ok {
		t.Fatalf("build missing: %#v", body)
	}
	for field, want := range map[string]any{
		"revision": "0123456789abcdef0123456789abcdef01234567",
		"target":   "linux/amd64",
		"built_at": "2026-10-30T12:00:00Z",
	} {
		if got := build[field]; got != want {
			t.Fatalf("build.%s = %v, want %v", field, got, want)
		}
	}

	// A build without VCS information still answers, with nulls.
	partial := newTestServer(t, Config{AllowAnonymousLoopback: true, BuildTarget: "linux/arm64"}, fakeRuntimeProvider{runtime: testRuntime()})
	partialBody := decodeJSON(t, doRequest(partial, http.MethodGet, "/api/v1/version", "127.0.0.1:1234", nil))
	partialBuild, ok := partialBody["build"].(map[string]any)
	if !ok {
		t.Fatalf("partial build missing: %#v", partialBody)
	}
	if partialBuild["revision"] != nil || partialBuild["built_at"] != nil {
		t.Fatalf("unknown fields must be null: %#v", partialBuild)
	}
	if partialBuild["target"] != "linux/arm64" {
		t.Fatalf("target = %v", partialBuild["target"])
	}

	// Without any build information the field is omitted entirely.
	plain := newTestServer(t, Config{AllowAnonymousLoopback: true}, fakeRuntimeProvider{runtime: testRuntime()})
	if _, exists := decodeJSON(t, doRequest(plain, http.MethodGet, "/api/v1/version", "127.0.0.1:1234", nil))["build"]; exists {
		t.Fatal("build must be omitted when nothing is known")
	}
}
