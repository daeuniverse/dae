/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package nativeapi

import (
	"context"
	"net/http"
	"testing"
)

type fakeOutboundProvider struct {
	outbounds RuntimeOutbounds
	err       error
}

func (p fakeOutboundProvider) RuntimeOutbounds(ctx context.Context) (RuntimeOutbounds, error) {
	return p.outbounds, p.err
}

type fakeMemoryProvider struct {
	memory   RuntimeMemory
	history  MemoryHistory
	metrics  []string
	err      error
	lastWin  int
	lastPts  int
	callsHit int
}

func (p *fakeMemoryProvider) SnapshotMemory(ctx context.Context) (RuntimeMemory, error) {
	p.callsHit++
	return p.memory, p.err
}

func (p *fakeMemoryProvider) MemoryHistory(ctx context.Context, windowSeconds, maxPoints int) (MemoryHistory, error) {
	p.lastWin, p.lastPts = windowSeconds, maxPoints
	return p.history, p.err
}

func (p *fakeMemoryProvider) MemoryMetrics(ctx context.Context) []string {
	return p.metrics
}

type fakeDatapathProvider struct {
	datapath Datapath
	detail   string
	err      error
}

func (p *fakeDatapathProvider) SnapshotDatapath(ctx context.Context, detail string) (Datapath, error) {
	p.detail = detail
	return p.datapath, p.err
}

func withRuntimeProviders(server *Server) *fakeMemoryProvider {
	memory := &fakeMemoryProvider{
		memory: RuntimeMemory{ObservedAt: "2026-01-01T00:00:00Z"},
		history: MemoryHistory{
			ObservedAt:          "2026-01-01T00:00:00Z",
			WindowSeconds:       3600,
			SampledEverySeconds: 1,
		},
		metrics: []string{"process.rss_bytes"},
	}
	server.SetOutboundProvider(fakeOutboundProvider{outbounds: RuntimeOutbounds{
		ObservedAt:   "2026-01-01T00:00:00Z",
		CounterSince: "2026-01-01T00:00:00Z",
		Outbounds: []OutboundCounters{{
			Name:              "direct",
			Kind:              "builtin",
			ActiveConnections: 2,
			TotalConnections:  "3",
			UploadBytes:       "4",
			DownloadBytes:     "5",
			Errors:            "0",
		}},
	}})
	server.SetMemoryProvider(memory)
	server.SetDatapathProvider(&fakeDatapathProvider{datapath: Datapath{
		ObservedAt: "2026-01-01T00:00:00Z",
		Kind:       "ebpf",
		State:      "active",
		Visibility: "partial",
		Ebpf:       &EbpfDetail{},
	}})
	return memory
}

func TestRuntimeOutbounds(t *testing.T) {
	server := newTestServer(t, Config{AllowAnonymousLoopback: true}, fakeRuntimeProvider{runtime: testRuntime()})
	withRuntimeProviders(server)
	remote := "127.0.0.1:1234"

	response := doRequest(server, http.MethodGet, "/api/v1/runtime/outbounds", remote, nil)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", response.Code, response.Body.String())
	}
	body := decodeJSON(t, response)
	outbounds, ok := body["outbounds"].([]any)
	if !ok || len(outbounds) != 1 {
		t.Fatalf("outbounds = %#v", body["outbounds"])
	}
	first := outbounds[0].(map[string]any)
	if first["name"] != "direct" || first["kind"] != "builtin" {
		t.Fatalf("outbound = %#v", first)
	}
	if first["total_connections"] != "3" {
		t.Fatalf("total_connections = %#v, want string 3", first["total_connections"])
	}
	if first["active_connections"] != float64(2) {
		t.Fatalf("active_connections = %#v, want number 2", first["active_connections"])
	}

	method := doRequest(server, http.MethodPost, "/api/v1/runtime/outbounds", remote, nil)
	if method.Code != http.StatusMethodNotAllowed {
		t.Fatalf("method status = %d, want 405", method.Code)
	}
}

func TestRuntimeMemoryAndHistory(t *testing.T) {
	server := newTestServer(t, Config{AllowAnonymousLoopback: true}, fakeRuntimeProvider{runtime: testRuntime()})
	memory := withRuntimeProviders(server)
	remote := "127.0.0.1:1234"

	response := doRequest(server, http.MethodGet, "/api/v1/runtime/memory", remote, nil)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", response.Code, response.Body.String())
	}

	history := doRequest(server, http.MethodGet, "/api/v1/runtime/memory/history?window_seconds=60&max_points=30", remote, nil)
	if history.Code != http.StatusOK {
		t.Fatalf("history status = %d, want 200: %s", history.Code, history.Body.String())
	}
	if memory.lastWin != 60 || memory.lastPts != 30 {
		t.Fatalf("history query = (%d,%d), want (60,30)", memory.lastWin, memory.lastPts)
	}

	tooLarge := doRequest(server, http.MethodGet, "/api/v1/runtime/memory/history?window_seconds=3601", remote, nil)
	if tooLarge.Code != http.StatusBadRequest {
		t.Fatalf("oversized window status = %d, want 400", tooLarge.Code)
	}
	if body := decodeJSON(t, tooLarge); body["error"].(map[string]any)["code"] != codeInvalidRequest {
		t.Fatalf("error = %#v", body["error"])
	}
}

func TestDatapath(t *testing.T) {
	server := newTestServer(t, Config{AllowAnonymousLoopback: true}, fakeRuntimeProvider{runtime: testRuntime()})
	withRuntimeProviders(server)
	remote := "127.0.0.1:1234"

	response := doRequest(server, http.MethodGet, "/api/v1/datapath", remote, nil)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", response.Code, response.Body.String())
	}
	body := decodeJSON(t, response)
	if body["kind"] != "ebpf" || body["visibility"] != "partial" {
		t.Fatalf("datapath = %#v", body)
	}
	if errors, ok := body["errors"].([]any); !ok || len(errors) != 0 {
		t.Fatalf("errors = %#v, want empty array", body["errors"])
	}

	full := doRequest(server, http.MethodGet, "/api/v1/datapath?detail=full", remote, nil)
	if full.Code != http.StatusOK {
		t.Fatalf("full status = %d, want 200", full.Code)
	}
	if provider, ok := server.datapath.(*fakeDatapathProvider); !ok || provider.detail != "full" {
		t.Fatalf("detail not forwarded: %#v", server.datapath)
	}

	invalid := doRequest(server, http.MethodGet, "/api/v1/datapath?detail=bogus", remote, nil)
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("invalid detail status = %d, want 400", invalid.Code)
	}

	method := doRequest(server, http.MethodDelete, "/api/v1/datapath", remote, nil)
	if method.Code != http.StatusMethodNotAllowed {
		t.Fatalf("method status = %d, want 405", method.Code)
	}
}

func TestRuntimeCapabilitiesAdvertiseNewResources(t *testing.T) {
	server := newTestServer(t, Config{AllowAnonymousLoopback: true}, fakeRuntimeProvider{runtime: testRuntime()})
	withRuntimeProviders(server)
	remote := "127.0.0.1:1234"

	response := doRequest(server, http.MethodGet, "/api/v1/capabilities", remote, nil)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.Code)
	}
	body := decodeJSON(t, response)
	resources := body["resources"].(map[string]any)

	outbounds := resources["runtime_outbounds"].(map[string]any)
	if outbounds["available"] != true {
		t.Fatalf("runtime_outbounds = %#v", outbounds)
	}
	memory := resources["runtime_memory"].(map[string]any)
	if memory["available"] != true {
		t.Fatalf("runtime_memory = %#v", memory)
	}
	metrics := memory["metrics"].([]any)
	if len(metrics) != 1 || metrics[0] != "process.rss_bytes" {
		t.Fatalf("metrics = %#v", metrics)
	}
	history := resources["memory_history"].(map[string]any)
	if history["max_window_seconds"] != float64(MaxMemoryHistoryWindowSeconds) {
		t.Fatalf("memory_history = %#v", history)
	}
	datapath := resources["datapath"].(map[string]any)
	if datapath["available"] != true {
		t.Fatalf("datapath = %#v", datapath)
	}
}
