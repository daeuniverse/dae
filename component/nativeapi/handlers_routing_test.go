/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package nativeapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const validRoutingTraceBody = `{"input":{"network":"tcp","domain":"example.com","dst_ip":null,"dst_port":443}}`

type unavailableTraceRules struct{ fakeRules }

func (unavailableTraceRules) RoutingTraceAvailable() bool { return false }

func newRoutingTraceTestServer(t *testing.T) *Server {
	t.Helper()
	server := newTestServer(t, Config{AllowAnonymousLoopback: true}, fakeRuntimeProvider{runtime: testRuntime()})
	server.SetRulesProvider(fakeRules{})
	return server
}

func traceRequest(server *Server, body string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, "/api/v1/routing/trace", strings.NewReader(body))
	request.Host = "127.0.0.1:9527"
	request.RemoteAddr = "127.0.0.1:1234"
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	return recorder
}

func TestRoutingTraceHandler(t *testing.T) {
	server := newRoutingTraceTestServer(t)
	response := traceRequest(server, validRoutingTraceBody)
	if response.Code != http.StatusOK {
		t.Fatalf("trace status = %d: %s", response.Code, response.Body.String())
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q", response.Header().Get("Cache-Control"))
	}
	body := decodeJSON(t, response)
	if body["mode"] != "simulation" || body["generation_id"] != "1" {
		t.Fatalf("unexpected trace response: %#v", body)
	}
}

func TestRoutingTraceAvailabilityMatchesCapabilities(t *testing.T) {
	server := newTestServer(t, Config{AllowAnonymousLoopback: true}, fakeRuntimeProvider{runtime: testRuntime()})
	server.SetRulesProvider(unavailableTraceRules{})

	response := doRequest(server, http.MethodGet, "/api/v1/capabilities", "127.0.0.1:1234", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("capabilities status = %d: %s", response.Code, response.Body.String())
	}
	resources := decodeJSON(t, response)["resources"].(map[string]any)
	trace := resources["routing_trace"].(map[string]any)
	if trace["available"] != false {
		t.Fatalf("routing_trace capability = %#v", trace)
	}

	response = traceRequest(server, validRoutingTraceBody)
	if response.Code != http.StatusNotFound {
		t.Fatalf("unavailable trace status = %d, want 404: %s", response.Code, response.Body.String())
	}
	if decodeJSON(t, response)["error"].(map[string]any)["code"] != codeCapabilityNotSupported {
		t.Fatalf("unavailable trace error = %s", response.Body.String())
	}
}

func TestRoutingTraceRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "source port zero",
			body: `{"input":{"network":"tcp","domain":"example.com","dst_port":443,"src_port":0}}`,
		},
		{
			name: "DSCP out of range",
			body: `{"input":{"network":"tcp","domain":"example.com","dst_port":443,"dscp":64}}`,
		},
		{
			name: "live DNS resolution unsupported",
			body: `{"input":{"network":"tcp","domain":"example.com","dst_port":443},"resolve":"live"}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := traceRequest(newRoutingTraceTestServer(t), test.body)
			if response.Code != http.StatusBadRequest && response.Code != http.StatusUnprocessableEntity {
				t.Fatalf("status = %d, want 400 or 422: %s", response.Code, response.Body.String())
			}
		})
	}
}

func TestRoutingTraceRejectsOversizedAndTrailingJSON(t *testing.T) {
	server := newTestServer(t, Config{
		AllowAnonymousLoopback: true,
		MaxJSONBodyBytes:       16,
	}, fakeRuntimeProvider{runtime: testRuntime()})
	server.SetRulesProvider(fakeRules{})
	oversized := traceRequest(server, validRoutingTraceBody)
	if oversized.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body status = %d, want 413", oversized.Code)
	}

	server = newRoutingTraceTestServer(t)
	trailing := traceRequest(server, validRoutingTraceBody+` {}`)
	if trailing.Code != http.StatusBadRequest {
		t.Fatalf("trailing JSON status = %d, want 400: %s", trailing.Code, trailing.Body.String())
	}
}

func TestRoutingTraceRateLimiter(t *testing.T) {
	now := time.Date(2026, time.January, 2, 3, 4, 0, 0, time.UTC)
	var perPrincipal routingTraceRateLimiter
	for i := 0; i < routingTraceRequestsPerPrincipalPerMinute; i++ {
		if allowed, _ := perPrincipal.allow("caller", now); !allowed {
			t.Fatalf("request %d was unexpectedly limited", i+1)
		}
	}
	if allowed, retry := perPrincipal.allow("caller", now); allowed || retry != 60 {
		t.Fatalf("over-limit request = (%v, %d), want (false, 60)", allowed, retry)
	}
	if allowed, _ := perPrincipal.allow("caller", now.Add(time.Minute)); !allowed {
		t.Fatal("request should be allowed in the next window")
	}

	var global routingTraceRateLimiter
	for i := 0; i < routingTraceGlobalRequestsPerMinute; i++ {
		if allowed, _ := global.allow(string(rune(i+1)), now); !allowed {
			t.Fatalf("global request %d was unexpectedly limited", i+1)
		}
	}
	if allowed, _ := global.allow("next-caller", now); allowed {
		t.Fatal("request beyond the global limit was allowed")
	}
}

func TestRoutingTraceHandlerEnforcesRateLimit(t *testing.T) {
	server := newRoutingTraceTestServer(t)
	for i := 0; i < routingTraceRequestsPerPrincipalPerMinute; i++ {
		response := traceRequest(server, validRoutingTraceBody)
		if response.Code != http.StatusOK {
			t.Fatalf("request %d status = %d, want 200: %s", i+1, response.Code, response.Body.String())
		}
	}
	response := traceRequest(server, validRoutingTraceBody)
	if response.Code != http.StatusTooManyRequests {
		t.Fatalf("over-limit status = %d, want 429: %s", response.Code, response.Body.String())
	}
	if response.Header().Get("Retry-After") == "" {
		t.Fatal("rate-limited response has no Retry-After header")
	}
}
