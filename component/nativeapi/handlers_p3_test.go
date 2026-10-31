/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package nativeapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type fakeRules struct{}

func (fakeRules) RoutingRules(context.Context) (RuleList, error) {
	return RuleList{
		GenerationID: "1",
		Rules: []RoutingRule{
			{RuleID: "traffic:0", Index: 0, Expression: "fallback: direct", Outbound: "direct", Kind: "fallback"},
		},
		Fallback: RuleFallback{Outbound: "direct"},
	}, nil
}

type fakeProviders struct{}

func (fakeProviders) ListProviders(context.Context, int, string) (ProviderList, error) {
	return ProviderList{Providers: []Provider{{ID: "p_a", Name: "a", Kind: "subscription", NodeCount: 1, Status: "ok"}}}, nil
}

func (fakeProviders) GetProvider(context.Context, string) (*Provider, error) {
	return &Provider{ID: "p_a", Name: "a", Kind: "subscription", NodeCount: 1, Status: "ok"}, nil
}

type fakeGeo struct{}

func (fakeGeo) GeoData(context.Context) (GeoData, error) {
	return GeoData{ObservedAt: "2026-01-01T00:00:00Z", Assets: []GeoAsset{{
		Kind: "geoip", SHA256: strings.Repeat("a", 64), SizeBytes: "10",
	}}}, nil
}

type fakeDns struct{}

func (fakeDns) DnsCache(context.Context, DnsCacheFilter) (DnsCacheList, error) {
	return DnsCacheList{ObservedAt: "2026-01-01T00:00:00Z", Total: 0}, nil
}

func (fakeDns) DeleteDnsCacheByName(context.Context, string, []string) (DeleteMatchingCount, error) {
	return DeleteMatchingCount{Matched: 1, Deleted: 1}, nil
}

func (fakeDns) DeleteDnsCacheEntry(context.Context, string) (DeleteCount, error) {
	return DeleteCount{Deleted: 1}, nil
}

func (fakeDns) FlushDnsCache(context.Context) (DeleteMatchingCount, error) {
	return DeleteMatchingCount{Matched: 2, Deleted: 2}, nil
}

func (fakeDns) DnsLog(context.Context, DnsLogFilter) (DnsLogList, error) {
	return DnsLogList{ObservedAt: "2026-01-01T00:00:00Z"}, nil
}

func (fakeDns) DnsRules(context.Context) (DnsRuleList, error) {
	return DnsRuleList{
		GenerationID: "1",
		Request:      []DnsRoutingRule{{RuleID: "r", Index: 0, Expression: "fallback: asis", Action: "asis", Kind: "fallback"}},
		Response:     []DnsRoutingRule{{RuleID: "s", Index: 0, Expression: "fallback: accept", Action: "accept", Kind: "fallback"}},
	}, nil
}

func (fakeDns) QueryDns(context.Context, DnsQueryRequest) (DnsQueryResponse, error) {
	return DnsQueryResponse{Domain: "example.com", CacheMode: "normal", QueryTime: "2026-01-01T00:00:00Z"}, nil
}

type fakeConnections struct{}

func (fakeConnections) ListConnections(context.Context, ConnectionFilter) (ConnectionList, error) {
	return ConnectionList{ObservedAt: "2026-01-01T00:00:00Z", InstanceID: "i", Visibility: "partial"}, nil
}

func (fakeConnections) CloseConnection(context.Context, string) error { return nil }

func (fakeConnections) CloseConnections(context.Context, ConnectionFilter, bool) (BulkCloseResult, error) {
	return BulkCloseResult{Closed: 1}, nil
}

type fakeFlows struct{}

func (fakeFlows) ListFlows(context.Context, FlowFilter) (FlowList, error) {
	return FlowList{InstanceID: "i", ObservedAt: "2026-01-01T00:00:00Z"}, nil
}

func (fakeFlows) GetFlow(context.Context, string) (*FlowDetail, error) {
	return &FlowDetail{
		FlowSummary: FlowSummary{ID: "f", InstanceID: "i", Revision: 1, Network: "tcp", State: "closed", TraceStatus: "disabled"},
		Input:       &FlowInput{DomainRuleIDs: []string{}},
		Trace:       &FlowTrace{Status: "disabled", Missing: []string{"not_instrumented"}, Steps: []any{}},
	}, nil
}

type fakeSSE struct {
	levels []string
	kinds  []string
}

func (f fakeSSE) OpenLogStream(context.Context, string, string, string) (*SSEStream, error) {
	ch := make(chan SSEFrame)
	close(ch)
	return &SSEStream{Ready: SSEFrame{ID: "logs:0", Event: "stream.ready", Data: StreamReadyEvent{InstanceID: "i"}}, Updates: ch, Cancel: func() {}}, nil
}

func (f fakeSSE) LogLevels() []string  { return f.levels }
func (f fakeSSE) LogFilters() []string { return []string{"level", "target"} }

func (f fakeSSE) OpenEventStream(context.Context, []string, string, string) (*SSEStream, error) {
	ch := make(chan SSEFrame)
	close(ch)
	return &SSEStream{Ready: SSEFrame{ID: "events:0", Event: "stream.ready", Data: StreamReadyEvent{InstanceID: "i"}}, Updates: ch, Cancel: func() {}}, nil
}

func (f fakeSSE) EventKinds() []string { return f.kinds }

type fakeProbes struct{}

func (fakeProbes) StartProbe(context.Context, ProbeRequest, string) (OperationAccepted, error) {
	return OperationAccepted{OperationID: "op-1", Kind: "probe", Status: "queued", Href: "/api/v1/operations/op-1"}, nil
}

func withP3Providers(server *Server) {
	server.SetRulesProvider(fakeRules{})
	server.SetProviderProvider(fakeProviders{})
	server.SetGeoDataProvider(fakeGeo{})
	server.SetDnsProvider(fakeDns{})
	server.SetConnectionProvider(fakeConnections{})
	server.SetFlowProvider(fakeFlows{})
	server.SetLogProvider(fakeSSE{levels: []string{"info"}})
	server.SetEventProvider(fakeSSE{kinds: []string{"stream.ready"}})
	server.SetProbeProvider(fakeProbes{})
}

func TestP3ReadEndpoints(t *testing.T) {
	server := newTestServer(t, Config{AllowAnonymousLoopback: true}, fakeRuntimeProvider{runtime: testRuntime()})
	withP3Providers(server)
	remote := "127.0.0.1:1234"

	for _, path := range []string{
		"/api/v1/rules",
		"/api/v1/providers",
		"/api/v1/providers/p_a",
		"/api/v1/geodata",
		"/api/v1/dns/cache",
		"/api/v1/dns/log",
		"/api/v1/dns/rules",
		"/api/v1/connections",
		"/api/v1/connections?type=tcp",
		"/api/v1/flows",
		"/api/v1/flows/f",
	} {
		response := doRequest(server, http.MethodGet, path, remote, nil)
		if response.Code != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200: %s", path, response.Code, response.Body.String())
		}
	}
}

func TestP3WriteEndpoints(t *testing.T) {
	server := newTestServer(t, Config{AllowAnonymousLoopback: true}, fakeRuntimeProvider{runtime: testRuntime()})
	withP3Providers(server)
	remote := "127.0.0.1:1234"

	cases := []struct {
		method, path string
		body         string
		want         int
	}{
		{http.MethodDelete, "/api/v1/dns/cache?name=example.com.", "", http.StatusOK},
		{http.MethodDelete, "/api/v1/dns/cache/de_1", "", http.StatusOK},
		{http.MethodDelete, "/api/v1/connections/c_1", "", http.StatusNoContent},
		{http.MethodDelete, "/api/v1/connections?all=true", "", http.StatusOK},
	}
	for _, tc := range cases {
		req := newRequestBody(tc.method, tc.path, tc.body)
		req.Host = "127.0.0.1:9527"
		req.RemoteAddr = remote
		recorder := serveRequest(server, req)
		if recorder.Code != tc.want {
			t.Fatalf("%s %s = %d, want %d: %s", tc.method, tc.path, recorder.Code, tc.want, recorder.Body.String())
		}
	}
}

func TestP3JSONEndpoints(t *testing.T) {
	server := newTestServer(t, Config{AllowAnonymousLoopback: true}, fakeRuntimeProvider{runtime: testRuntime()})
	withP3Providers(server)
	remote := "127.0.0.1:1234"

	probe := doJSONRequest(server, http.MethodPost, "/api/v1/probes",
		`{"target":{"type":"node","node_id":"n_1"},"kind":"tcp_connect","transport":["tcp"],"ip_version":"ipv4","warmth":"cold"}`, remote)
	if probe.Code != http.StatusAccepted {
		t.Fatalf("probe = %d, want 202: %s", probe.Code, probe.Body.String())
	}
	if probe.Header().Get("Location") == "" || probe.Header().Get("Retry-After") == "" {
		t.Fatal("202 response must carry Location and Retry-After")
	}

	query := doJSONRequest(server, http.MethodPost, "/api/v1/dns/query", `{"domain":"example.com"}`, remote)
	if query.Code != http.StatusOK {
		t.Fatalf("dns query = %d, want 200: %s", query.Code, query.Body.String())
	}

	flush := doJSONRequest(server, http.MethodPost, "/api/v1/dns/cache/flush", `{}`, remote)
	if flush.Code != http.StatusOK {
		t.Fatalf("flush = %d, want 200: %s", flush.Code, flush.Body.String())
	}
}

func TestP3Streams(t *testing.T) {
	server := newTestServer(t, Config{AllowAnonymousLoopback: true}, fakeRuntimeProvider{runtime: testRuntime()})
	withP3Providers(server)
	remote := "127.0.0.1:1234"

	logs := doRequest(server, http.MethodGet, "/api/v1/logs", remote, nil)
	if logs.Code != http.StatusOK || !strings.Contains(logs.Body.String(), "event: stream.ready") {
		t.Fatalf("logs = %d %q", logs.Code, logs.Body.String())
	}
	events := doRequest(server, http.MethodGet, "/api/v1/events", remote, nil)
	if events.Code != http.StatusOK || !strings.Contains(events.Body.String(), "event: stream.ready") {
		t.Fatalf("events = %d %q", events.Code, events.Body.String())
	}
}

// Provider refresh and geodata update are advertised as unavailable, so they
// must answer capability_not_supported rather than resource_not_found.
func TestP3UnavailableSubresources(t *testing.T) {
	server := newTestServer(t, Config{AllowAnonymousLoopback: true}, fakeRuntimeProvider{runtime: testRuntime()})
	withP3Providers(server)
	remote := "127.0.0.1:1234"

	cases := []struct{ method, path string }{
		{http.MethodPost, "/api/v1/providers/p_a/refresh"},
		{http.MethodPost, "/api/v1/geodata/update"},
	}
	for _, tc := range cases {
		response := doRequest(server, tc.method, tc.path, remote, nil)
		if response.Code != http.StatusNotFound {
			t.Fatalf("%s %s = %d, want 404: %s", tc.method, tc.path, response.Code, response.Body.String())
		}
		if got := decodeJSON(t, response)["error"].(map[string]any)["code"]; got != codeCapabilityNotSupported {
			t.Fatalf("%s %s error code = %v, want %s", tc.method, tc.path, got, codeCapabilityNotSupported)
		}
	}
}

func TestP3Capabilities(t *testing.T) {
	server := newTestServer(t, Config{AllowAnonymousLoopback: true}, fakeRuntimeProvider{runtime: testRuntime()})
	withP3Providers(server)
	response := doRequest(server, http.MethodGet, "/api/v1/capabilities", "127.0.0.1:1234", nil)
	body := decodeJSON(t, response)
	resources := body["resources"].(map[string]any)
	for _, name := range []string{"rules", "providers", "geodata", "dns_cache", "dns_log", "dns_rules", "dns_query", "connections", "flows", "logs", "events", "probes"} {
		resource, ok := resources[name].(map[string]any)
		if !ok || resource["available"] != true {
			t.Fatalf("%s = %#v, want available", name, resources[name])
		}
	}
	providers := resources["providers"].(map[string]any)
	if providers["can_refresh"] != false || providers["can_manage"] != false {
		t.Fatalf("providers = %#v", providers)
	}
}

func newRequestBody(method, path, body string) *http.Request {
	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}
	return httptest.NewRequest(method, path, reader)
}

func serveRequest(server *Server, req *http.Request) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, req)
	return recorder
}

func doJSONRequest(server *Server, method, path, body, remote string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Host = "127.0.0.1:9527"
	req.RemoteAddr = remote
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, req)
	return recorder
}

type capturingConnections struct {
	filter ConnectionFilter
}

func (c *capturingConnections) ListConnections(_ context.Context, filter ConnectionFilter) (ConnectionList, error) {
	c.filter = filter
	return ConnectionList{ObservedAt: "2026-01-01T00:00:00Z", InstanceID: "i", Visibility: "partial"}, nil
}

func (c *capturingConnections) CloseConnection(context.Context, string) error { return nil }

func (c *capturingConnections) CloseConnections(context.Context, ConnectionFilter, bool) (BulkCloseResult, error) {
	return BulkCloseResult{}, nil
}

type capturingDns struct {
	fakeDns
	filter DnsCacheFilter
	log    DnsLogFilter
}

func (c *capturingDns) DnsCache(_ context.Context, filter DnsCacheFilter) (DnsCacheList, error) {
	c.filter = filter
	return DnsCacheList{ObservedAt: "2026-01-01T00:00:00Z"}, nil
}

func (c *capturingDns) DnsLog(_ context.Context, filter DnsLogFilter) (DnsLogList, error) {
	c.log = filter
	return DnsLogList{ObservedAt: "2026-01-01T00:00:00Z"}, nil
}

func TestP3ListFiltersAndLimits(t *testing.T) {
	server := newTestServer(t, Config{AllowAnonymousLoopback: true}, fakeRuntimeProvider{runtime: testRuntime()})
	connections := &capturingConnections{}
	dns := &capturingDns{}
	server.SetConnectionProvider(connections)
	server.SetDnsProvider(dns)
	remote := "127.0.0.1:1234"

	recorder := doJSONRequest(server, http.MethodGet, "/api/v1/connections?type=all&src=10.0.0.1&limit=5", "", remote)
	if recorder.Code != http.StatusOK {
		t.Fatalf("connections status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	if connections.filter.Type != "" || connections.filter.Src != "10.0.0.1" || connections.filter.Limit != 5 {
		t.Fatalf("connection filter = %+v, want type=all src=10.0.0.1 limit=5", connections.filter)
	}

	for _, path := range []string{
		"/api/v1/connections?src=not-an-ip",
		"/api/v1/connections?limit=0",
		"/api/v1/connections?limit=1001",
		"/api/v1/dns/cache?limit=0",
		"/api/v1/dns/cache?limit=1001",
	} {
		if recorder := doJSONRequest(server, http.MethodGet, path, "", remote); recorder.Code != http.StatusBadRequest {
			t.Fatalf("%s status = %d, want 400", path, recorder.Code)
		}
	}

	recorder = doJSONRequest(server, http.MethodGet, "/api/v1/dns/cache?domain=example.com&limit=7&cursor=abc", "", remote)
	if recorder.Code != http.StatusOK {
		t.Fatalf("dns cache status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	if dns.filter.Limit != 7 || dns.filter.Cursor != "abc" || dns.filter.Domain != "example.com" {
		t.Fatalf("dns cache filter = %+v", dns.filter)
	}

	recorder = doJSONRequest(server, http.MethodGet, "/api/v1/dns/log?limit=3&name=example.com&type=A", "", remote)
	if recorder.Code != http.StatusOK {
		t.Fatalf("dns log status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	if dns.log.Limit != 3 || dns.log.Name != "example.com" || len(dns.log.Types) != 1 || dns.log.Types[0] != "A" {
		t.Fatalf("dns log filter = %+v", dns.log)
	}
}

func TestProviderErrorCarriesRetryAfter(t *testing.T) {
	server := newTestServer(t, Config{AllowAnonymousLoopback: true}, fakeRuntimeProvider{runtime: testRuntime()})
	server.SetProbeProvider(errorProbes{})
	recorder := doJSONRequest(server, http.MethodPost, "/api/v1/probes",
		`{"target":{"type":"node","node_id":"n"},"kind":"tcp_connect","transport":["tcp"],"ip_version":"ipv4","warmth":"cold"}`,
		"127.0.0.1:1234")
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", recorder.Code)
	}
	if got := recorder.Header().Get("Retry-After"); got != "1" {
		t.Fatalf("Retry-After = %q, want 1", got)
	}
}

type errorProbes struct{}

func (errorProbes) StartProbe(context.Context, ProbeRequest, string) (OperationAccepted, error) {
	return OperationAccepted{}, &APIError{Status: 503, Code: "temporarily_unavailable", Message: "probe queue is full", RetryAfterSeconds: 1}
}
