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

type fakeNodeProvider struct {
	nodes []Node
	page  NodeList
	err   error

	groupID string
	limit   int
	cursor  string
	nodeID  string
}

func (p *fakeNodeProvider) ListNodes(ctx context.Context, groupID string, limit int, cursor string) (NodeList, error) {
	p.groupID, p.limit, p.cursor = groupID, limit, cursor
	if p.err != nil {
		return NodeList{}, p.err
	}
	if p.page.Nodes == nil {
		return NodeList{ObservedAt: "2026-01-01T00:00:00Z", Nodes: p.nodes}, nil
	}
	return p.page, nil
}

func (p *fakeNodeProvider) GetNode(ctx context.Context, nodeID string) (*Node, error) {
	p.nodeID = nodeID
	if p.err != nil {
		return nil, p.err
	}
	for i := range p.nodes {
		if p.nodes[i].ID == nodeID {
			node := p.nodes[i]
			return &node, nil
		}
	}
	return nil, nil
}

func newNodesTestServer(t *testing.T, provider *fakeNodeProvider) *Server {
	t.Helper()
	server := newTestServer(t, Config{AllowAnonymousLoopback: true}, fakeRuntimeProvider{runtime: testRuntime()})
	server.SetNodeProvider(provider)
	return server
}

func TestNodesListAndDetail(t *testing.T) {
	protocol := "ss"
	tag := "my_sub"
	health := HealthObservation{
		Transport:    "tcp",
		Purpose:      "shared",
		IpVersion:    "ipv4",
		Warmth:       "unknown",
		Measurement:  "http_headers",
		SampleSource: "probe",
		State:        "healthy",
		ObservedAt:   "2026-01-01T00:00:00Z",
	}
	provider := &fakeNodeProvider{nodes: []Node{
		{ID: "n_1", Name: "hk-01", Protocol: &protocol, SubscriptionTag: &tag, GroupIDs: []string{"g_1"}, Health: []HealthObservation{health}},
		{ID: "n_2", Name: "jp-01", GroupIDs: []string{}, Health: []HealthObservation{}},
	}}
	server := newNodesTestServer(t, provider)
	remote := "127.0.0.1:1234"

	list := doRequest(server, http.MethodGet, "/api/v1/nodes?limit=50&group_id=g_1", remote, nil)
	if list.Code != http.StatusOK {
		t.Fatalf("list status = %d: %s", list.Code, list.Body.String())
	}
	if provider.limit != 50 || provider.groupID != "g_1" {
		t.Fatalf("provider call = limit %d group %q", provider.limit, provider.groupID)
	}
	body := decodeJSON(t, list)
	nodes := body["nodes"].([]any)
	if len(nodes) != 2 {
		t.Fatalf("nodes = %#v", nodes)
	}
	first := nodes[0].(map[string]any)
	for _, key := range []string{"id", "name", "protocol", "subscription_tag", "group_ids", "health"} {
		if _, ok := first[key]; !ok {
			t.Fatalf("node missing %q: %#v", key, first)
		}
	}
	if _, ok := body["next_cursor"]; !ok {
		t.Fatalf("next_cursor must be present: %#v", body)
	}

	detail := doRequest(server, http.MethodGet, "/api/v1/nodes/n_2", remote, nil)
	if detail.Code != http.StatusOK {
		t.Fatalf("detail status = %d: %s", detail.Code, detail.Body.String())
	}
	if provider.nodeID != "n_2" {
		t.Fatalf("node id = %q", provider.nodeID)
	}
	if got := decodeJSON(t, detail)["id"]; got != "n_2" {
		t.Fatalf("detail id = %v", got)
	}

	missing := doRequest(server, http.MethodGet, "/api/v1/nodes/n_missing", remote, nil)
	if missing.Code != http.StatusNotFound {
		t.Fatalf("missing status = %d, want 404", missing.Code)
	}
	if got := decodeJSON(t, missing)["error"].(map[string]any)["code"]; got != codeResourceNotFound {
		t.Fatalf("missing error code = %v", got)
	}
}

func TestNodesPaginationParameters(t *testing.T) {
	next := "abc"
	provider := &fakeNodeProvider{page: NodeList{
		ObservedAt: "2026-01-01T00:00:00Z",
		Nodes:      []Node{{ID: "n_1", Name: "hk-01", GroupIDs: []string{}, Health: []HealthObservation{}}},
		NextCursor: &next,
	}}
	server := newNodesTestServer(t, provider)
	remote := "127.0.0.1:1234"

	response := doRequest(server, http.MethodGet, "/api/v1/nodes?cursor="+next, remote, nil)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", response.Code, response.Body.String())
	}
	if provider.cursor != next {
		t.Fatalf("cursor = %q", provider.cursor)
	}
	if provider.limit != NodeListDefaultLimit {
		t.Fatalf("default limit = %d", provider.limit)
	}
	if got := decodeJSON(t, response)["next_cursor"]; got != next {
		t.Fatalf("next_cursor = %v", got)
	}

	for _, query := range []string{"limit=0", "limit=1001", "limit=abc"} {
		bad := doRequest(server, http.MethodGet, "/api/v1/nodes?"+query, remote, nil)
		if bad.Code != http.StatusBadRequest {
			t.Fatalf("%s status = %d, want 400", query, bad.Code)
		}
	}

	provider.err = NewAPIError(http.StatusGone, "snapshot_expired", "cursor expired")
	expired := doRequest(server, http.MethodGet, "/api/v1/nodes?cursor=stale", remote, nil)
	if expired.Code != http.StatusGone {
		t.Fatalf("expired cursor status = %d, want 410", expired.Code)
	}
}

func TestNodesManagementIsNotSupported(t *testing.T) {
	provider := &fakeNodeProvider{}
	server := newNodesTestServer(t, provider)
	remote := "127.0.0.1:1234"

	for _, request := range []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/api/v1/nodes"},
		{http.MethodDelete, "/api/v1/nodes/n_1"},
	} {
		response := doRequest(server, request.method, request.path, remote, nil)
		if response.Code != http.StatusNotFound {
			t.Fatalf("%s %s status = %d, want 404", request.method, request.path, response.Code)
		}
		if got := decodeJSON(t, response)["error"].(map[string]any)["code"]; got != codeCapabilityNotSupported {
			t.Fatalf("%s %s error code = %v", request.method, request.path, got)
		}
	}
}

func TestNodesUnavailableWithoutProvider(t *testing.T) {
	server := newTestServer(t, Config{AllowAnonymousLoopback: true}, fakeRuntimeProvider{runtime: testRuntime()})
	remote := "127.0.0.1:1234"

	response := doRequest(server, http.MethodGet, "/api/v1/nodes", remote, nil)
	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", response.Code)
	}
	if got := decodeJSON(t, response)["error"].(map[string]any)["code"]; got != codeCapabilityNotSupported {
		t.Fatalf("error code = %v", got)
	}

	capabilities := doRequest(server, http.MethodGet, "/api/v1/capabilities", remote, nil)
	resources := decodeJSON(t, capabilities)["resources"].(map[string]any)
	if resources["nodes"].(map[string]any)["available"] != false {
		t.Fatalf("nodes capability = %#v", resources["nodes"])
	}
}

func TestNodesCapability(t *testing.T) {
	provider := &fakeNodeProvider{}
	server := newNodesTestServer(t, provider)

	response := doRequest(server, http.MethodGet, "/api/v1/capabilities", "127.0.0.1:1234", nil)
	nodes := decodeJSON(t, response)["resources"].(map[string]any)["nodes"].(map[string]any)
	if nodes["available"] != true || nodes["can_manage"] != false {
		t.Fatalf("nodes capability = %#v", nodes)
	}
}
