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

// managingNodes is a node provider whose inline nodes can be edited.
type managingNodes struct {
	canManage bool
	created   NodeCreateRequest
	updated   NodeUpdateRequest
	deleted   NodeDeleteRequest
	updateOut NodeUpdateOutcome
	outcome   NodeDeleteOutcome
	createErr error
	updateErr error
}

func (p *managingNodes) ListNodes(context.Context, string, int, string) (NodeList, error) {
	return NodeList{ObservedAt: "2026-01-01T00:00:00Z", Nodes: []Node{}}, nil
}

func (p *managingNodes) GetNode(context.Context, string) (*Node, error) {
	return nil, &APIError{Status: 404, Code: "resource_not_found", Message: "node not found"}
}

func (p *managingNodes) NodeCapabilities() NodeCapabilities {
	return NodeCapabilities{CanManage: p.canManage}
}

func (p *managingNodes) CreateNode(_ context.Context, req NodeCreateRequest) (OperationAccepted, error) {
	p.created = req
	if p.createErr != nil {
		return OperationAccepted{}, p.createErr
	}
	return OperationAccepted{OperationID: "op-node-1", Kind: OperationKindNodeCreate, Status: "queued", Href: "/api/v1/operations/op-node-1"}, nil
}

func (p *managingNodes) UpdateNode(_ context.Context, req NodeUpdateRequest) (NodeUpdateOutcome, error) {
	p.updated = req
	if p.updateErr != nil {
		return NodeUpdateOutcome{}, p.updateErr
	}
	return p.updateOut, nil
}

func (p *managingNodes) DeleteNode(_ context.Context, req NodeDeleteRequest) (NodeDeleteOutcome, error) {
	p.deleted = req
	return p.outcome, nil
}

// refreshingProviders is a provider provider that can refresh subscriptions.
type refreshingProviders struct {
	canRefresh bool
	refreshed  ProviderRefreshRequest
	err        error
}

func (p *refreshingProviders) ListProviders(context.Context, int, string) (ProviderList, error) {
	return ProviderList{Providers: []Provider{}}, nil
}

func (p *refreshingProviders) GetProvider(context.Context, string) (*Provider, error) {
	return &Provider{ID: "p_a", Name: "a", Kind: "subscription", Status: "ok"}, nil
}

func (p *refreshingProviders) ProviderCapabilities() ProviderCapabilities {
	return ProviderCapabilities{CanRefresh: p.canRefresh}
}

func (p *refreshingProviders) RefreshProvider(_ context.Context, req ProviderRefreshRequest) (OperationAccepted, error) {
	p.refreshed = req
	if p.err != nil {
		return OperationAccepted{}, p.err
	}
	return OperationAccepted{OperationID: "op-refresh-1", Kind: OperationKindProviderRefresh, Status: "queued", Href: "/api/v1/operations/op-refresh-1"}, nil
}

func newManageServer(t *testing.T, nodes NodeProvider, providers ProviderProvider) *Server {
	t.Helper()
	server := newTestServer(t, Config{AllowAnonymousLoopback: true}, fakeRuntimeProvider{})
	if nodes != nil {
		server.SetNodeProvider(nodes)
	}
	if providers != nil {
		server.SetProviderProvider(providers)
	}
	return server
}

func TestCreateNodeQueuesOperation(t *testing.T) {
	nodes := &managingNodes{canManage: true}
	server := newManageServer(t, nodes, nil)

	recorder := doConfigRequest(server, http.MethodPost, "/api/v1/nodes",
		`{"name":"mock-01","link":"socks5://192.0.2.10:1080"}`, map[string]string{"Idempotency-Key": "key-1"})
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202: %s", recorder.Code, recorder.Body.String())
	}
	if got := recorder.Header().Get("Location"); got != "/api/v1/operations/op-node-1" {
		t.Fatalf("Location = %q", got)
	}
	if got := recorder.Header().Get("Retry-After"); got != operationPollRetryAfter {
		t.Fatalf("Retry-After = %q", got)
	}
	if nodes.created.Name != "mock-01" || nodes.created.Link != "socks5://192.0.2.10:1080" || nodes.created.IdempotencyKey != "key-1" {
		t.Fatalf("forwarded request = %+v", nodes.created)
	}
}

func TestCreateNodeWithoutManagementAnswers404(t *testing.T) {
	server := newManageServer(t, &managingNodes{canManage: false}, nil)

	recorder := doConfigRequest(server, http.MethodPost, "/api/v1/nodes",
		`{"name":"mock-01","link":"socks5://192.0.2.10:1080"}`, nil)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", recorder.Code)
	}
	if code := errorCode(t, recorder); code != codeCapabilityNotSupported {
		t.Fatalf("code = %s", code)
	}
}

func TestCreateNodeRequiresNameAndLink(t *testing.T) {
	server := newManageServer(t, &managingNodes{canManage: true}, nil)

	recorder := doConfigRequest(server, http.MethodPost, "/api/v1/nodes", `{"name":"mock-01"}`, nil)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", recorder.Code)
	}
}

func TestCreateNodeRequiresJSON(t *testing.T) {
	server := newManageServer(t, &managingNodes{canManage: true}, nil)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/nodes", strings.NewReader(`{"name":"a","link":"b"}`))
	req.Host = "127.0.0.1:9527"
	req.RemoteAddr = "127.0.0.1:50000"
	req.Header.Set("Content-Type", "text/plain")
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("status = %d, want 415", recorder.Code)
	}
}

func TestDeleteNodeQueuesOperation(t *testing.T) {
	nodes := &managingNodes{
		canManage: true,
		outcome:   NodeDeleteOutcome{Deleted: 1, Accepted: OperationAccepted{OperationID: "op-1", Kind: OperationKindNodeDelete, Status: "queued", Href: "/api/v1/operations/op-1"}},
	}
	server := newManageServer(t, nodes, nil)

	recorder := doConfigRequest(server, http.MethodDelete, "/api/v1/nodes/n_mock", "", nil)
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202: %s", recorder.Code, recorder.Body.String())
	}
	if nodes.deleted.NodeID != "n_mock" {
		t.Fatalf("forwarded node id = %q", nodes.deleted.NodeID)
	}
}

func TestDeleteNodeIsIdempotentForUnknownID(t *testing.T) {
	nodes := &managingNodes{canManage: true, outcome: NodeDeleteOutcome{Deleted: 0}}
	server := newManageServer(t, nodes, nil)

	recorder := doConfigRequest(server, http.MethodDelete, "/api/v1/nodes/n_missing", "", nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	body := decodeJSON(t, recorder)
	if body["deleted"] != float64(0) {
		t.Fatalf("body = %v, want deleted 0", body)
	}
}

func TestDeleteNodeWithoutManagementAnswers404(t *testing.T) {
	server := newManageServer(t, &managingNodes{canManage: false}, nil)

	recorder := doConfigRequest(server, http.MethodDelete, "/api/v1/nodes/n_mock", "", nil)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", recorder.Code)
	}
}

func TestUpdateNodeQueuesOperation(t *testing.T) {
	nodes := &managingNodes{
		canManage: true,
		updateOut: NodeUpdateOutcome{Updated: 1, Accepted: OperationAccepted{
			OperationID: "op-node-2", Kind: OperationKindNodeUpdate, Status: "queued", Href: "/api/v1/operations/op-node-2",
		}},
	}
	server := newManageServer(t, nodes, nil)

	recorder := doConfigRequest(server, http.MethodPatch, "/api/v1/nodes/n_mock",
		`{"name":"mock-02","link":"socks5://192.0.2.11:1080"}`, map[string]string{"Idempotency-Key": "key-3"})
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202: %s", recorder.Code, recorder.Body.String())
	}
	if got := recorder.Header().Get("Location"); got != "/api/v1/operations/op-node-2" {
		t.Fatalf("Location = %q", got)
	}
	updated := nodes.updated
	if updated.NodeID != "n_mock" || updated.IdempotencyKey != "key-3" {
		t.Fatalf("forwarded request = %+v", updated)
	}
	if updated.Name == nil || *updated.Name != "mock-02" || updated.Link == nil || *updated.Link != "socks5://192.0.2.11:1080" {
		t.Fatalf("forwarded values = %+v", updated)
	}
}

func TestUpdateNodeKeepsOmittedFields(t *testing.T) {
	// A patch that only names a link must not invent a name: a nil field is
	// what tells the provider to keep the current value.
	nodes := &managingNodes{canManage: true, updateOut: NodeUpdateOutcome{Updated: 1}}
	server := newManageServer(t, nodes, nil)

	recorder := doConfigRequest(server, http.MethodPatch, "/api/v1/nodes/n_mock", `{"link":"socks5://192.0.2.11:1080"}`, nil)
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202: %s", recorder.Code, recorder.Body.String())
	}
	if nodes.updated.Name != nil {
		t.Fatalf("name = %q, want nil", *nodes.updated.Name)
	}
	if nodes.updated.Link == nil || *nodes.updated.Link != "socks5://192.0.2.11:1080" {
		t.Fatalf("link = %v", nodes.updated.Link)
	}
}

func TestUpdateNodeNoChangeAnswers200(t *testing.T) {
	nodes := &managingNodes{canManage: true, updateOut: NodeUpdateOutcome{Updated: 0}}
	server := newManageServer(t, nodes, nil)

	recorder := doConfigRequest(server, http.MethodPatch, "/api/v1/nodes/n_mock", `{"name":"mock-01"}`, nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	body := decodeJSON(t, recorder)
	if body["updated"] != float64(0) {
		t.Fatalf("body = %v, want updated 0", body)
	}
}

func TestUpdateNodeRequiresAField(t *testing.T) {
	server := newManageServer(t, &managingNodes{canManage: true}, nil)

	recorder := doConfigRequest(server, http.MethodPatch, "/api/v1/nodes/n_mock", `{}`, nil)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", recorder.Code)
	}
}

func TestUpdateNodeWithoutManagementAnswers404(t *testing.T) {
	server := newManageServer(t, &managingNodes{canManage: false}, nil)

	recorder := doConfigRequest(server, http.MethodPatch, "/api/v1/nodes/n_mock", `{"name":"mock-02"}`, nil)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", recorder.Code)
	}
	if code := errorCode(t, recorder); code != codeCapabilityNotSupported {
		t.Fatalf("code = %s", code)
	}
}

func TestUpdateNodeRequiresJSON(t *testing.T) {
	server := newManageServer(t, &managingNodes{canManage: true}, nil)

	req := httptest.NewRequest(http.MethodPatch, "/api/v1/nodes/n_mock", strings.NewReader(`{"name":"mock-02"}`))
	req.Host = "127.0.0.1:9527"
	req.RemoteAddr = "127.0.0.1:50000"
	req.Header.Set("Content-Type", "text/plain")
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("status = %d, want 415", recorder.Code)
	}
}

func TestRefreshProviderQueuesOperation(t *testing.T) {
	providers := &refreshingProviders{canRefresh: true}
	server := newManageServer(t, nil, providers)

	recorder := doConfigRequest(server, http.MethodPost, "/api/v1/providers/p_a/refresh", "", map[string]string{"Idempotency-Key": "key-2"})
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202: %s", recorder.Code, recorder.Body.String())
	}
	if providers.refreshed.ProviderID != "p_a" || providers.refreshed.IdempotencyKey != "key-2" {
		t.Fatalf("forwarded request = %+v", providers.refreshed)
	}
}

func TestRefreshProviderPropagatesCapabilityError(t *testing.T) {
	providers := &refreshingProviders{
		canRefresh: true,
		err:        &APIError{Status: 404, Code: "capability_not_supported", Message: "This provider cannot be refreshed"},
	}
	server := newManageServer(t, nil, providers)

	recorder := doConfigRequest(server, http.MethodPost, "/api/v1/providers/p_inline/refresh", "", nil)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", recorder.Code)
	}
	if code := errorCode(t, recorder); code != codeCapabilityNotSupported {
		t.Fatalf("code = %s", code)
	}
}

func TestRefreshProviderRejectsNonPost(t *testing.T) {
	server := newManageServer(t, nil, &refreshingProviders{canRefresh: true})

	recorder := doConfigRequest(server, http.MethodGet, "/api/v1/providers/p_a/refresh", "", nil)
	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", recorder.Code)
	}
}

func TestCapabilitiesReportNodeAndProviderManagement(t *testing.T) {
	server := newManageServer(t, &managingNodes{canManage: true}, &refreshingProviders{canRefresh: true})

	recorder := doConfigRequest(server, http.MethodGet, "/api/v1/capabilities", "", nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}
	body := decodeJSON(t, recorder)
	resources, _ := body["resources"].(map[string]any)
	nodes, _ := resources["nodes"].(map[string]any)
	if nodes["can_manage"] != true {
		t.Fatalf("nodes capability = %v, want can_manage true", nodes)
	}
	providers, _ := resources["providers"].(map[string]any)
	if providers["can_refresh"] != true {
		t.Fatalf("providers capability = %v, want can_refresh true", providers)
	}
}
