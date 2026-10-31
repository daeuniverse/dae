/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package nativeapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type fakeGroupProvider struct {
	summaries []GroupSummary
	group     *Group
	document  GroupConfigDocument
	revision  string

	selectionResult GroupSelectionResult
	setErr          error
	clearErr        error

	setGroupID    string
	setMemberID   string
	setNetwork    string
	clearGroupID  string
	clearNetwork  string
	getGroupID    string
	configGroupID string
}

func (p *fakeGroupProvider) ListGroups(ctx context.Context) ([]GroupSummary, error) {
	return p.summaries, nil
}

func (p *fakeGroupProvider) GetGroup(ctx context.Context, groupID string) (*Group, error) {
	p.getGroupID = groupID
	if p.group == nil || p.group.ID != groupID {
		return nil, NewAPIError(http.StatusNotFound, codeResourceNotFound, "group not found")
	}
	return p.group, nil
}

func (p *fakeGroupProvider) GetGroupConfig(ctx context.Context, groupID string) (GroupConfigDocument, string, error) {
	p.configGroupID = groupID
	return p.document, p.revision, nil
}

func (p *fakeGroupProvider) SetGroupSelection(ctx context.Context, groupID, memberID, network string) (GroupSelectionResult, error) {
	p.setGroupID, p.setMemberID, p.setNetwork = groupID, memberID, network
	if p.setErr != nil {
		return GroupSelectionResult{}, p.setErr
	}
	return p.selectionResult, nil
}

func (p *fakeGroupProvider) ClearGroupSelection(ctx context.Context, groupID, network string) (GroupOverrideCleared, error) {
	p.clearGroupID, p.clearNetwork = groupID, network
	if p.clearErr != nil {
		return GroupOverrideCleared{}, p.clearErr
	}
	return GroupOverrideCleared{}, nil
}

func testGroup() Group {
	return Group{
		ID:             "g_0123456789ab",
		Name:           "proxy",
		ConfigRevision: "rev-1",
		Policy:         GroupPolicy{Kind: "selector", Native: "select(0)"},
		Members: []GroupMember{
			{ID: "n_0123456789ab", Name: "hk-01", Kind: "node"},
		},
		Config: GroupConfig{XDae: &GroupConfigExtension{CheckAddresses: []string{}}},
		Runtime: GroupRuntime{
			Selection: GroupSelectionPair{},
			Health:    []GroupHealthObservation{},
		},
		Capabilities: GroupCapabilities{
			CanSelect:       true,
			MutableConfig:   []string{},
			ProbeTransports: []string{},
		},
	}
}

func newGroupTestServer(t *testing.T, provider *fakeGroupProvider) *Server {
	t.Helper()
	server := newTestServer(t, Config{AllowAnonymousLoopback: true}, fakeRuntimeProvider{runtime: testRuntime()})
	server.SetGroupProvider(provider)
	return server
}

func doRequestWithBody(server *Server, method, path, contentType, body string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Host = "127.0.0.1:9527"
	request.RemoteAddr = "127.0.0.1:1234"
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	return recorder
}

func TestGroupsListAndDetail(t *testing.T) {
	group := testGroup()
	provider := &fakeGroupProvider{
		summaries: []GroupSummary{{
			ID:             group.ID,
			Name:           group.Name,
			ConfigRevision: "rev-1",
			Policy:         group.Policy,
			MemberCount:    1,
			Selection:      GroupSummarySelection{},
		}},
		group: &group,
	}
	server := newGroupTestServer(t, provider)
	remote := "127.0.0.1:1234"

	list := doRequest(server, http.MethodGet, "/api/v1/groups", remote, nil)
	if list.Code != http.StatusOK {
		t.Fatalf("list status = %d: %s", list.Code, list.Body.String())
	}
	var summaries []map[string]any
	if err := json.Unmarshal(list.Body.Bytes(), &summaries); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(summaries) != 1 || summaries[0]["id"] != group.ID {
		t.Fatalf("summaries = %#v", summaries)
	}
	if _, ok := summaries[0]["selection"].(map[string]any)["tcp_member_id"]; !ok {
		t.Fatalf("summary selection must carry tcp_member_id: %#v", summaries[0])
	}

	detail := doRequest(server, http.MethodGet, "/api/v1/groups/"+group.ID, remote, nil)
	if detail.Code != http.StatusOK {
		t.Fatalf("detail status = %d: %s", detail.Code, detail.Body.String())
	}
	if provider.getGroupID != group.ID {
		t.Fatalf("group id passed to provider = %q", provider.getGroupID)
	}
	detailBody := decodeJSON(t, detail)
	capabilities := detailBody["capabilities"].(map[string]any)
	for _, key := range []string{"can_select", "can_override", "supports_nested_groups", "mutable_config", "probe_transports"} {
		if _, ok := capabilities[key]; !ok {
			t.Fatalf("capabilities missing %q: %#v", key, capabilities)
		}
	}

	missing := doRequest(server, http.MethodGet, "/api/v1/groups/unknown", remote, nil)
	if missing.Code != http.StatusNotFound {
		t.Fatalf("missing status = %d, want 404", missing.Code)
	}
}

func TestGroupConfigETagAndPatchCapability(t *testing.T) {
	provider := &fakeGroupProvider{
		document: GroupConfigDocument{Policy: GroupPolicy{Kind: "fixed", Native: "fixed(1)"}},
		revision: "rev-42",
	}
	server := newGroupTestServer(t, provider)
	remote := "127.0.0.1:1234"

	config := doRequest(server, http.MethodGet, "/api/v1/groups/g_1/config", remote, nil)
	if config.Code != http.StatusOK {
		t.Fatalf("config status = %d: %s", config.Code, config.Body.String())
	}
	if got, want := config.Header().Get("ETag"), `"rev-42"`; got != want {
		t.Fatalf("ETag = %q, want %q", got, want)
	}

	patch := doRequest(server, http.MethodPatch, "/api/v1/groups/g_1/config", remote, nil)
	if patch.Code != http.StatusNotFound {
		t.Fatalf("patch status = %d, want 404", patch.Code)
	}
	if got := decodeJSON(t, patch)["error"].(map[string]any)["code"]; got != codeCapabilityNotSupported {
		t.Fatalf("patch error code = %v", got)
	}
}

func TestGroupSelectionPut(t *testing.T) {
	provider := &fakeGroupProvider{
		selectionResult: GroupSelectionResult{
			GroupID:           "g_1",
			MemberID:          "n_1",
			Network:           "both",
			Source:            "runtime",
			SelectionRevision: "3",
		},
	}
	server := newGroupTestServer(t, provider)

	response := doRequestWithBody(server, http.MethodPut, "/api/v1/groups/g_1/selection", "application/json",
		`{"member_id":"n_1","network":"both"}`)
	if response.Code != http.StatusOK {
		t.Fatalf("put status = %d: %s", response.Code, response.Body.String())
	}
	if provider.setGroupID != "g_1" || provider.setMemberID != "n_1" || provider.setNetwork != "both" {
		t.Fatalf("provider call = %q %q %q", provider.setGroupID, provider.setMemberID, provider.setNetwork)
	}
	body := decodeJSON(t, response)
	if body["source"] != "runtime" || body["selection_revision"] != "3" {
		t.Fatalf("body = %#v", body)
	}
	if body["connections_interrupted"] != false {
		t.Fatalf("connections_interrupted = %v", body["connections_interrupted"])
	}

	missingType := doRequestWithBody(server, http.MethodPut, "/api/v1/groups/g_1/selection", "", `{"member_id":"n_1","network":"both"}`)
	if missingType.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("missing content-type status = %d, want 415", missingType.Code)
	}

	badNetwork := doRequestWithBody(server, http.MethodPut, "/api/v1/groups/g_1/selection", "application/json",
		`{"member_id":"n_1","network":"quic"}`)
	if badNetwork.Code != http.StatusBadRequest {
		t.Fatalf("bad network status = %d, want 400", badNetwork.Code)
	}

	unknownField := doRequestWithBody(server, http.MethodPut, "/api/v1/groups/g_1/selection", "application/json",
		`{"member_id":"n_1","network":"tcp","extra":true}`)
	if unknownField.Code != http.StatusBadRequest {
		t.Fatalf("unknown field status = %d, want 400", unknownField.Code)
	}
}

func TestGroupSelectionErrors(t *testing.T) {
	provider := &fakeGroupProvider{
		setErr:   NewAPIError(http.StatusUnprocessableEntity, codeUnsupportedValue, "policy cannot select"),
		clearErr: NewAPIError(http.StatusConflict, codeStateConflict, "selector keeps its choice"),
	}
	server := newGroupTestServer(t, provider)

	conflict := doRequestWithBody(server, http.MethodPut, "/api/v1/groups/g_1/selection", "application/json",
		`{"member_id":"n_1","network":"tcp"}`)
	if conflict.Code != http.StatusUnprocessableEntity {
		t.Fatalf("set status = %d, want 422", conflict.Code)
	}
	if got := decodeJSON(t, conflict)["error"].(map[string]any)["code"]; got != codeUnsupportedValue {
		t.Fatalf("set error code = %v", got)
	}

	deleteSelection := doRequest(server, http.MethodDelete, "/api/v1/groups/g_1/selection?network=udp", "127.0.0.1:1234", nil)
	if deleteSelection.Code != http.StatusConflict {
		t.Fatalf("delete status = %d, want 409", deleteSelection.Code)
	}
	if provider.clearGroupID != "g_1" || provider.clearNetwork != "udp" {
		t.Fatalf("clear call = %q %q", provider.clearGroupID, provider.clearNetwork)
	}

	badNetwork := doRequest(server, http.MethodDelete, "/api/v1/groups/g_1/selection?network=bogus", "127.0.0.1:1234", nil)
	if badNetwork.Code != http.StatusBadRequest {
		t.Fatalf("delete bad network status = %d, want 400", badNetwork.Code)
	}
}

func TestCapabilitiesAdvertiseImplementedResources(t *testing.T) {
	provider := &fakeGroupProvider{}
	server := newTestServer(t, Config{AllowAnonymousLoopback: true}, fakeRuntimeProvider{runtime: testRuntime()})
	server.SetGroupProvider(provider)
	server.SetTrafficHistoryProvider(&fakeTrafficProvider{})
	server.SetOperationProvider(newFakeOperationProvider())

	response := doRequest(server, http.MethodGet, "/api/v1/capabilities", "127.0.0.1:1234", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("capabilities status = %d", response.Code)
	}
	resources := decodeJSON(t, response)["resources"].(map[string]any)

	groups := resources["groups"].(map[string]any)
	if groups["available"] != true || groups["config_patch"] != false || groups["selection"] != true {
		t.Fatalf("groups capability = %#v", groups)
	}
	history := resources["traffic_history"].(map[string]any)
	if history["available"] != true || history["max_window_seconds"] != float64(MaxTrafficHistoryWindowSeconds) {
		t.Fatalf("traffic_history capability = %#v", history)
	}
	operations := resources["operations"].(map[string]any)
	if operations["available"] != true {
		t.Fatalf("operations capability = %#v", operations)
	}
	for _, key := range []string{"reload", "suspend", "resume"} {
		if resources[key].(map[string]any)["available"] != true {
			t.Fatalf("%s capability = %#v", key, resources[key])
		}
	}
}
