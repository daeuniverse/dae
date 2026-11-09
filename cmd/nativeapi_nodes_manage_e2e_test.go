/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/component/nativeapi"
	"github.com/sirupsen/logrus"
)

// e2eRuntime is the runtime snapshot the endpoint tests never read.
type e2eRuntime struct{}

func (e2eRuntime) SnapshotRuntime(context.Context, string) (nativeapi.Runtime, error) {
	return nativeapi.Runtime{}, nil
}

// editorNodes serves nodes through the real config editor, so one HTTP request
// exercises the handler, the write admission and the file rewrite together.
type editorNodes struct {
	e     *configEditor
	index nodeIndexFunc
}

func (p *editorNodes) ListNodes(context.Context, string, int, string) (nativeapi.NodeList, error) {
	return nativeapi.NodeList{}, nil
}

func (p *editorNodes) GetNode(context.Context, string) (*nativeapi.Node, error) {
	return nil, &nativeapi.APIError{Status: 404, Code: "resource_not_found", Message: "node not found"}
}

func (p *editorNodes) NodeCapabilities() nativeapi.NodeCapabilities {
	return nativeapi.NodeCapabilities{CanManage: true}
}

func (p *editorNodes) CreateNode(ctx context.Context, req nativeapi.NodeCreateRequest) (nativeapi.OperationAccepted, error) {
	return p.e.CreateNode(ctx, req, p.index, nil)
}

func (p *editorNodes) UpdateNode(ctx context.Context, req nativeapi.NodeUpdateRequest) (nativeapi.NodeUpdateOutcome, error) {
	return p.e.UpdateNode(ctx, req, p.index, func(nodeID string) (any, error) { return nodeID, nil })
}

func (p *editorNodes) DeleteNode(ctx context.Context, req nativeapi.NodeDeleteRequest) (nativeapi.NodeDeleteOutcome, error) {
	return p.e.DeleteNode(ctx, req, p.index, nil)
}

// TestNodeEditFlowOverHTTP mirrors the dashboard's edit-node sequence: read the
// sources, validate the rewritten node block under a request-local id, then
// write the source back with its hash. The last step is what actually changes
// the node; the first two are the project's compatibility conditions.
func TestNodeEditFlowOverHTTP(t *testing.T) {
	main, _ := newManagedTree(t)
	ops := &fakeConfigOperations{}
	e := newFlowEditor(t, main, true, ops)
	target := flowSource(t, e, "config.d/node.dae")
	if _, err := e.CreateNode(context.Background(), nativeapi.NodeCreateRequest{Name: "mock-01", Link: mockLink}, emptyNodeIndex, nil); err != nil {
		t.Fatal(err)
	}
	ops.calls = 0

	server, err := nativeapi.NewServer(nativeapi.Config{
		Listen:                 "127.0.0.1:9527",
		AllowAnonymousLoopback: true,
	}, e2eRuntime{}, logrus.New())
	if err != nil {
		t.Fatal(err)
	}
	server.SetConfigProvider(e)
	call := func(method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Host = "127.0.0.1:9527"
		req.RemoteAddr = "127.0.0.1:50000"
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		for key, value := range headers {
			req.Header.Set(key, value)
		}
		rec := httptest.NewRecorder()
		server.ServeHTTP(rec, req)
		return rec
	}

	// 1. The dashboard locates the node in a writable source.
	configRec := call(http.MethodGet, "/api/v1/config", "", nil)
	if configRec.Code != http.StatusOK {
		t.Fatalf("GET /config = %d: %s", configRec.Code, configRec.Body.String())
	}
	var effective struct {
		Sources []struct {
			ID            string `json:"id"`
			Path          string `json:"path"`
			Kind          string `json:"kind"`
			Content       string `json:"content"`
			ContentSHA256 string `json:"content_sha256"`
			Writable      bool   `json:"writable"`
		} `json:"sources"`
	}
	if err := json.Unmarshal(configRec.Body.Bytes(), &effective); err != nil {
		t.Fatal(err)
	}
	var nodeSource struct {
		ID            string `json:"id"`
		Path          string `json:"path"`
		Kind          string `json:"kind"`
		Content       string `json:"content"`
		ContentSHA256 string `json:"content_sha256"`
		Writable      bool   `json:"writable"`
	}
	for _, source := range effective.Sources {
		if source.Path == "config.d/node.dae" {
			nodeSource.ID, nodeSource.Path, nodeSource.Kind = source.ID, source.Path, source.Kind
			nodeSource.Content, nodeSource.ContentSHA256, nodeSource.Writable = source.Content, source.ContentSHA256, source.Writable
		}
	}
	if nodeSource.ID == "" || !nodeSource.Writable {
		t.Fatalf("the node source should be listed and writable: %+v", effective.Sources)
	}

	// 2. The rewritten node block is validated under its own label.
	relinked := "socks5://user:pass@192.0.2.11:1080"
	block := "node {\n  mock-01: '" + relinked + "'\n}\n"
	validateBody, err := json.Marshal(map[string]any{
		"mode":    "syntax",
		"sources": []map[string]string{{"id": "node", "content": block}},
	})
	if err != nil {
		t.Fatal(err)
	}
	validateRec := call(http.MethodPost, "/api/v1/config/validate", string(validateBody), nil)
	if validateRec.Code != http.StatusOK {
		t.Fatalf("validate = %d: %s", validateRec.Code, validateRec.Body.String())
	}
	var validated struct {
		Valid bool `json:"valid"`
	}
	if err := json.Unmarshal(validateRec.Body.Bytes(), &validated); err != nil {
		t.Fatal(err)
	}
	if !validated.Valid {
		t.Fatalf("the rewritten node block should validate: %s", validateRec.Body.String())
	}

	// 3. The source is written back with the hash the dashboard read.
	updated := strings.Replace(nodeSource.Content, mockLink, relinked, 1)
	if updated == nodeSource.Content {
		t.Fatalf("the fixture does not carry the node link:\n%s", nodeSource.Content)
	}
	writeBody, err := json.Marshal(map[string]string{"content": updated})
	if err != nil {
		t.Fatal(err)
	}
	writeRec := call(http.MethodPut, "/api/v1/config/sources/"+nodeSource.ID, string(writeBody),
		map[string]string{"If-Match": nodeSource.ContentSHA256})
	if writeRec.Code != http.StatusAccepted {
		t.Fatalf("PUT source = %d: %s", writeRec.Code, writeRec.Body.String())
	}
	content, err := os.ReadFile(target.abs)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), relinked) {
		t.Fatalf("the edit did not reach the file:\n%s", content)
	}
	if ops.calls != 1 {
		t.Fatalf("StartOperation calls = %d, want 1", ops.calls)
	}
}

func TestPatchNodeEditsTheManagedFileOverHTTP(t *testing.T) {
	main, _ := newManagedTree(t)
	ops := &fakeConfigOperations{}
	e := newFlowEditor(t, main, true, ops)
	target := flowSource(t, e, "config.d/node.dae")
	if _, err := e.CreateNode(context.Background(), nativeapi.NodeCreateRequest{Name: "mock-01", Link: mockLink}, emptyNodeIndex, nil); err != nil {
		t.Fatal(err)
	}
	ops.calls = 0

	server, err := nativeapi.NewServer(nativeapi.Config{
		Listen:                 "127.0.0.1:9527",
		AllowAnonymousLoopback: true,
	}, e2eRuntime{}, logrus.New())
	if err != nil {
		t.Fatal(err)
	}
	server.SetNodeProvider(&editorNodes{
		e:     e,
		index: nodeIndexWith(map[string]nodeRef{"n_mock": {Name: "mock-01", ProviderID: inlineProviderID}}),
	})

	relinked := "socks5://user:pass@192.0.2.11:1080"
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/nodes/n_mock",
		strings.NewReader(`{"name":"mock-02","link":"`+relinked+`"}`))
	req.Host = "127.0.0.1:9527"
	req.RemoteAddr = "127.0.0.1:50000"
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"kind":"node_update"`) {
		t.Fatalf("body = %s", rec.Body.String())
	}
	content, err := os.ReadFile(target.abs)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), "mock-02: '"+relinked+"'") {
		t.Fatalf("the file was not edited:\n%s", content)
	}
	if ops.calls != 1 {
		t.Fatalf("StartOperation calls = %d, want 1", ops.calls)
	}
}
