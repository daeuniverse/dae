/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package nativeapi

import (
	"net/http"
	"strconv"
	"strings"
)

func (s *Server) handleNodes(w http.ResponseWriter, r *http.Request) {
	requestID := requestIDFromContext(r.Context())
	if s.nodes == nil {
		writeError(w, requestID, http.StatusNotFound, codeCapabilityNotSupported, "resource is not supported by this engine")
		return
	}
	if r.Method == http.MethodPost {
		s.handleCreateNode(w, r)
		return
	}
	if !isReadMethod(r.Method) {
		writeMethodNotAllowed(w, requestID, "GET, HEAD, POST")
		return
	}
	query := r.URL.Query()
	limit, ok := parseBoundedPositiveInt(query.Get("limit"), NodeListDefaultLimit)
	if !ok || limit > NodeListMaxLimit {
		writeError(w, requestID, http.StatusBadRequest, codeInvalidRequest,
			"limit must be an integer in 1.."+strconv.Itoa(NodeListMaxLimit))
		return
	}
	page, err := s.nodes.ListNodes(r.Context(), query.Get("group_id"), limit, query.Get("cursor"))
	if err != nil {
		s.writeProviderFailure(w, requestID, err)
		return
	}
	if page.Nodes == nil {
		page.Nodes = []Node{}
	}
	writeJSON(w, http.StatusOK, page)
}

func (s *Server) handleNode(w http.ResponseWriter, r *http.Request) {
	requestID := requestIDFromContext(r.Context())
	if s.nodes == nil {
		writeError(w, requestID, http.StatusNotFound, codeCapabilityNotSupported, "resource is not supported by this engine")
		return
	}
	if r.Method == http.MethodPatch {
		s.handleUpdateNode(w, r)
		return
	}
	if r.Method == http.MethodDelete {
		s.handleDeleteNode(w, r)
		return
	}
	if !isReadMethod(r.Method) {
		writeMethodNotAllowed(w, requestID, "GET, HEAD, PATCH, DELETE")
		return
	}
	nodeID := strings.TrimPrefix(r.URL.Path, "/api/v1/nodes/")
	if nodeID == "" || strings.Contains(nodeID, "/") {
		writeError(w, requestID, http.StatusNotFound, codeResourceNotFound, "resource not found")
		return
	}
	node, err := s.nodes.GetNode(r.Context(), nodeID)
	if err != nil {
		s.writeProviderFailure(w, requestID, err)
		return
	}
	if node == nil {
		writeError(w, requestID, http.StatusNotFound, codeResourceNotFound, "node not found")
		return
	}
	writeJSON(w, http.StatusOK, node)
}

// handleCreateNode accepts one inline node. The engine writes it into the
// managed node source and reloads, so the answer is the queued operation.
func (s *Server) handleCreateNode(w http.ResponseWriter, r *http.Request) {
	requestID := requestIDFromContext(r.Context())
	if !s.nodes.NodeCapabilities().CanManage {
		writeError(w, requestID, http.StatusNotFound, codeCapabilityNotSupported, "node management is not supported by this engine")
		return
	}
	if !isJSONContentType(r.Header.Get("Content-Type")) {
		writeError(w, requestID, http.StatusUnsupportedMediaType, codeUnsupportedMediaType, "Content-Type must be application/json")
		return
	}
	var body struct {
		Name string `json:"name"`
		Link string `json:"link"`
	}
	if err := decodeLimitedJSON(r, s.cfg.MaxJSONBodyBytes, &body); err != nil {
		if err == errLimitedJSONBodyTooLarge {
			writeError(w, requestID, http.StatusRequestEntityTooLarge, codeInvalidRequest, "request body is too large")
			return
		}
		writeError(w, requestID, http.StatusBadRequest, codeInvalidRequest, "invalid JSON body: "+err.Error())
		return
	}
	if body.Name == "" || body.Link == "" {
		writeError(w, requestID, http.StatusBadRequest, codeInvalidRequest, "name and link are required")
		return
	}
	accepted, err := s.nodes.CreateNode(r.Context(), NodeCreateRequest{
		Name:           body.Name,
		Link:           body.Link,
		IdempotencyKey: r.Header.Get("Idempotency-Key"),
	})
	if err != nil {
		s.writeProviderFailure(w, requestID, err)
		return
	}
	writeAccepted(w, accepted)
}

// handleUpdateNode changes the name and/or link of one inline node. The engine
// rewrites the node's line in the managed node source and reloads, so the answer
// is the queued operation; a patch that names the values the node already has
// writes nothing and answers 200 with updated 0.
func (s *Server) handleUpdateNode(w http.ResponseWriter, r *http.Request) {
	requestID := requestIDFromContext(r.Context())
	nodeID := strings.TrimPrefix(r.URL.Path, "/api/v1/nodes/")
	if nodeID == "" || strings.Contains(nodeID, "/") {
		writeError(w, requestID, http.StatusNotFound, codeResourceNotFound, "resource not found")
		return
	}
	if !s.nodes.NodeCapabilities().CanManage {
		writeError(w, requestID, http.StatusNotFound, codeCapabilityNotSupported, "node management is not supported by this engine")
		return
	}
	if !isJSONContentType(r.Header.Get("Content-Type")) {
		writeError(w, requestID, http.StatusUnsupportedMediaType, codeUnsupportedMediaType, "Content-Type must be application/json")
		return
	}
	// Pointers separate "keep the current value" from an explicit empty value,
	// which the provider then rejects through its own validation.
	var body struct {
		Name *string `json:"name"`
		Link *string `json:"link"`
	}
	if err := decodeLimitedJSON(r, s.cfg.MaxJSONBodyBytes, &body); err != nil {
		if err == errLimitedJSONBodyTooLarge {
			writeError(w, requestID, http.StatusRequestEntityTooLarge, codeInvalidRequest, "request body is too large")
			return
		}
		writeError(w, requestID, http.StatusBadRequest, codeInvalidRequest, "invalid JSON body: "+err.Error())
		return
	}
	if body.Name == nil && body.Link == nil {
		writeError(w, requestID, http.StatusBadRequest, codeInvalidRequest, "name or link is required")
		return
	}
	outcome, err := s.nodes.UpdateNode(r.Context(), NodeUpdateRequest{
		NodeID:         nodeID,
		Name:           body.Name,
		Link:           body.Link,
		IdempotencyKey: r.Header.Get("Idempotency-Key"),
	})
	if err != nil {
		s.writeProviderFailure(w, requestID, err)
		return
	}
	if outcome.Updated == 0 {
		// The node already carries these values: no write, no reload.
		writeJSON(w, http.StatusOK, map[string]int{"updated": 0})
		return
	}
	writeAccepted(w, outcome.Accepted)
}

// handleDeleteNode removes one inline node. A node that a provider delivered is
// not the caller's to delete, so it answers like an unknown id.
func (s *Server) handleDeleteNode(w http.ResponseWriter, r *http.Request) {
	requestID := requestIDFromContext(r.Context())
	nodeID := strings.TrimPrefix(r.URL.Path, "/api/v1/nodes/")
	if nodeID == "" || strings.Contains(nodeID, "/") {
		writeError(w, requestID, http.StatusNotFound, codeResourceNotFound, "resource not found")
		return
	}
	if !s.nodes.NodeCapabilities().CanManage {
		writeError(w, requestID, http.StatusNotFound, codeCapabilityNotSupported, "node management is not supported by this engine")
		return
	}
	accepted, err := s.nodes.DeleteNode(r.Context(), NodeDeleteRequest{
		NodeID:         nodeID,
		IdempotencyKey: r.Header.Get("Idempotency-Key"),
	})
	if err != nil {
		s.writeProviderFailure(w, requestID, err)
		return
	}
	if accepted.Deleted == 0 {
		// Idempotent: the id names nothing in the managed node source.
		writeJSON(w, http.StatusOK, map[string]int{"deleted": 0})
		return
	}
	writeAccepted(w, accepted.Accepted)
}
