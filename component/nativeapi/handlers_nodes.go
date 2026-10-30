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
	if r.Method == http.MethodPost || r.Method == http.MethodDelete {
		// Not a missing route: this engine has no managed configuration to
		// write into, which the capability document states as can_manage=false.
		writeError(w, requestID, http.StatusNotFound, codeCapabilityNotSupported, "node management is not supported by this engine")
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
	if r.Method == http.MethodDelete {
		writeError(w, requestID, http.StatusNotFound, codeCapabilityNotSupported, "node management is not supported by this engine")
		return
	}
	if !isReadMethod(r.Method) {
		writeMethodNotAllowed(w, requestID, "GET, HEAD, DELETE")
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
