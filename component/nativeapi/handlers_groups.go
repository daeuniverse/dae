/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package nativeapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
)

const (
	groupNetworkTCP  = "tcp"
	groupNetworkUDP  = "udp"
	groupNetworkBoth = "both"
)

func (s *Server) handleGroups(w http.ResponseWriter, r *http.Request) {
	requestID := requestIDFromContext(r.Context())
	if s.groups == nil {
		writeError(w, requestID, http.StatusNotFound, codeCapabilityNotSupported, "resource is not supported by this engine")
		return
	}
	if !isReadMethod(r.Method) {
		writeMethodNotAllowed(w, requestID, "GET, HEAD")
		return
	}
	groups, err := s.groups.ListGroups(r.Context())
	if err != nil {
		s.writeProviderFailure(w, requestID, err)
		return
	}
	if groups == nil {
		groups = []GroupSummary{}
	}
	writeJSON(w, http.StatusOK, groups)
}

func (s *Server) handleGroup(w http.ResponseWriter, r *http.Request) {
	requestID := requestIDFromContext(r.Context())
	if s.groups == nil {
		writeError(w, requestID, http.StatusNotFound, codeCapabilityNotSupported, "resource is not supported by this engine")
		return
	}
	groupID, sub, ok := parseGroupSubresource(r.URL.Path)
	if !ok {
		writeError(w, requestID, http.StatusNotFound, codeResourceNotFound, "resource not found")
		return
	}

	switch sub {
	case "":
		if !isReadMethod(r.Method) {
			writeMethodNotAllowed(w, requestID, "GET, HEAD")
			return
		}
		group, err := s.groups.GetGroup(r.Context(), groupID)
		if err != nil {
			s.writeProviderFailure(w, requestID, err)
			return
		}
		if group == nil {
			writeError(w, requestID, http.StatusNotFound, codeResourceNotFound, "group not found")
			return
		}
		writeJSON(w, http.StatusOK, group)

	case "config":
		if r.Method == http.MethodPatch {
			// dae has no configuration write path; the capability document
			// advertises config_patch=false, so PATCH is a missing capability,
			// never a missing route or method.
			writeError(w, requestID, http.StatusNotFound, codeCapabilityNotSupported, "group configuration patch is not supported by this engine")
			return
		}
		if !isReadMethod(r.Method) {
			writeMethodNotAllowed(w, requestID, "GET, HEAD, PATCH")
			return
		}
		document, revision, err := s.groups.GetGroupConfig(r.Context(), groupID)
		if err != nil {
			s.writeProviderFailure(w, requestID, err)
			return
		}
		if revision != "" {
			w.Header().Set("ETag", `"`+revision+`"`)
		}
		writeJSON(w, http.StatusOK, document)

	case "selection":
		switch r.Method {
		case http.MethodPut:
			s.handlePutSelection(w, r, groupID)
		case http.MethodDelete:
			s.handleDeleteSelection(w, r, groupID)
		default:
			writeMethodNotAllowed(w, requestID, "PUT, DELETE")
		}

	default:
		writeError(w, requestID, http.StatusNotFound, codeResourceNotFound, "resource not found")
	}
}

func (s *Server) handlePutSelection(w http.ResponseWriter, r *http.Request, groupID string) {
	requestID := requestIDFromContext(r.Context())
	if !isJSONContentType(r.Header.Get("Content-Type")) {
		writeError(w, requestID, http.StatusUnsupportedMediaType, codeUnsupportedMediaType, "Content-Type must be application/json")
		return
	}
	var request GroupSelectionRequest
	if err := decodeLimitedJSON(r, s.cfg.MaxJSONBodyBytes, &request); err != nil {
		writeError(w, requestID, http.StatusBadRequest, codeInvalidRequest, "invalid JSON body: "+err.Error())
		return
	}
	if request.MemberID == "" {
		writeError(w, requestID, http.StatusBadRequest, codeInvalidRequest, "member_id is required")
		return
	}
	if !validSelectionNetwork(request.Network) {
		writeError(w, requestID, http.StatusBadRequest, codeInvalidRequest, "network must be tcp, udp or both")
		return
	}
	result, err := s.groups.SetGroupSelection(r.Context(), groupID, request.MemberID, request.Network)
	if err != nil {
		s.writeProviderFailure(w, requestID, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleDeleteSelection(w http.ResponseWriter, r *http.Request, groupID string) {
	requestID := requestIDFromContext(r.Context())
	network := r.URL.Query().Get("network")
	if network == "" {
		network = groupNetworkBoth
	}
	if !validSelectionNetwork(network) {
		writeError(w, requestID, http.StatusBadRequest, codeInvalidRequest, "network must be tcp, udp or both")
		return
	}
	cleared, err := s.groups.ClearGroupSelection(r.Context(), groupID, network)
	if err != nil {
		s.writeProviderFailure(w, requestID, err)
		return
	}
	writeJSON(w, http.StatusOK, cleared)
}

// parseGroupSubresource splits /api/v1/groups/{id}[/{config|selection}].
func parseGroupSubresource(path string) (groupID, sub string, ok bool) {
	rest := strings.TrimPrefix(path, "/api/v1/groups/")
	if rest == "" || rest == path {
		return "", "", false
	}
	parts := strings.Split(rest, "/")
	if len(parts) > 2 {
		return "", "", false
	}
	// r.URL.Path is already decoded, so the identifier is used verbatim.
	groupID = parts[0]
	if groupID == "" || strings.Contains(groupID, "/") {
		return "", "", false
	}
	if len(parts) == 2 {
		sub = parts[1]
	}
	return groupID, sub, true
}

func validSelectionNetwork(network string) bool {
	switch network {
	case groupNetworkTCP, groupNetworkUDP, groupNetworkBoth:
		return true
	default:
		return false
	}
}

func isJSONContentType(value string) bool {
	mediaType := strings.ToLower(strings.TrimSpace(strings.SplitN(value, ";", 2)[0]))
	return mediaType == "application/json"
}

func decodeLimitedJSON(r *http.Request, limit int, target any) error {
	if r.Body == nil {
		return errors.New("request body is required")
	}
	decoder := json.NewDecoder(io.LimitReader(r.Body, int64(limit)+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if decoder.More() {
		return errors.New("unexpected trailing data")
	}
	return nil
}

func (s *Server) writeProviderFailure(w http.ResponseWriter, requestID string, err error) {
	if writeProviderError(w, requestID, err) {
		return
	}
	writeError(w, requestID, http.StatusServiceUnavailable, codeTemporarilyUnavailable, "runtime state is unavailable")
}
