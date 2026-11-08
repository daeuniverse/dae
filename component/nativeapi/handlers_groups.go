/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package nativeapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
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
			s.handlePatchGroupConfig(w, r, groupID)
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

func (s *Server) handlePatchGroupConfig(w http.ResponseWriter, r *http.Request, groupID string) {
	requestID := requestIDFromContext(r.Context())
	provider, ok := s.groups.(GroupConfigPatchCapabilities)
	if !ok || !provider.GroupConfigPatchAvailable() {
		writeError(w, requestID, http.StatusNotFound, codeCapabilityNotSupported, "group configuration patch is not supported by this engine")
		return
	}
	// The request-boundary order is 428 before 415/400/413: a missing
	// precondition is reported whatever the body looks like.
	if strings.TrimSpace(r.Header.Get("If-Match")) == "" {
		writeError(w, requestID, http.StatusPreconditionRequired, "precondition_required", "If-Match is required")
		return
	}
	if !isJSONPatchContentType(r.Header.Get("Content-Type")) {
		writeError(w, requestID, http.StatusUnsupportedMediaType, codeUnsupportedMediaType, "Content-Type must be application/json-patch+json")
		return
	}
	operations, err := decodeGroupConfigPatch(r, s.cfg.MaxJSONBodyBytes)
	if err != nil {
		if errors.Is(err, errGroupPatchTooLarge) {
			writeError(w, requestID, http.StatusRequestEntityTooLarge, codeInvalidRequest, "request body is too large")
			return
		}
		writeError(w, requestID, http.StatusBadRequest, codeInvalidRequest, "invalid JSON patch: "+err.Error())
		return
	}
	if len(operations) == 0 || len(operations) > MaxGroupPatchOperations {
		writeError(w, requestID, http.StatusBadRequest, codeInvalidRequest, fmt.Sprintf("patch must contain between 1 and %d operations", MaxGroupPatchOperations))
		return
	}
	document, revision, accepted, err := s.groups.PatchGroupConfig(r.Context(), groupID, GroupConfigPatchRequest{
		IfMatch:        r.Header.Get("If-Match"),
		IdempotencyKey: r.Header.Get("Idempotency-Key"),
		Operations:     operations,
	})
	if err != nil {
		s.writeProviderFailure(w, requestID, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if accepted != nil {
		w.Header().Set("Location", accepted.Href)
		w.Header().Set("Retry-After", operationPollRetryAfter)
		writeJSON(w, http.StatusAccepted, accepted)
		return
	}
	if revision != "" {
		w.Header().Set("ETag", `"`+revision+`"`)
	}
	writeJSON(w, http.StatusOK, document)
}

var errGroupPatchTooLarge = errors.New("request body is too large")
var errLimitedJSONBodyTooLarge = errors.New("request body is too large")

func decodeGroupConfigPatch(r *http.Request, limit int) ([]GroupConfigPatchOperation, error) {
	if r.Body == nil {
		return nil, errors.New("request body is required")
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(body) > limit {
		return nil, errGroupPatchTooLarge
	}
	var operations []GroupConfigPatchOperation
	if err := json.Unmarshal(body, &operations); err != nil {
		return nil, err
	}
	return operations, nil
}

func isJSONPatchContentType(value string) bool {
	mediaType := strings.ToLower(strings.TrimSpace(strings.SplitN(value, ";", 2)[0]))
	return mediaType == "application/json-patch+json"
}

func (s *Server) handlePutSelection(w http.ResponseWriter, r *http.Request, groupID string) {
	requestID := requestIDFromContext(r.Context())
	if !isJSONContentType(r.Header.Get("Content-Type")) {
		writeError(w, requestID, http.StatusUnsupportedMediaType, codeUnsupportedMediaType, "Content-Type must be application/json")
		return
	}
	var request GroupSelectionRequest
	if err := decodeLimitedJSON(r, s.cfg.MaxJSONBodyBytes, &request); err != nil {
		if err == errLimitedJSONBodyTooLarge {
			writeError(w, requestID, http.StatusRequestEntityTooLarge, codeInvalidRequest, "request body is too large")
			return
		}
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
	body, err := io.ReadAll(io.LimitReader(r.Body, int64(limit)+1))
	if err != nil {
		return err
	}
	if len(body) > limit {
		return errLimitedJSONBodyTooLarge
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	return decodeSingleJSON(decoder, target)
}

// decodeSingleJSON decodes one JSON value and refuses anything after it, so a
// body such as `{...}{...}` or `{...} junk` is not silently half-accepted.
func decodeSingleJSON(decoder *json.Decoder, target any) error {
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("unexpected trailing data")
		}
		return err
	}
	return nil
}

func (s *Server) writeProviderFailure(w http.ResponseWriter, requestID string, err error) {
	if writeProviderError(w, requestID, err) {
		return
	}
	writeError(w, requestID, http.StatusServiceUnavailable, codeTemporarilyUnavailable, "runtime state is unavailable")
}
