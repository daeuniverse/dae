/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package nativeapi

import (
	"net/http"
	"strings"
)

const (
	configPath         = "/api/v1/config"
	configValidatePath = "/api/v1/config/validate"
	configSourcesPath  = "/api/v1/config/sources"
	configSourcePrefix = "/api/v1/config/sources/"
)

func isConfigPath(path string) bool {
	return path == configPath || strings.HasPrefix(path, configPath+"/")
}

// handleConfig serves /api/v1/config/*. Without a provider every route
// answers capability_not_supported, matching the advertised capability.
func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	requestID := requestIDFromContext(r.Context())
	if s.config == nil {
		writeError(w, requestID, http.StatusNotFound, codeCapabilityNotSupported, "configuration readback is unavailable")
		return
	}

	switch path := r.URL.Path; {
	case path == configPath:
		if !isReadMethod(r.Method) {
			writeMethodNotAllowed(w, requestID, "GET, HEAD")
			return
		}
		doc, err := s.config.GetConfig(r.Context())
		if err != nil {
			s.writeProviderFailure(w, requestID, err)
			return
		}
		writeJSON(w, http.StatusOK, doc)

	case path == configValidatePath:
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, requestID, "POST")
			return
		}
		s.handleValidateConfig(w, r)

	case path == configSourcesPath:
		// Create (POST) is not implemented; the list route is not in the contract.
		if r.Method == http.MethodPost {
			writeError(w, requestID, http.StatusNotFound, codeCapabilityNotSupported, "configuration source creation is not supported by this engine")
			return
		}
		writeError(w, requestID, http.StatusMethodNotAllowed, codeMethodNotAllowed, "method is not allowed")

	case strings.HasPrefix(path, configSourcePrefix):
		sourceID := strings.TrimPrefix(path, configSourcePrefix)
		if sourceID == "" || strings.Contains(sourceID, "/") {
			writeError(w, requestID, http.StatusNotFound, codeResourceNotFound, "resource not found")
			return
		}
		switch r.Method {
		case http.MethodGet, http.MethodHead:
			s.handleGetConfigSource(w, r, sourceID)
		case http.MethodPut:
			s.handleReplaceConfigSource(w, r, sourceID)
		default:
			writeMethodNotAllowed(w, requestID, "GET, HEAD, PUT")
		}

	default:
		writeError(w, requestID, http.StatusNotFound, codeResourceNotFound, "resource not found")
	}
}

func (s *Server) handleGetConfigSource(w http.ResponseWriter, r *http.Request, sourceID string) {
	requestID := requestIDFromContext(r.Context())
	source, complete, err := s.config.GetConfigSource(r.Context(), sourceID)
	if err != nil {
		s.writeProviderFailure(w, requestID, err)
		return
	}
	// An ETag is only meaningful when the content is complete (not masked).
	if complete {
		w.Header().Set("ETag", `"`+source.ContentSHA256+`"`)
	}
	writeJSON(w, http.StatusOK, source)
}

func (s *Server) handleReplaceConfigSource(w http.ResponseWriter, r *http.Request, sourceID string) {
	requestID := requestIDFromContext(r.Context())
	caps := s.config.ConfigCapabilities()
	if !caps.Writable {
		writeError(w, requestID, http.StatusForbidden, codePermissionDenied, "configuration writes are disabled")
		return
	}
	// The request-boundary order is 428 before 415: a missing precondition is
	// reported whatever the body looks like.
	ifMatch := strings.TrimSpace(r.Header.Get("If-Match"))
	if ifMatch == "" {
		writeError(w, requestID, http.StatusPreconditionRequired, codePreconditionRequired, "If-Match is required")
		return
	}
	if !isJSONContentType(r.Header.Get("Content-Type")) {
		writeError(w, requestID, http.StatusUnsupportedMediaType, codeUnsupportedMediaType, "Content-Type must be application/json")
		return
	}
	var body struct {
		Content *string `json:"content"`
	}
	if err := decodeLimitedJSON(r, s.cfg.MaxJSONBodyBytes, &body); err != nil {
		if err == errLimitedJSONBodyTooLarge {
			writeError(w, requestID, http.StatusRequestEntityTooLarge, codeInvalidRequest, "request body is too large")
			return
		}
		writeError(w, requestID, http.StatusBadRequest, codeInvalidRequest, "invalid JSON body: "+err.Error())
		return
	}
	if body.Content == nil {
		writeError(w, requestID, http.StatusBadRequest, codeInvalidRequest, "content is required")
		return
	}
	if len(*body.Content) > caps.MaxBytes {
		writeError(w, requestID, http.StatusRequestEntityTooLarge, codeRequestTooLarge, "content is too large")
		return
	}
	accepted, err := s.config.ReplaceConfigSource(r.Context(), ReplaceConfigSourceRequest{
		SourceID:       sourceID,
		IfMatch:        strings.Trim(ifMatch, `"`),
		IdempotencyKey: r.Header.Get("Idempotency-Key"),
		Content:        *body.Content,
	})
	if err != nil {
		s.writeProviderFailure(w, requestID, err)
		return
	}
	w.Header().Set("Location", accepted.Href)
	w.Header().Set("Retry-After", operationPollRetryAfter)
	writeJSON(w, http.StatusAccepted, accepted)
}

func (s *Server) handleValidateConfig(w http.ResponseWriter, r *http.Request) {
	requestID := requestIDFromContext(r.Context())
	if !isJSONContentType(r.Header.Get("Content-Type")) {
		writeError(w, requestID, http.StatusUnsupportedMediaType, codeUnsupportedMediaType, "Content-Type must be application/json")
		return
	}
	var request ConfigValidationRequest
	if err := decodeLimitedJSON(r, s.cfg.MaxJSONBodyBytes, &request); err != nil {
		if err == errLimitedJSONBodyTooLarge {
			writeError(w, requestID, http.StatusRequestEntityTooLarge, codeInvalidRequest, "request body is too large")
			return
		}
		writeError(w, requestID, http.StatusBadRequest, codeInvalidRequest, "invalid JSON body: "+err.Error())
		return
	}
	if request.Mode == "" {
		writeError(w, requestID, http.StatusBadRequest, codeInvalidRequest, "mode is required")
		return
	}
	if request.Mode != "syntax" && request.Mode != "full" {
		writeError(w, requestID, http.StatusUnprocessableEntity, codeUnsupportedValue, "mode must be syntax or full")
		return
	}
	if len(request.Sources) == 0 {
		writeError(w, requestID, http.StatusBadRequest, codeInvalidRequest, "sources must not be empty")
		return
	}
	caps := s.config.ConfigCapabilities()
	if len(request.Sources) > caps.MaxSources {
		writeError(w, requestID, http.StatusRequestEntityTooLarge, codeRequestTooLarge, "too many sources")
		return
	}
	total := 0
	for _, source := range request.Sources {
		if source.Content == nil {
			writeError(w, requestID, http.StatusBadRequest, codeInvalidRequest, "each source requires content")
			return
		}
		// The contract bounds the sum of the candidate bytes, not each source alone.
		total += len(*source.Content)
		if total > caps.MaxBytes {
			writeError(w, requestID, http.StatusRequestEntityTooLarge, codeRequestTooLarge, "source bytes exceed max_bytes")
			return
		}
	}
	result, err := s.config.ValidateConfig(r.Context(), request)
	if err != nil {
		s.writeProviderFailure(w, requestID, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}
