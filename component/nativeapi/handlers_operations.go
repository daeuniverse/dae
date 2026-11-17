/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package nativeapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
)

var (
	errUnsupportedMediaType = errors.New("Content-Type must be application/json")
	errInvalidJSONBody      = errors.New("invalid JSON body")
	errNonEmptyBody         = errors.New("the request body must be an empty object")
)

const operationPollRetryAfter = "1"

func (s *Server) handleStartOperation(w http.ResponseWriter, r *http.Request) {
	requestID := requestIDFromContext(r.Context())
	if s.operations == nil {
		writeError(w, requestID, http.StatusNotFound, codeCapabilityNotSupported, "resource is not supported by this engine")
		return
	}
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, requestID, "POST")
		return
	}
	kind := strings.TrimPrefix(r.URL.Path, "/api/v1/operations/")
	if err := validateEmptyJSONBody(r, s.cfg.MaxJSONBodyBytes); err != nil {
		if errors.Is(err, errUnsupportedMediaType) {
			writeError(w, requestID, http.StatusUnsupportedMediaType, codeUnsupportedMediaType, err.Error())
			return
		}
		if errors.Is(err, errLimitedJSONBodyTooLarge) {
			writeError(w, requestID, http.StatusRequestEntityTooLarge, codeInvalidRequest, "request body is too large")
			return
		}
		writeError(w, requestID, http.StatusBadRequest, codeInvalidRequest, err.Error())
		return
	}
	accepted, err := s.operations.StartOperation(r.Context(), kind, r.Method+" "+r.URL.Path, r.Header.Get("Idempotency-Key"))
	if err != nil {
		s.writeProviderFailure(w, requestID, err)
		return
	}
	writeAccepted(w, accepted)
}

// writeAccepted reports a queued operation with the headers every 202 carries.
func writeAccepted(w http.ResponseWriter, accepted OperationAccepted) {
	w.Header().Set("Location", accepted.Href)
	w.Header().Set("Retry-After", operationPollRetryAfter)
	writeJSON(w, http.StatusAccepted, accepted)
}

func (s *Server) handleOperation(w http.ResponseWriter, r *http.Request) {
	requestID := requestIDFromContext(r.Context())
	if s.operations == nil {
		writeError(w, requestID, http.StatusNotFound, codeCapabilityNotSupported, "resource is not supported by this engine")
		return
	}
	if !isReadMethod(r.Method) {
		writeMethodNotAllowed(w, requestID, "GET, HEAD")
		return
	}
	operationID := strings.TrimPrefix(r.URL.Path, "/api/v1/operations/")
	if operationID == "" || strings.Contains(operationID, "/") {
		writeError(w, requestID, http.StatusNotFound, codeResourceNotFound, "resource not found")
		return
	}
	operation, ok, err := s.operations.GetOperation(r.Context(), operationID)
	if err != nil {
		s.writeProviderFailure(w, requestID, err)
		return
	}
	if !ok {
		writeError(w, requestID, http.StatusNotFound, codeResourceNotFound, "operation not found")
		return
	}
	if operation.Status != OperationStatusSucceeded && operation.Status != OperationStatusFailed {
		w.Header().Set("Retry-After", operationPollRetryAfter)
	}
	writeJSON(w, http.StatusOK, operation)
}

// validateEmptyJSONBody accepts an absent body or the contract's empty object.
func validateEmptyJSONBody(r *http.Request, limit int) error {
	if r.Body == nil || r.ContentLength == 0 {
		return nil
	}
	if !isJSONContentType(r.Header.Get("Content-Type")) {
		return errUnsupportedMediaType
	}
	var body map[string]json.RawMessage
	if err := decodeLimitedJSON(r, limit, &body); err != nil {
		if errors.Is(err, errLimitedJSONBodyTooLarge) {
			return err
		}
		return errInvalidJSONBody
	}
	if len(body) != 0 {
		return errNonEmptyBody
	}
	return nil
}

func parseBoundedPositiveInt(raw string, fallback int) (int, bool) {
	if raw == "" {
		return fallback, true
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value <= 0 {
		return 0, false
	}
	return value, true
}
