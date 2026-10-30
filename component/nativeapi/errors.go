/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package nativeapi

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

const (
	codeInvalidRequest         = "invalid_request"
	codeAuthenticationRequired = "authentication_required"
	codePermissionDenied       = "permission_denied"
	codeResourceNotFound       = "resource_not_found"
	codeCapabilityNotSupported = "capability_not_supported"
	codeMethodNotAllowed       = "method_not_allowed"
	codeStateConflict          = "state_conflict"
	codeIdempotencyConflict    = "idempotency_conflict"
	codePreconditionRequired   = "precondition_required"
	codeUnsupportedValue       = "unsupported_value"
	codeRequestTooLarge        = "request_too_large"
	codeUnsupportedMediaType   = "unsupported_media_type"
	codeTemporarilyUnavailable = "temporarily_unavailable"
)

func newRequestID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("req-%d", time.Now().UnixNano())
	}
	return "req-" + hex.EncodeToString(b[:])
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, requestID string, status int, code, message string) {
	recordErrorCode(w, code)
	writeJSON(w, status, ErrorResponse{
		Error: SafeError{
			Code:    code,
			Message: message,
		},
		RequestID: &requestID,
	})
}

func writeErrorDetails(w http.ResponseWriter, requestID string, status int, code, message string, details any) {
	recordErrorCode(w, code)
	writeJSON(w, status, ErrorResponse{
		Error: SafeError{
			Code:    code,
			Message: message,
			Details: details,
		},
		RequestID: &requestID,
	})
}

// APIError lets a provider choose the contract error a handler returns.
// Handlers translate it with writeProviderError so provider code never writes
// HTTP responses itself.
type APIError struct {
	Status  int
	Code    string
	Message string
	Details any
}

func (e *APIError) Error() string {
	if e == nil {
		return ""
	}
	return e.Message
}

// NewAPIError builds an error a handler can return verbatim.
func NewAPIError(status int, code, message string) *APIError {
	return &APIError{Status: status, Code: code, Message: message}
}

// writeProviderError writes err as an error envelope. It reports false when err
// is not an APIError, so the caller can fall back to a generic status.
func writeProviderError(w http.ResponseWriter, requestID string, err error) bool {
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr == nil {
		return false
	}
	status := apiErr.Status
	if status == 0 {
		status = http.StatusInternalServerError
	}
	code := apiErr.Code
	if code == "" {
		code = codeInvalidRequest
	}
	if apiErr.Details != nil {
		writeErrorDetails(w, requestID, status, code, apiErr.Message, apiErr.Details)
		return true
	}
	writeError(w, requestID, status, code, apiErr.Message)
	return true
}
