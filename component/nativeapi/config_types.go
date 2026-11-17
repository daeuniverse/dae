/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package nativeapi

import (
	"context"
	"time"
)

// CodeStaleRevision is returned with 412 when If-Match does not match the
// stored source hash.
const CodeStaleRevision = "stale_revision"

// ConfigCapabilities describes the configuration resources a provider serves.
type ConfigCapabilities struct {
	// Writable reports whether control callers may replace editable sources.
	Writable   bool
	MaxBytes   int
	MaxSources int
	// Layout is "managed" or "unmanaged"; LayoutReason explains why writes are
	// unavailable when it is not empty.
	Layout       string
	LayoutReason string
	// HiddenSources lists source names that are never exposed by the API.
	HiddenSources []string
}

// ConfigSourceContent is one accepted source's identity and content.
type ConfigSourceContent struct {
	ID            string `json:"id"`
	Path          string `json:"path"`
	Kind          string `json:"kind"`
	ContentSHA256 string `json:"content_sha256"`
	Bytes         int    `json:"bytes"`
	Content       string `json:"content"`
	LineCount     int    `json:"line_count"`
}

// ConfigSource is an entry of GET /config.
type ConfigSource struct {
	ConfigSourceContent
	Writable bool `json:"writable"`
	// ReadOnlyReason explains why the source is not writable; empty when writable.
	ReadOnlyReason string    `json:"read_only_reason,omitempty"`
	LoadedAt       time.Time `json:"loaded_at"`
}

// ConfigDiagnostic is one diagnostic attached to a source.
type ConfigDiagnostic struct {
	Level    string `json:"level"`
	SourceID string `json:"source_id"`
	Line     *int   `json:"line"`
	Column   *int   `json:"column"`
	Span     any    `json:"span"`
	Code     string `json:"code"`
	Message  string `json:"message"`
}

// EffectiveConfig is the body of GET /config.
type EffectiveConfig struct {
	GenerationID    string             `json:"generation_id"`
	Revision        string             `json:"revision"`
	Sources         []ConfigSource     `json:"sources"`
	Diagnostics     []ConfigDiagnostic `json:"diagnostics"`
	SecretsRedacted bool               `json:"secrets_redacted"`
}

// ConfigValidationSource is one candidate source of POST /config/validate.
type ConfigValidationSource struct {
	ID      string  `json:"id,omitempty"`
	Path    string  `json:"path,omitempty"`
	Content *string `json:"content"`
}

// ConfigValidationRequest is the body of POST /config/validate.
type ConfigValidationRequest struct {
	Sources []ConfigValidationSource `json:"sources"`
	Mode    string                   `json:"mode"`
}

// ConfigValidationResult is the body of a validation response.
type ConfigValidationResult struct {
	Valid        bool               `json:"valid"`
	Diagnostics  []ConfigDiagnostic `json:"diagnostics"`
	GenerationID string             `json:"generation_id"`
	ValidatedAt  time.Time          `json:"validated_at"`
}

// ReplaceConfigSourceRequest carries a validated PUT to a provider. Size and
// JSON shape are checked by the handler; the provider owns the rest.
type ReplaceConfigSourceRequest struct {
	SourceID       string
	IfMatch        string
	IdempotencyKey string
	Content        string
}

// ConfigProvider serves the accepted configuration. Errors are returned as
// *APIError so handlers map them to contract responses.
type ConfigProvider interface {
	ConfigCapabilities() ConfigCapabilities
	GetConfig(ctx context.Context) (EffectiveConfig, error)
	// GetConfigSource returns the source and whether its content is complete
	// (no listener secret was masked), which decides whether an ETag is sent.
	GetConfigSource(ctx context.Context, sourceID string) (ConfigSourceContent, bool, error)
	ReplaceConfigSource(ctx context.Context, req ReplaceConfigSourceRequest) (OperationAccepted, error)
	ValidateConfig(ctx context.Context, req ConfigValidationRequest) (ConfigValidationResult, error)
}
