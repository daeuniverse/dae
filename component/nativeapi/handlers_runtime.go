/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package nativeapi

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

func (s *Server) handleRuntimeOutbounds(w http.ResponseWriter, r *http.Request) {
	requestID := requestIDFromContext(r.Context())
	if s.outbounds == nil {
		writeError(w, requestID, http.StatusNotFound, codeCapabilityNotSupported, "resource is not supported by this engine")
		return
	}
	if !isReadMethod(r.Method) {
		writeMethodNotAllowed(w, requestID, "GET, HEAD")
		return
	}
	outbounds, err := s.outbounds.RuntimeOutbounds(r.Context())
	if err != nil {
		s.writeProviderFailure(w, requestID, err)
		return
	}
	if outbounds.ObservedAt == "" {
		outbounds.ObservedAt = time.Now().UTC().Format(time.RFC3339)
	}
	if outbounds.Outbounds == nil {
		outbounds.Outbounds = []OutboundCounters{}
	}
	writeJSON(w, http.StatusOK, outbounds)
}

func (s *Server) handleRuntimeMemory(w http.ResponseWriter, r *http.Request) {
	requestID := requestIDFromContext(r.Context())
	if s.memory == nil {
		writeError(w, requestID, http.StatusNotFound, codeCapabilityNotSupported, "resource is not supported by this engine")
		return
	}
	if !isReadMethod(r.Method) {
		writeMethodNotAllowed(w, requestID, "GET, HEAD")
		return
	}
	memory, err := s.memory.SnapshotMemory(r.Context())
	if err != nil {
		s.writeProviderFailure(w, requestID, err)
		return
	}
	if memory.ObservedAt == "" {
		memory.ObservedAt = time.Now().UTC().Format(time.RFC3339)
	}
	writeJSON(w, http.StatusOK, memory)
}

func (s *Server) handleMemoryHistory(w http.ResponseWriter, r *http.Request) {
	requestID := requestIDFromContext(r.Context())
	if s.memory == nil {
		writeError(w, requestID, http.StatusNotFound, codeCapabilityNotSupported, "resource is not supported by this engine")
		return
	}
	if !isReadMethod(r.Method) {
		writeMethodNotAllowed(w, requestID, "GET, HEAD")
		return
	}
	query := r.URL.Query()
	windowSeconds, ok := parseBoundedPositiveInt(query.Get("window_seconds"), DefaultMemoryHistoryWindow)
	if !ok || windowSeconds > MaxMemoryHistoryWindowSeconds {
		writeError(w, requestID, http.StatusBadRequest, codeInvalidRequest,
			"window_seconds must be an integer in 1.."+strconv.Itoa(MaxMemoryHistoryWindowSeconds))
		return
	}
	maxPoints, ok := parseBoundedPositiveInt(query.Get("max_points"), DefaultMemoryHistoryPoints)
	if !ok || maxPoints > MaxMemoryHistoryPoints {
		writeError(w, requestID, http.StatusBadRequest, codeInvalidRequest,
			"max_points must be an integer in 1.."+strconv.Itoa(MaxMemoryHistoryPoints))
		return
	}
	history, err := s.memory.MemoryHistory(r.Context(), windowSeconds, maxPoints)
	if err != nil {
		s.writeProviderFailure(w, requestID, err)
		return
	}
	if history.ObservedAt == "" {
		history.ObservedAt = time.Now().UTC().Format(time.RFC3339)
	}
	if history.Samples == nil {
		history.Samples = []MemoryHistorySample{}
	}
	writeJSON(w, http.StatusOK, history)
}

func (s *Server) handleDatapath(w http.ResponseWriter, r *http.Request) {
	requestID := requestIDFromContext(r.Context())
	if s.datapath == nil {
		writeError(w, requestID, http.StatusNotFound, codeCapabilityNotSupported, "resource is not supported by this engine")
		return
	}
	if !isReadMethod(r.Method) {
		writeMethodNotAllowed(w, requestID, "GET, HEAD")
		return
	}
	detail := r.URL.Query().Get("detail")
	if detail == "" {
		detail = "summary"
	}
	if detail != "summary" && detail != "full" {
		writeError(w, requestID, http.StatusBadRequest, codeInvalidRequest, "detail must be summary or full")
		return
	}
	datapath, err := s.datapath.SnapshotDatapath(r.Context(), detail)
	if err != nil {
		s.writeProviderFailure(w, requestID, err)
		return
	}
	if datapath.ObservedAt == "" {
		datapath.ObservedAt = time.Now().UTC().Format(time.RFC3339)
	}
	if datapath.Errors == nil {
		datapath.Errors = []SafeError{}
	}
	writeJSON(w, http.StatusOK, datapath)
}

func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	requestID := requestIDFromContext(r.Context())
	if s.rules == nil {
		writeError(w, requestID, http.StatusNotFound, codeCapabilityNotSupported, "resource is not supported by this engine")
		return
	}
	if !isReadMethod(r.Method) {
		writeMethodNotAllowed(w, requestID, "GET, HEAD")
		return
	}
	rules, err := s.rules.RoutingRules(r.Context())
	if err != nil {
		s.writeProviderFailure(w, requestID, err)
		return
	}
	if rules.Rules == nil {
		rules.Rules = []RoutingRule{}
	}
	writeJSON(w, http.StatusOK, rules)
}

func (s *Server) handleProviders(w http.ResponseWriter, r *http.Request) {
	requestID := requestIDFromContext(r.Context())
	if s.providers == nil {
		writeError(w, requestID, http.StatusNotFound, codeCapabilityNotSupported, "resource is not supported by this engine")
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		if r.Method == http.MethodPost {
			// Provider creation is a configuration write; this engine is read-only.
			writeError(w, requestID, http.StatusNotFound, codeCapabilityNotSupported, "resource is not supported by this engine")
			return
		}
		writeMethodNotAllowed(w, requestID, "GET, HEAD")
		return
	}
	limit, ok := parseBoundedPositiveInt(r.URL.Query().Get("limit"), NodeListDefaultLimit)
	if !ok || limit > NodeListMaxLimit {
		writeError(w, requestID, http.StatusBadRequest, codeInvalidRequest,
			"limit must be an integer in 1.."+strconv.Itoa(NodeListMaxLimit))
		return
	}
	page, err := s.providers.ListProviders(r.Context(), limit, r.URL.Query().Get("cursor"))
	if err != nil {
		s.writeProviderFailure(w, requestID, err)
		return
	}
	if page.Providers == nil {
		page.Providers = []Provider{}
	}
	writeJSON(w, http.StatusOK, page)
}

func (s *Server) handleProvider(w http.ResponseWriter, r *http.Request) {
	requestID := requestIDFromContext(r.Context())
	if s.providers == nil {
		writeError(w, requestID, http.StatusNotFound, codeCapabilityNotSupported, "resource is not supported by this engine")
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/api/v1/providers/")
	if strings.HasSuffix(rest, "/refresh") {
		// POST /providers/{id}/refresh is advertised as unavailable.
		writeError(w, requestID, http.StatusNotFound, codeCapabilityNotSupported, "resource is not supported by this engine")
		return
	}
	if rest == "" || strings.Contains(rest, "/") {
		writeError(w, requestID, http.StatusNotFound, codeResourceNotFound, "resource not found")
		return
	}
	if r.Method == http.MethodDelete || r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch {
		// Provider creation, deletion and refresh are configuration writes.
		writeError(w, requestID, http.StatusNotFound, codeCapabilityNotSupported, "resource is not supported by this engine")
		return
	}
	if !isReadMethod(r.Method) {
		writeMethodNotAllowed(w, requestID, "GET, HEAD")
		return
	}
	provider, err := s.providers.GetProvider(r.Context(), rest)
	if err != nil {
		s.writeProviderFailure(w, requestID, err)
		return
	}
	writeJSON(w, http.StatusOK, provider)
}

func (s *Server) handleGeoData(w http.ResponseWriter, r *http.Request) {
	requestID := requestIDFromContext(r.Context())
	if s.geodata == nil {
		writeError(w, requestID, http.StatusNotFound, codeCapabilityNotSupported, "resource is not supported by this engine")
		return
	}
	if !isReadMethod(r.Method) {
		writeMethodNotAllowed(w, requestID, "GET, HEAD")
		return
	}
	data, err := s.geodata.GeoData(r.Context())
	if err != nil {
		s.writeProviderFailure(w, requestID, err)
		return
	}
	if data.ObservedAt == "" {
		data.ObservedAt = time.Now().UTC().Format(time.RFC3339)
	}
	if data.Assets == nil {
		data.Assets = []GeoAsset{}
	}
	writeJSON(w, http.StatusOK, data)
}
