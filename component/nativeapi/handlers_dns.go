/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package nativeapi

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func dnsTypeParams(values []string) []string {
	types := make([]string, 0, len(values))
	for _, value := range values {
		for _, item := range strings.Split(value, ",") {
			item = strings.ToUpper(strings.TrimSpace(item))
			if item != "" {
				types = append(types, item)
			}
		}
	}
	return types
}

func (s *Server) handleDnsCache(w http.ResponseWriter, r *http.Request) {
	requestID := requestIDFromContext(r.Context())
	if s.dns == nil {
		writeError(w, requestID, http.StatusNotFound, codeCapabilityNotSupported, "resource is not supported by this engine")
		return
	}
	query := r.URL.Query()
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		limit, ok := parseBoundedPositiveInt(query.Get("limit"), NodeListDefaultLimit)
		if !ok || limit > NodeListMaxLimit {
			writeError(w, requestID, http.StatusBadRequest, codeInvalidRequest,
				"limit must be an integer in 1.."+strconv.Itoa(NodeListMaxLimit))
			return
		}
		cache, err := s.dns.DnsCache(r.Context(), DnsCacheFilter{
			Name:           query.Get("name"),
			Domain:         query.Get("domain"),
			Types:          dnsTypeParams(query["type"]),
			IncludeExpired: query.Get("include_expired") == "true",
			Limit:          limit,
			Cursor:         query.Get("cursor"),
		})
		if err != nil {
			s.writeProviderFailure(w, requestID, err)
			return
		}
		if cache.Entries == nil {
			cache.Entries = []DnsCacheEntry{}
		}
		writeJSON(w, http.StatusOK, cache)
	case http.MethodDelete:
		name := query.Get("name")
		if name == "" {
			writeError(w, requestID, http.StatusBadRequest, codeInvalidRequest, "name is required")
			return
		}
		result, err := s.dns.DeleteDnsCacheByName(r.Context(), name, dnsTypeParams(query["type"]))
		if err != nil {
			s.writeProviderFailure(w, requestID, err)
			return
		}
		writeJSON(w, http.StatusOK, result)
	default:
		writeMethodNotAllowed(w, requestID, "GET, HEAD, DELETE")
	}
}

func (s *Server) handleDnsCacheEntry(w http.ResponseWriter, r *http.Request) {
	requestID := requestIDFromContext(r.Context())
	if s.dns == nil {
		writeError(w, requestID, http.StatusNotFound, codeCapabilityNotSupported, "resource is not supported by this engine")
		return
	}
	entryID := strings.TrimPrefix(r.URL.Path, "/api/v1/dns/cache/")
	if entryID == "" || strings.Contains(entryID, "/") {
		writeError(w, requestID, http.StatusNotFound, codeResourceNotFound, "resource not found")
		return
	}
	if r.Method != http.MethodDelete {
		writeMethodNotAllowed(w, requestID, "DELETE")
		return
	}
	result, err := s.dns.DeleteDnsCacheEntry(r.Context(), entryID)
	if err != nil {
		s.writeProviderFailure(w, requestID, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleDnsCacheFlush(w http.ResponseWriter, r *http.Request) {
	requestID := requestIDFromContext(r.Context())
	if s.dns == nil {
		writeError(w, requestID, http.StatusNotFound, codeCapabilityNotSupported, "resource is not supported by this engine")
		return
	}
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, requestID, "POST")
		return
	}
	if !isJSONContentType(r.Header.Get("Content-Type")) && r.ContentLength > 0 {
		writeError(w, requestID, http.StatusUnsupportedMediaType, codeUnsupportedMediaType, "Content-Type must be application/json")
		return
	}
	result, err := s.dns.FlushDnsCache(r.Context())
	if err != nil {
		s.writeProviderFailure(w, requestID, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleDnsLog(w http.ResponseWriter, r *http.Request) {
	requestID := requestIDFromContext(r.Context())
	if s.dns == nil {
		writeError(w, requestID, http.StatusNotFound, codeCapabilityNotSupported, "resource is not supported by this engine")
		return
	}
	if !isReadMethod(r.Method) {
		writeMethodNotAllowed(w, requestID, "GET, HEAD")
		return
	}
	query := r.URL.Query()
	limit, ok := parseBoundedPositiveInt(query.Get("limit"), 100)
	if !ok || limit > DnsLogMaxPageSize {
		writeError(w, requestID, http.StatusBadRequest, codeInvalidRequest,
			"limit must be an integer in 1.."+strconv.Itoa(DnsLogMaxPageSize))
		return
	}
	list, err := s.dns.DnsLog(r.Context(), DnsLogFilter{
		Name:   query.Get("name"),
		Types:  dnsTypeParams(query["type"]),
		Src:    query.Get("src"),
		Limit:  limit,
		Cursor: query.Get("cursor"),
	})
	if err != nil {
		s.writeProviderFailure(w, requestID, err)
		return
	}
	if list.Records == nil {
		list.Records = []DnsLogRecord{}
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) handleDnsRules(w http.ResponseWriter, r *http.Request) {
	requestID := requestIDFromContext(r.Context())
	if s.dns == nil {
		writeError(w, requestID, http.StatusNotFound, codeCapabilityNotSupported, "resource is not supported by this engine")
		return
	}
	if !isReadMethod(r.Method) {
		writeMethodNotAllowed(w, requestID, "GET, HEAD")
		return
	}
	rules, err := s.dns.DnsRules(r.Context())
	if err != nil {
		s.writeProviderFailure(w, requestID, err)
		return
	}
	if rules.Request == nil {
		rules.Request = []DnsRoutingRule{}
	}
	if rules.Response == nil {
		rules.Response = []DnsRoutingRule{}
	}
	writeJSON(w, http.StatusOK, rules)
}

func (s *Server) handleDnsQuery(w http.ResponseWriter, r *http.Request) {
	requestID := requestIDFromContext(r.Context())
	if s.dns == nil {
		writeError(w, requestID, http.StatusNotFound, codeCapabilityNotSupported, "resource is not supported by this engine")
		return
	}
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, requestID, "POST")
		return
	}
	if !isJSONContentType(r.Header.Get("Content-Type")) {
		writeError(w, requestID, http.StatusUnsupportedMediaType, codeUnsupportedMediaType, "Content-Type must be application/json")
		return
	}
	var request DnsQueryRequest
	decoder := json.NewDecoder(io.LimitReader(r.Body, int64(s.cfg.MaxJSONBodyBytes)+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeError(w, requestID, http.StatusBadRequest, codeInvalidRequest, "invalid JSON body")
		return
	}
	request.Domain = strings.TrimSpace(request.Domain)
	if request.Domain == "" || len(request.Domain) > 253 {
		writeError(w, requestID, http.StatusBadRequest, codeInvalidRequest, "domain must be 1..253 characters")
		return
	}
	if len(request.Type) == 0 {
		request.Type = []string{"A"}
	}
	if len(request.Type) > DnsQueryMaxTypes {
		writeError(w, requestID, http.StatusBadRequest, codeInvalidRequest,
			"type must contain at most "+strconv.Itoa(DnsQueryMaxTypes)+" record types")
		return
	}
	if request.CacheMode == "" {
		request.CacheMode = "normal"
	}
	if request.CacheMode != "normal" && request.CacheMode != "bypass" {
		writeError(w, requestID, http.StatusBadRequest, codeInvalidRequest, "cache_mode must be normal or bypass")
		return
	}
	response, err := s.dns.QueryDns(r.Context(), request)
	if err != nil {
		s.writeProviderFailure(w, requestID, err)
		return
	}
	if response.QueryTime == "" {
		response.QueryTime = time.Now().UTC().Format(time.RFC3339)
	}
	if response.Results == nil {
		response.Results = []DnsQueryResult{}
	}
	writeJSON(w, http.StatusOK, response)
}
