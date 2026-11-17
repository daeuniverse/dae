/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package nativeapi

import (
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

func (s *Server) handleConnections(w http.ResponseWriter, r *http.Request) {
	requestID := requestIDFromContext(r.Context())
	if s.connections == nil {
		writeError(w, requestID, http.StatusNotFound, codeCapabilityNotSupported, "resource is not supported by this engine")
		return
	}
	query := r.URL.Query()
	filter := ConnectionFilter{
		Type: strings.ToLower(query.Get("type")),
		Src:  query.Get("src"),
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		if filter.Type == "all" {
			filter.Type = ""
		}
		if filter.Type != "" && filter.Type != "tcp" && filter.Type != "udp" {
			writeError(w, requestID, http.StatusBadRequest, codeInvalidRequest, "type must be tcp or udp")
			return
		}
		if filter.Src != "" && net.ParseIP(filter.Src) == nil {
			writeError(w, requestID, http.StatusBadRequest, codeInvalidRequest, "src must be an IP literal")
			return
		}
		limit, ok := parseBoundedPositiveInt(query.Get("limit"), NodeListDefaultLimit)
		if !ok || limit > NodeListMaxLimit {
			writeError(w, requestID, http.StatusBadRequest, codeInvalidRequest,
				"limit must be an integer in 1.."+strconv.Itoa(NodeListMaxLimit))
			return
		}
		filter.Limit = limit
		order, errMsg := parseConnectionOrder(query)
		if errMsg != "" {
			writeError(w, requestID, http.StatusBadRequest, codeInvalidRequest, errMsg)
			return
		}
		filter.Sort, filter.Order, filter.WindowSeconds = order.sort, order.order, order.windowSeconds
		list, err := s.connections.ListConnections(r.Context(), filter)
		if err != nil {
			s.writeProviderFailure(w, requestID, err)
			return
		}
		if list.TCP == nil {
			list.TCP = []Connection{}
		}
		if list.UDP == nil {
			list.UDP = []Connection{}
		}
		writeJSON(w, http.StatusOK, list)
	case http.MethodDelete:
		all := query.Get("all") == "true"
		// `type=all` is not a filter: the provider matches only tcp and udp, so
		// passing it fell through to "close everything" without the explicit
		// all=true the bulk call requires. An unknown type had the same effect.
		if filter.Type != "" && filter.Type != "tcp" && filter.Type != "udp" {
			writeError(w, requestID, http.StatusBadRequest, codeInvalidRequest,
				"type must be tcp or udp; pass all=true to close every connection")
			return
		}
		// The read path rejects a non-literal src; without the same check here a
		// typo matches nothing and the call reports a successful close of 0.
		if filter.Src != "" && net.ParseIP(filter.Src) == nil {
			writeError(w, requestID, http.StatusBadRequest, codeInvalidRequest, "src must be an IP literal")
			return
		}
		if !all && filter.Type == "" && filter.Src == "" {
			writeError(w, requestID, http.StatusBadRequest, codeInvalidRequest,
				"Supply type=tcp, type=udp, or src, or explicitly pass all=true.")
			return
		}
		result, err := s.connections.CloseConnections(r.Context(), filter, all)
		if err != nil {
			s.writeProviderFailure(w, requestID, err)
			return
		}
		writeJSON(w, http.StatusOK, result)
	default:
		writeMethodNotAllowed(w, requestID, "GET, HEAD, DELETE")
	}
}

// connectionSortFields are the ordering keys /connections accepts. The
// window_* keys rank by the trailing-window bytes and therefore need a window.
var connectionSortFields = []string{"download", "upload", "total", "window_download", "window_upload", "window_total"}

type connectionOrder struct {
	sort          string
	order         string
	windowSeconds int
}

func isConnectionSort(field string) bool {
	for _, candidate := range connectionSortFields {
		if candidate == field {
			return true
		}
	}
	return false
}

// parseConnectionOrder reads `sort`, `order` and `window_seconds`. A non-empty
// message is the 400 reason; the values are otherwise valid for the provider.
func parseConnectionOrder(query url.Values) (connectionOrder, string) {
	parsed := connectionOrder{sort: strings.ToLower(strings.TrimSpace(query.Get("sort"))), order: strings.ToLower(strings.TrimSpace(query.Get("order")))}
	if parsed.sort != "" && !isConnectionSort(parsed.sort) {
		return parsed, "sort must be one of " + strings.Join(connectionSortFields, ", ")
	}
	switch parsed.order {
	case "":
		parsed.order = "desc"
	case "asc", "desc":
	default:
		return parsed, "order must be asc or desc"
	}
	raw := query.Get("window_seconds")
	if raw == "" {
		if strings.HasPrefix(parsed.sort, "window_") {
			return parsed, "sort=" + parsed.sort + " requires window_seconds"
		}
		return parsed, ""
	}
	seconds, ok := parseBoundedPositiveInt(raw, 0)
	if !ok || seconds > ConnectionWindowMaxSeconds {
		return parsed, "window_seconds must be an integer in 1.." + strconv.Itoa(ConnectionWindowMaxSeconds)
	}
	parsed.windowSeconds = seconds
	return parsed, ""
}

func (s *Server) handleConnection(w http.ResponseWriter, r *http.Request) {
	requestID := requestIDFromContext(r.Context())
	if s.connections == nil {
		writeError(w, requestID, http.StatusNotFound, codeCapabilityNotSupported, "resource is not supported by this engine")
		return
	}
	connectionID := strings.TrimPrefix(r.URL.Path, "/api/v1/connections/")
	if connectionID == "" || strings.Contains(connectionID, "/") {
		writeError(w, requestID, http.StatusNotFound, codeResourceNotFound, "resource not found")
		return
	}
	if r.Method != http.MethodDelete {
		writeMethodNotAllowed(w, requestID, "DELETE")
		return
	}
	if err := s.connections.CloseConnection(r.Context(), connectionID); err != nil {
		s.writeProviderFailure(w, requestID, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleFlows(w http.ResponseWriter, r *http.Request) {
	requestID := requestIDFromContext(r.Context())
	if s.flows == nil {
		writeError(w, requestID, http.StatusNotFound, codeCapabilityNotSupported, "resource is not supported by this engine")
		return
	}
	if !isReadMethod(r.Method) {
		writeMethodNotAllowed(w, requestID, "GET, HEAD")
		return
	}
	query := r.URL.Query()
	limit, ok := parseBoundedPositiveInt(query.Get("limit"), NodeListDefaultLimit)
	if !ok || limit > NodeListMaxLimit {
		writeError(w, requestID, http.StatusBadRequest, codeInvalidRequest,
			"limit must be an integer in 1.."+strconv.Itoa(NodeListMaxLimit))
		return
	}
	list, err := s.flows.ListFlows(r.Context(), FlowFilter{
		Network:      query.Get("network"),
		State:        query.Get("state"),
		ConnectionID: query.Get("connection_id"),
		Limit:        limit,
		Cursor:       query.Get("cursor"),
	})
	if err != nil {
		s.writeProviderFailure(w, requestID, err)
		return
	}
	if list.Flows == nil {
		list.Flows = []FlowSummary{}
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) handleFlow(w http.ResponseWriter, r *http.Request) {
	requestID := requestIDFromContext(r.Context())
	if s.flows == nil {
		writeError(w, requestID, http.StatusNotFound, codeCapabilityNotSupported, "resource is not supported by this engine")
		return
	}
	flowID := strings.TrimPrefix(r.URL.Path, "/api/v1/flows/")
	if flowID == "" || strings.Contains(flowID, "/") {
		writeError(w, requestID, http.StatusNotFound, codeResourceNotFound, "resource not found")
		return
	}
	if !isReadMethod(r.Method) {
		writeMethodNotAllowed(w, requestID, "GET, HEAD")
		return
	}
	detail, err := s.flows.GetFlow(r.Context(), flowID)
	if err != nil {
		s.writeProviderFailure(w, requestID, err)
		return
	}
	writeJSON(w, http.StatusOK, detail)
}
