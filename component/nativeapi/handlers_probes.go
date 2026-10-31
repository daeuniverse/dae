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
)

func (s *Server) handleProbes(w http.ResponseWriter, r *http.Request) {
	requestID := requestIDFromContext(r.Context())
	if s.probes == nil {
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
	var request ProbeRequest
	decoder := json.NewDecoder(io.LimitReader(r.Body, int64(s.cfg.MaxJSONBodyBytes)+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeError(w, requestID, http.StatusBadRequest, codeInvalidRequest, "invalid JSON body")
		return
	}
	if request.Target.Type != "node" && request.Target.Type != "group" {
		writeError(w, requestID, http.StatusBadRequest, codeInvalidRequest, "target.type must be node or group")
		return
	}
	if request.Target.Type == "node" && request.Target.NodeID == "" {
		writeError(w, requestID, http.StatusBadRequest, codeInvalidRequest, "target.node_id is required")
		return
	}
	if request.Target.Type == "group" && request.Target.GroupID == "" {
		writeError(w, requestID, http.StatusBadRequest, codeInvalidRequest, "target.group_id is required")
		return
	}
	switch request.Kind {
	case "tcp_connect", "http", "dns":
	default:
		writeError(w, requestID, http.StatusUnprocessableEntity, codeUnsupportedValue, "unsupported probe kind")
		return
	}
	if len(request.Transport) == 0 || len(request.Transport) > 2 {
		writeError(w, requestID, http.StatusBadRequest, codeInvalidRequest, "transport must contain one or two values")
		return
	}
	seen := map[string]struct{}{}
	for _, transport := range request.Transport {
		if transport != "tcp" && transport != "udp" {
			writeError(w, requestID, http.StatusUnprocessableEntity, codeUnsupportedValue, "unsupported probe transport")
			return
		}
		if _, duplicate := seen[transport]; duplicate {
			writeError(w, requestID, http.StatusBadRequest, codeInvalidRequest, "duplicate probe transport")
			return
		}
		seen[transport] = struct{}{}
		if request.Kind != "dns" && transport != "tcp" {
			writeError(w, requestID, http.StatusUnprocessableEntity, codeUnsupportedValue, "tcp_connect and http probes only run over tcp")
			return
		}
	}
	if request.IPVersion != "ipv4" && request.IPVersion != "ipv6" && request.IPVersion != "any" {
		writeError(w, requestID, http.StatusBadRequest, codeInvalidRequest, "ip_version must be ipv4, ipv6 or any")
		return
	}
	if request.Warmth != "cold" && request.Warmth != "warm" {
		writeError(w, requestID, http.StatusBadRequest, codeInvalidRequest, "warmth must be cold or warm")
		return
	}
	if request.Target.Type == "node" && request.Members != nil {
		writeError(w, requestID, http.StatusBadRequest, codeInvalidRequest, "members is only valid for a group target")
		return
	}
	accepted, err := s.probes.StartProbe(r.Context(), request, r.Header.Get("Idempotency-Key"))
	if err != nil {
		s.writeProviderFailure(w, requestID, err)
		return
	}
	w.Header().Set("Location", accepted.Href)
	w.Header().Set("Retry-After", strconv.Itoa(1))
	writeJSON(w, http.StatusAccepted, accepted)
}
