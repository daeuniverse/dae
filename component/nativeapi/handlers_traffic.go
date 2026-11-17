/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package nativeapi

import (
	"net/http"
	"strconv"
)

func (s *Server) handleTrafficHistory(w http.ResponseWriter, r *http.Request) {
	requestID := requestIDFromContext(r.Context())
	if s.traffic == nil {
		writeError(w, requestID, http.StatusNotFound, codeCapabilityNotSupported, "resource is not supported by this engine")
		return
	}
	if !isReadMethod(r.Method) {
		writeMethodNotAllowed(w, requestID, "GET, HEAD")
		return
	}
	query := r.URL.Query()
	windowSeconds, ok := parseBoundedPositiveInt(query.Get("window_seconds"), DefaultTrafficHistoryWindow)
	if !ok || windowSeconds > MaxTrafficHistoryWindowSeconds {
		writeError(w, requestID, http.StatusBadRequest, codeInvalidRequest,
			"window_seconds must be an integer in 1.."+strconv.Itoa(MaxTrafficHistoryWindowSeconds))
		return
	}
	maxPoints, ok := parseBoundedPositiveInt(query.Get("max_points"), DefaultTrafficHistoryPoints)
	if !ok || maxPoints > MaxTrafficHistoryPoints {
		writeError(w, requestID, http.StatusBadRequest, codeInvalidRequest,
			"max_points must be an integer in 1.."+strconv.Itoa(MaxTrafficHistoryPoints))
		return
	}
	history, err := s.traffic.TrafficHistory(r.Context(), windowSeconds, maxPoints)
	if err != nil {
		s.writeProviderFailure(w, requestID, err)
		return
	}
	if history.Samples == nil {
		history.Samples = []TrafficHistorySample{}
	}
	writeJSON(w, http.StatusOK, history)
}
