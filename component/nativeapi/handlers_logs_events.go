/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package nativeapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

var logLevelOrder = []string{"trace", "debug", "info", "warn", "error"}

func writeSSEFrame(w http.ResponseWriter, frame SSEFrame) error {
	if frame.ID != "" {
		if _, err := fmt.Fprintf(w, "id: %s\n", frame.ID); err != nil {
			return err
		}
	}
	if frame.Event != "" {
		if _, err := fmt.Fprintf(w, "event: %s\n", frame.Event); err != nil {
			return err
		}
	}
	data, err := json.Marshal(frame.Data)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "data: %s\n\n", data); err != nil {
		return err
	}
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
	return nil
}

func containsString(values []string, value string) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}

func (s *Server) streamFrames(w http.ResponseWriter, r *http.Request, stream *SSEStream) {
	if stream.Cancel != nil {
		defer stream.Cancel()
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("X-Accel-Buffering", "no")
	if err := writeSSEFrame(w, stream.Ready); err != nil {
		return
	}
	for _, frame := range stream.Replay {
		if err := writeSSEFrame(w, frame); err != nil {
			return
		}
	}
	heartbeat := time.NewTicker(SSEHeartbeatSeconds * time.Second)
	defer heartbeat.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case frame, ok := <-stream.Updates:
			if !ok {
				return
			}
			if err := writeSSEFrame(w, frame); err != nil {
				return
			}
		case <-heartbeat.C:
			if _, err := fmt.Fprint(w, ": heartbeat\n\n"); err != nil {
				return
			}
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
		}
	}
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	requestID := requestIDFromContext(r.Context())
	if s.logs == nil {
		writeError(w, requestID, http.StatusNotFound, codeCapabilityNotSupported, "resource is not supported by this engine")
		return
	}
	if !isReadMethod(r.Method) {
		writeMethodNotAllowed(w, requestID, "GET, HEAD")
		return
	}
	level := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("level")))
	if level != "" && !containsString(logLevelOrder, level) {
		writeError(w, requestID, http.StatusBadRequest, codeInvalidRequest, "level is not a valid log level")
		return
	}
	if level != "" && !containsString(s.logs.LogLevels(), level) {
		writeError(w, requestID, http.StatusUnprocessableEntity, codeUnsupportedValue, "level is not advertised by this engine")
		return
	}
	target := r.URL.Query().Get("target")
	if target != "" && !containsString(s.logs.LogFilters(), "target") {
		writeError(w, requestID, http.StatusUnprocessableEntity, codeUnsupportedValue, "target is not an advertised log filter")
		return
	}
	stream, err := s.logs.OpenLogStream(r.Context(), level, target, r.Header.Get("Last-Event-ID"))
	if err != nil {
		s.writeProviderFailure(w, requestID, err)
		return
	}
	s.streamFrames(w, r, stream)
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	requestID := requestIDFromContext(r.Context())
	if s.events == nil {
		writeError(w, requestID, http.StatusNotFound, codeCapabilityNotSupported, "resource is not supported by this engine")
		return
	}
	if !isReadMethod(r.Method) {
		writeMethodNotAllowed(w, requestID, "GET, HEAD")
		return
	}
	var kinds []string
	if raw := strings.TrimSpace(r.URL.Query().Get("kinds")); raw != "" {
		seen := map[string]struct{}{}
		for _, kind := range strings.Split(raw, ",") {
			kind = strings.TrimSpace(kind)
			if kind == "" {
				continue
			}
			if _, duplicate := seen[kind]; duplicate {
				writeError(w, requestID, http.StatusBadRequest, codeInvalidRequest, "duplicate event kind: "+kind)
				return
			}
			seen[kind] = struct{}{}
			if !containsString(eventKindCatalogue, kind) {
				writeError(w, requestID, http.StatusBadRequest, codeInvalidRequest, "unknown event kind: "+kind)
				return
			}
			if !containsString(s.events.EventKinds(), kind) {
				writeError(w, requestID, http.StatusUnprocessableEntity, codeUnsupportedValue, "event kind is not advertised: "+kind)
				return
			}
			kinds = append(kinds, kind)
		}
	}
	stream, err := s.events.OpenEventStream(r.Context(), kinds, r.URL.Query().Get("flow_id"), r.Header.Get("Last-Event-ID"))
	if err != nil {
		s.writeProviderFailure(w, requestID, err)
		return
	}
	s.streamFrames(w, r, stream)
}

var eventKindCatalogue = []string{
	"stream.ready",
	"runtime.updated",
	"flow.updated",
	"flow.gap",
	"operation.updated",
	"generation.changed",
}
