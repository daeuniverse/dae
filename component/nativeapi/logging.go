/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package nativeapi

import (
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// responseRecorder captures what the access log reports. It forwards to the
// underlying writer unchanged, so handlers and net/http keep full control.
type responseRecorder struct {
	http.ResponseWriter
	status    int
	bytes     int
	errorCode string
}

func (r *responseRecorder) WriteHeader(status int) {
	if r.status == 0 {
		r.status = status
	}
	r.ResponseWriter.WriteHeader(status)
}

// Flush and Unwrap keep streaming handlers working through the recorder.
func (r *responseRecorder) Flush() {
	if flusher, ok := r.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (r *responseRecorder) Unwrap() http.ResponseWriter {
	return r.ResponseWriter
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	n, err := r.ResponseWriter.Write(b)
	r.bytes += n
	return n, err
}

func (r *responseRecorder) setErrorCode(code string) {
	r.errorCode = code
}

type errorCodeSetter interface {
	setErrorCode(code string)
}

func recordErrorCode(w http.ResponseWriter, code string) {
	if setter, ok := w.(errorCodeSetter); ok {
		setter.setErrorCode(code)
	}
}

// fixedRouteTemplates are the exact paths the server routes. A log entry names
// the route so per-route alerting works, and naming it from a fixed table is
// what keeps probing random paths from growing log cardinality.
var fixedRouteTemplates = map[string]string{
	"/api":                            "/api",
	"/api/v1/version":                 "/api/v1/version",
	"/api/v1/capabilities":            "/api/v1/capabilities",
	"/api/v1/runtime":                 "/api/v1/runtime",
	"/api/v1/runtime/traffic/history": "/api/v1/runtime/traffic/history",
	"/api/v1/runtime/outbounds":       "/api/v1/runtime/outbounds",
	"/api/v1/runtime/memory":          "/api/v1/runtime/memory",
	"/api/v1/runtime/memory/history":  "/api/v1/runtime/memory/history",
	"/api/v1/runtime/direct-stats":    "/api/v1/runtime/direct-stats",
	"/api/v1/datapath":                "/api/v1/datapath",
	"/api/v1/rules":                   "/api/v1/rules",
	"/api/v1/routing/trace":           "/api/v1/routing/trace",
	"/api/v1/providers":               "/api/v1/providers",
	"/api/v1/geodata":                 "/api/v1/geodata",
	"/api/v1/dns/cache":               "/api/v1/dns/cache",
	"/api/v1/dns/cache/flush":         "/api/v1/dns/cache/flush",
	"/api/v1/dns/log":                 "/api/v1/dns/log",
	"/api/v1/dns/rules":               "/api/v1/dns/rules",
	"/api/v1/dns/query":               "/api/v1/dns/query",
	"/api/v1/connections":             "/api/v1/connections",
	"/api/v1/flows":                   "/api/v1/flows",
	"/api/v1/logs":                    "/api/v1/logs",
	"/api/v1/events":                  "/api/v1/events",
	"/api/v1/probes":                  "/api/v1/probes",
	"/api/v1/groups":                  "/api/v1/groups",
	"/api/v1/nodes":                   "/api/v1/nodes",
	"/api/v1/operations/reload":       "/api/v1/operations/reload",
	"/api/v1/operations/suspend":      "/api/v1/operations/suspend",
	"/api/v1/operations/resume":       "/api/v1/operations/resume",
	"/api/v1/config":                  "/api/v1/config",
	"/api/v1/config/validate":         "/api/v1/config/validate",
	"/api/v1/config/sources":          "/api/v1/config/sources",
	"/":                               "/",
	"/ui":                             "/ui",
	UIBasePath:                        UIBasePath,
}

// dynamicRouteTemplates maps a routed collection path onto a bounded template.
// subs lists the fixed subresource names that are worth keeping distinct; any
// other suffix collapses into the collection template, so a client cannot grow
// log cardinality with arbitrary path segments.
var dynamicRouteTemplates = []struct {
	prefix   string
	template string
	subs     []string
}{
	{"/api/v1/groups/", "/api/v1/groups/{group_id}", []string{"config", "selection"}},
	{"/api/v1/nodes/", "/api/v1/nodes/{node_id}", nil},
	{"/api/v1/operations/", "/api/v1/operations/{operation_id}", nil},
	{"/api/v1/providers/", "/api/v1/providers/{provider_id}", nil},
	{"/api/v1/dns/cache/", "/api/v1/dns/cache/{entry_id}", nil},
	{"/api/v1/connections/", "/api/v1/connections/{connection_id}", nil},
	{"/api/v1/flows/", "/api/v1/flows/{flow_id}", nil},
	{"/api/v1/config/sources/", "/api/v1/config/sources/{source_id}", nil},
}

// routeTemplate maps a request path onto the route it belongs to.
func routeTemplate(path string) string {
	if template, ok := fixedRouteTemplates[path]; ok {
		return template
	}
	if strings.HasPrefix(path, UIBasePath) {
		return "/ui/*"
	}
	for _, route := range dynamicRouteTemplates {
		if !strings.HasPrefix(path, route.prefix) {
			continue
		}
		rest := strings.TrimPrefix(path, route.prefix)
		if id, sub, found := strings.Cut(rest, "/"); found && id != "" {
			for _, candidate := range route.subs {
				if sub == candidate {
					return route.template + "/" + candidate
				}
			}
		}
		return route.template
	}
	for _, prefix := range unavailablePrefixes {
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			return prefix
		}
	}
	return "<unmatched>"
}

func remoteIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}

// logRequest mirrors the reference engine: a dashboard polls every few seconds,
// so ordinary requests log at debug, while refusals and failures are visible at
// the default level. Neither headers nor query strings are logged, so an
// Authorization token or secret never reaches the log.
func (s *Server) logRequest(recorder *responseRecorder, r *http.Request, started time.Time) {
	if s.log == nil {
		return
	}
	status := recorder.status
	if status == 0 {
		status = http.StatusOK
	}
	fields := logrus.Fields{
		"method":     r.Method,
		"route":      routeTemplate(r.URL.Path),
		"status":     status,
		"elapsed_ms": float64(time.Since(started).Microseconds()) / 1000,
		"request_id": requestIDFromContext(r.Context()),
		"remote_ip":  remoteIP(r.RemoteAddr),
		"bytes":      recorder.bytes,
	}
	if recorder.errorCode != "" {
		fields["error_code"] = recorder.errorCode
	}
	for key, value := range uiLogFields(r, status) {
		fields[key] = value
	}
	switch {
	case status >= http.StatusInternalServerError:
		s.refused.Add(1)
		s.log.WithFields(fields).Errorln("Native API request failed")
	case status >= http.StatusBadRequest:
		s.refused.Add(1)
		s.log.WithFields(fields).Infoln("Native API request refused")
	default:
		s.served.Add(1)
		s.log.WithFields(fields).Debugln("Native API request")
	}
}

// accessSummaryInterval bounds how often a busy dashboard can add a line to the
// log at the default level: individual requests stay at debug, while this
// periodic line proves the API is in use.
const accessSummaryInterval = time.Minute

func (s *Server) startAccessSummary() {
	if s.log == nil {
		return
	}
	s.summaryMu.Lock()
	defer s.summaryMu.Unlock()
	if s.summaryOn {
		return
	}
	s.summaryOn = true
	s.stop = make(chan struct{})
	s.done = make(chan struct{})
	go s.summarizeAccess(s.stop, s.done)
}

func (s *Server) stopAccessSummary() {
	s.summaryMu.Lock()
	on := s.summaryOn
	s.summaryOn = false
	s.summaryMu.Unlock()
	if !on {
		return
	}
	s.stopOnce.Do(func() { close(s.stop) })
	<-s.done
}

func (s *Server) summarizeAccess(stop, done chan struct{}) {
	ticker := time.NewTicker(accessSummaryInterval)
	defer ticker.Stop()
	defer close(done)
	for {
		select {
		case <-stop:
			s.reportAccessSummary()
			return
		case <-ticker.C:
			s.reportAccessSummary()
		}
	}
}

func (s *Server) reportAccessSummary() {
	served := s.served.Swap(0)
	refused := s.refused.Swap(0)
	if served+refused == 0 || s.log == nil {
		return
	}
	s.log.WithFields(logrus.Fields{
		"served":         served,
		"refused":        refused,
		"window_seconds": int(accessSummaryInterval / time.Second),
	}).Infoln("Native API traffic")
}
