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

type hostAuthority struct {
	host string
	port int
}

var corsAllowedHeaders = map[string]struct{}{
	"authorization":   {},
	"last-event-id":   {},
	"content-type":    {},
	"if-match":        {},
	"idempotency-key": {},
	"accept":          {},
}

func (s *Server) hostAllowed(hostHeader string) bool {
	host, port, ok := parseAuthority(hostHeader, 80)
	if !ok {
		return false
	}
	if equalHost(host, s.listenHost) && port == s.listenPort {
		return true
	}
	if s.listenerIsLoopback && isLoopbackHost(host) && port == s.listenPort {
		return true
	}
	if s.wildcardListen {
		if net.ParseIP(host) != nil && port == s.listenPort {
			return true
		}
		if strings.EqualFold(host, "localhost") && port == s.listenPort {
			return true
		}
	}
	for _, allowed := range s.allowedHosts {
		if equalHost(host, allowed.host) && port == allowed.port {
			return true
		}
	}
	return false
}

func (s *Server) originAllowed(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		if s.cfg.Secret == "" && s.listenerIsLoopback && strings.EqualFold(r.Header.Get("Sec-Fetch-Site"), "cross-site") {
			return false
		}
		return true
	}
	if s.isSameOrigin(origin, r.Host) {
		return true
	}
	_, ok := s.allowedOrigins[origin]
	return ok
}

func (s *Server) isSameOrigin(origin, hostHeader string) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "http" {
		return false
	}
	originHost, originPort, ok := parseAuthority(u.Host, 80)
	if !ok {
		return false
	}
	requestHost, requestPort, ok := parseAuthority(hostHeader, 80)
	if !ok {
		return false
	}
	return equalHost(originHost, requestHost) && originPort == requestPort
}

func (s *Server) setCORSHeaders(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if origin == "" || !s.originAllowed(r) {
		return
	}
	header := w.Header()
	header.Set("Access-Control-Allow-Origin", origin)
	header.Add("Vary", "Origin")
	header.Set("Access-Control-Expose-Headers", "Location, Retry-After, ETag")
}

func (s *Server) handlePreflight(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if origin == "" || !s.originAllowed(r) {
		writeError(w, requestIDFromContext(r.Context()), http.StatusForbidden, codePermissionDenied, "origin is not allowed")
		return
	}
	// The control plane serves state-changing routes too (PUT selection,
	// POST operations, DELETE selection); a cross-origin dashboard always
	// preflights them because of Authorization and Content-Type.
	method := r.Header.Get("Access-Control-Request-Method")
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodOptions:
	default:
		writeError(w, requestIDFromContext(r.Context()), http.StatusForbidden, codePermissionDenied, "method is not allowed")
		return
	}
	for _, requested := range strings.Split(r.Header.Get("Access-Control-Request-Headers"), ",") {
		name := strings.ToLower(strings.TrimSpace(requested))
		if name == "" {
			continue
		}
		if _, ok := corsAllowedHeaders[name]; !ok {
			writeError(w, requestIDFromContext(r.Context()), http.StatusForbidden, codePermissionDenied, "request header is not allowed")
			return
		}
	}

	header := w.Header()
	header.Set("Access-Control-Allow-Origin", origin)
	header.Add("Vary", "Origin")
	header.Set("Access-Control-Allow-Methods", "GET, HEAD, POST, PUT, DELETE, OPTIONS")
	header.Set("Access-Control-Allow-Headers", "Authorization, Last-Event-ID, Content-Type, If-Match, Idempotency-Key, Accept")
	header.Set("Access-Control-Expose-Headers", "Location, Retry-After, ETag")
	header.Set("Access-Control-Max-Age", "600")
	w.WriteHeader(http.StatusNoContent)
}

func parseAuthority(value string, defaultPort int) (host string, port int, ok bool) {
	value = strings.TrimSpace(value)
	if value == "" || strings.ContainsAny(value, " \t\r\n") {
		return "", 0, false
	}
	if strings.HasPrefix(value, "[") {
		if h, p, err := net.SplitHostPort(value); err == nil {
			port, ok := parsePort(p)
			if !ok {
				return "", 0, false
			}
			return h, port, true
		}
		if strings.HasSuffix(value, "]") {
			return strings.Trim(value, "[]"), defaultPort, true
		}
		return "", 0, false
	}
	if h, p, err := net.SplitHostPort(value); err == nil {
		port, ok := parsePort(p)
		if !ok {
			return "", 0, false
		}
		return h, port, true
	}
	if strings.Contains(value, ":") {
		return "", 0, false
	}
	return strings.ToLower(value), defaultPort, true
}

// requestHeaderBytes estimates the on-wire size of the request line and headers.
// Parsed headers drop framing details, so this counts a conservative envelope.
func requestHeaderBytes(r *http.Request) int {
	size := len(r.Method) + len(r.RequestURI) + len(r.Proto) + len("Host") + len(r.Host) + 8
	for name, values := range r.Header {
		for _, value := range values {
			size += len(name) + len(value) + 4
		}
	}
	return size
}

func parsePort(value string) (int, bool) {
	if value == "" {
		return 0, false
	}
	port, err := strconv.Atoi(value)
	if err != nil || port < 1 || port > 65535 {
		return 0, false
	}
	return port, true
}

func equalHost(a, b string) bool {
	if strings.EqualFold(a, b) {
		return true
	}
	aIP, bIP := net.ParseIP(a), net.ParseIP(b)
	return aIP != nil && bIP != nil && aIP.Equal(bIP)
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
