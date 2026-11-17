/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package nativeapi

import (
	"crypto/sha256"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

const (
	routingTraceRequestsPerPrincipalPerMinute = 30
	routingTraceGlobalRequestsPerMinute       = 120
)

type routingTraceRateLimiter struct {
	mu         sync.Mutex
	window     time.Time
	global     int
	principals map[[32]byte]int
}

func (l *routingTraceRateLimiter) allow(principal string, now time.Time) (bool, int) {
	window := now.Truncate(time.Minute)
	l.mu.Lock()
	defer l.mu.Unlock()
	if !window.Equal(l.window) {
		l.window = window
		l.global = 0
		l.principals = make(map[[32]byte]int)
	}
	key := sha256.Sum256([]byte(principal))
	principalCount := l.principals[key]
	if l.global >= routingTraceGlobalRequestsPerMinute ||
		principalCount >= routingTraceRequestsPerPrincipalPerMinute {
		remaining := window.Add(time.Minute).Sub(now)
		retryAfter := int((remaining + time.Second - 1) / time.Second)
		if retryAfter < 1 {
			retryAfter = 1
		}
		return false, retryAfter
	}
	l.global++
	l.principals[key] = principalCount + 1
	return true, 0
}

func (s *Server) handleRoutingTrace(w http.ResponseWriter, r *http.Request) {
	requestID := requestIDFromContext(r.Context())
	if s.rules == nil {
		writeError(w, requestID, http.StatusNotFound, codeCapabilityNotSupported, "routing trace is not supported by this engine")
		return
	}
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, requestID, http.MethodPost)
		return
	}
	if provider, ok := s.rules.(interface{ RoutingTraceAvailable() bool }); ok && !provider.RoutingTraceAvailable() {
		writeError(w, requestID, http.StatusNotFound, codeCapabilityNotSupported, "routing trace is not supported by this engine")
		return
	}
	if !isJSONContentType(r.Header.Get("Content-Type")) {
		writeError(w, requestID, http.StatusUnsupportedMediaType, codeUnsupportedMediaType, "Content-Type must be application/json")
		return
	}
	if allowed, retryAfter := s.traceRateLimiter.allow(routingTracePrincipal(r), time.Now()); !allowed {
		writeProviderError(w, requestID, &APIError{
			Status: http.StatusTooManyRequests, Code: "rate_limited",
			Message: "routing trace request limit exceeded", RetryAfterSeconds: retryAfter,
		})
		return
	}
	var request RoutingTraceRequest
	if err := decodeLimitedJSON(r, s.cfg.MaxJSONBodyBytes, &request); err != nil {
		if err == errLimitedJSONBodyTooLarge {
			writeError(w, requestID, http.StatusRequestEntityTooLarge, codeInvalidRequest, "request body is too large")
			return
		}
		writeError(w, requestID, http.StatusBadRequest, codeInvalidRequest, "invalid JSON body: "+err.Error())
		return
	}
	if request.Resolve == "" {
		request.Resolve = "none"
	}
	if request.Resolve != "none" && request.Resolve != "live" {
		writeError(w, requestID, http.StatusBadRequest, codeInvalidRequest, "resolve must be none or live")
		return
	}
	if request.Input.Network != groupNetworkTCP && request.Input.Network != groupNetworkUDP {
		writeError(w, requestID, http.StatusBadRequest, codeInvalidRequest, "network must be tcp or udp")
		return
	}
	if request.Input.DstPort == 0 {
		writeError(w, requestID, http.StatusBadRequest, codeInvalidRequest, "dst_port must be between 1 and 65535")
		return
	}
	if request.Input.SrcPort != nil && *request.Input.SrcPort == 0 {
		writeError(w, requestID, http.StatusBadRequest, codeInvalidRequest, "src_port must be between 1 and 65535")
		return
	}
	if request.Input.Dscp != nil && *request.Input.Dscp > 63 {
		writeError(w, requestID, http.StatusBadRequest, codeInvalidRequest, "dscp must be between 0 and 63")
		return
	}
	if request.Input.Domain != nil && (strings.TrimSpace(*request.Input.Domain) == "" || *request.Input.Domain != strings.TrimSpace(*request.Input.Domain)) {
		writeError(w, requestID, http.StatusBadRequest, codeInvalidRequest, "domain must be a non-empty hostname")
		return
	}
	if request.Input.Domain == nil && request.Input.DstIP == nil {
		writeError(w, requestID, http.StatusBadRequest, codeInvalidRequest, "domain or dst_ip is required")
		return
	}
	if request.Resolve == "live" {
		if request.Input.Domain == nil || request.Input.DstIP != nil {
			writeError(w, requestID, http.StatusBadRequest, codeInvalidRequest, "resolve=live requires domain and dst_ip must be null")
			return
		}
		writeError(w, requestID, http.StatusUnprocessableEntity, codeUnsupportedValue, "live DNS resolution is not supported by this engine")
		return
	}
	if _, err := parseOptionalTraceIP(request.Input.DstIP); err != nil {
		writeError(w, requestID, http.StatusBadRequest, codeInvalidRequest, "dst_ip must be a valid IP address")
		return
	}
	if _, err := parseOptionalTraceIP(request.Input.SrcIP); err != nil {
		writeError(w, requestID, http.StatusBadRequest, codeInvalidRequest, "src_ip must be a valid IP address")
		return
	}

	response, err := s.rules.TraceRouting(r.Context(), request)
	if err != nil {
		s.writeProviderFailure(w, requestID, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	writeJSON(w, http.StatusOK, response)
}

func routingTracePrincipal(r *http.Request) string {
	if token, present, valid := parseBearer(r.Header.Get("Authorization")); valid && present {
		return "token:" + token
	}
	return "remote:" + remoteIP(r.RemoteAddr)
}

func parseOptionalTraceIP(value *string) (*netip.Addr, error) {
	if value == nil {
		return nil, nil
	}
	addr, err := netip.ParseAddr(*value)
	if err != nil {
		return nil, err
	}
	if addr.Zone() != "" {
		return nil, errInvalidTraceIP
	}
	return &addr, nil
}

var errInvalidTraceIP = &traceInputError{}

type traceInputError struct{}

func (*traceInputError) Error() string { return "invalid IP address" }
