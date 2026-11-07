/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package nativeapi

import (
	"crypto/subtle"
	"net"
	"net/http"
	"strings"
)

// authenticate admits a request and reports whether discovery should use the
// full (admitted) view. Discovery is public in every mode: a request without a
// credential gets the public view, while an invalid credential is rejected.
func (s *Server) authenticate(r *http.Request) (admitted bool, fullDiscovery bool) {
	token, hasCredential, parsed := parseBearer(r.Header.Get("Authorization"))
	if !parsed {
		return false, false
	}

	if r.URL.Path == "/api" {
		if !hasCredential {
			if s.anonymousLoopbackActive() && remoteIsLoopback(r.RemoteAddr) {
				return true, true
			}
			return true, false
		}
		if s.cfg.Secret != "" && constantTimeEqual(token, s.cfg.Secret) {
			return true, true
		}
		return false, false
	}

	if s.cfg.Secret != "" {
		if hasCredential && constantTimeEqual(token, s.cfg.Secret) {
			return true, true
		}
		return false, false
	}

	if s.cfg.AllowAnonymousLoopback && s.listenerIsLoopback && remoteIsLoopback(r.RemoteAddr) {
		return true, true
	}
	return false, false
}

func parseBearer(header string) (token string, present bool, ok bool) {
	if header == "" {
		return "", false, true
	}
	parts := strings.Fields(header)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", true, false
	}
	return parts[1], true, true
}

func constantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func (s *Server) anonymousLoopbackActive() bool {
	return s.cfg.Secret == "" && s.cfg.AllowAnonymousLoopback && s.listenerIsLoopback
}

func remoteIsLoopback(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
