/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package config

import (
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
)

// ListenHostPort parses Api.Listen as a numeric IP and port.
func (a Api) ListenHostPort() (string, int, error) {
	host, portStr, err := net.SplitHostPort(a.Listen)
	if err != nil {
		return "", 0, fmt.Errorf("api.listen %q: %w", a.Listen, err)
	}
	if host == "" {
		return "", 0, fmt.Errorf("api.listen %q: host must not be empty", a.Listen)
	}
	if net.ParseIP(host) == nil {
		return "", 0, fmt.Errorf("api.listen %q: host must be a numeric IP", a.Listen)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, fmt.Errorf("api.listen %q: invalid port: %w", a.Listen, err)
	}
	if port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("api.listen %q: port must be in 1..65535", a.Listen)
	}
	return host, port, nil
}

// ListenerIsLoopback reports whether the configured listen address is loopback.
func (a Api) ListenerIsLoopback() bool {
	host, _, err := a.ListenHostPort()
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// AnonymousLoopbackActive reports whether an unauthenticated loopback caller is
// admitted under the configured token mode.
func (a Api) AnonymousLoopbackActive() bool {
	return a.Enabled && a.Secret == "" && a.AllowAnonymousLoopback && a.ListenerIsLoopback()
}

// Validate checks the listener and authentication configuration.
func (a Api) Validate() error {
	if !a.Enabled {
		return nil
	}
	if _, _, err := a.ListenHostPort(); err != nil {
		return err
	}

	if a.Secret != "" {
		if err := validateAPISecret(a.Secret); err != nil {
			return fmt.Errorf("api.secret: %w", err)
		}
	} else {
		if !a.AllowAnonymousLoopback {
			return fmt.Errorf("api: secret is empty and allow_anonymous_loopback is false")
		}
		if !a.ListenerIsLoopback() {
			return fmt.Errorf("api: non-loopback listener requires secret")
		}
	}

	for _, origin := range a.AllowOrigins {
		if err := validateAPIOrigin(origin); err != nil {
			return fmt.Errorf("api.allow_origins: %w", err)
		}
	}
	for _, host := range a.AllowedHosts {
		if err := validateAPIAllowedHost(host); err != nil {
			return fmt.Errorf("api.allowed_hosts: %w", err)
		}
	}
	if a.UI != "" {
		if err := validateAPIUIDir(a.UI); err != nil {
			return fmt.Errorf("api.ui: %w", err)
		}
	}
	return nil
}

// validateAPIUIDir requires an absolute path, since a relative one would depend
// on the daemon's working directory. Whether the directory is usable is checked
// at startup only: a missing UI must not stop the proxy.
func validateAPIUIDir(dir string) error {
	if !filepath.IsAbs(dir) {
		return fmt.Errorf("%q must be an absolute path", dir)
	}
	return nil
}

// Warnings returns non-fatal deployment advisories. Callers log them at startup.
func (a Api) Warnings() []string {
	if !a.Enabled {
		return nil
	}
	var warnings []string
	if a.Secret != "" && a.AllowAnonymousLoopback {
		warnings = append(warnings, "api.allow_anonymous_loopback has no effect while secret is set")
	}
	if !a.ListenerIsLoopback() {
		warnings = append(warnings, "api listens on a non-loopback address; terminate TLS at a trusted reverse proxy")
		if a.Secret != "" && len(a.Secret) < 16 {
			warnings = append(warnings, "api.secret is shorter than 16 bytes; use an unpredictable token")
		}
	}
	return warnings
}

func validateAPISecret(secret string) error {
	if secret == "" {
		return fmt.Errorf("must not be empty")
	}
	for i := 0; i < len(secret); i++ {
		c := secret[i]
		if c < 0x21 || c > 0x7e || c == ',' {
			return fmt.Errorf("must be visible ASCII without whitespace or commas")
		}
	}
	return nil
}

func validateAPIOrigin(origin string) error {
	if origin == "" {
		return fmt.Errorf("origin must not be empty")
	}
	u, err := url.Parse(origin)
	if err != nil {
		return err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("%q: scheme must be http or https", origin)
	}
	if u.Host == "" || u.User != nil {
		return fmt.Errorf("%q: origin must have a host and no userinfo", origin)
	}
	if strings.Contains(u.Host, "*") {
		return fmt.Errorf("%q: wildcard origins are not allowed", origin)
	}
	if u.Path != "" {
		return fmt.Errorf("%q: origin must not have a path", origin)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("%q: origin must not have query or fragment", origin)
	}
	if port := u.Port(); port != "" {
		p, err := strconv.Atoi(port)
		if err != nil || p < 1 || p > 65535 {
			return fmt.Errorf("%q: invalid port", origin)
		}
	}
	return nil
}

func validateAPIAllowedHost(value string) error {
	if value == "" {
		return fmt.Errorf("host must not be empty")
	}
	if strings.ContainsAny(value, " \t\r\n") {
		return fmt.Errorf("%q: host must not contain whitespace", value)
	}
	if strings.ContainsAny(value, "*/?#@") {
		return fmt.Errorf("%q: host must not contain scheme, path, credentials or wildcards", value)
	}

	host := value
	portStr := ""
	switch {
	case strings.HasPrefix(value, "["):
		end := strings.LastIndex(value, "]")
		if end < 0 {
			return fmt.Errorf("%q: invalid bracketed IPv6 host", value)
		}
		host = value[:end+1]
		if end+1 < len(value) {
			if value[end+1] != ':' {
				return fmt.Errorf("%q: invalid host suffix", value)
			}
			portStr = value[end+2:]
		}
	case strings.Count(value, ":") == 1:
		host, portStr, _ = strings.Cut(value, ":")
	case strings.Count(value, ":") > 1:
		return fmt.Errorf("%q: IPv6 host must be bracketed", value)
	}
	if host == "" {
		return fmt.Errorf("%q: host must not be empty", value)
	}
	if portStr != "" {
		p, err := strconv.Atoi(portStr)
		if err != nil || p < 1 || p > 65535 {
			return fmt.Errorf("%q: invalid port", value)
		}
	}
	return nil
}
