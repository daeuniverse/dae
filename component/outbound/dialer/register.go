/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"encoding/base64"
	"net"
	"net/url"
	"strings"

	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/dialer/stickyip"
	"github.com/daeuniverse/outbound/protocol/direct"
	"github.com/sirupsen/logrus"
)

func NewFromLink(gOption *GlobalOption, iOption InstanceOption, link string, subscriptionTag string) (*Dialer, error) {
	normalizedLink := normalizeShadowTLSPluginOptions(link)

	// First, create the protocol dialer with direct dialer to get the property
	d, _p, err := D.NewNetproxyDialerFromLink(direct.SymmetricDirect, &gOption.ExtraOption, normalizedLink)
	if err != nil {
		return nil, err
	}
	p := Property{
		Property:        *_p,
		SubscriptionTag: subscriptionTag,
	}

	// Debug: log proxy address type
	if gOption.Log != nil && gOption.Log.IsLevelEnabled(logrus.DebugLevel) {
		needsCache := p.Address != "" && needsStickyIpCaching(p.Address)
		gOption.Log.WithFields(logrus.Fields{
			"proxy_address": p.Address,
			"needs_cache":   needsCache,
			"subscription":  subscriptionTag,
		}).Debug("[DialerRegister] Checking if sticky IP caching is needed")
	}

	// If the proxy address is a domain (not an IP), wrap with sticky IP dialer
	// This caches the proxy server's resolved IP to ensure stable connections
	// within a health check cycle, while allowing failover between cycles.
	var stickyWrapper *stickyip.StickyIpDialer
	if p.Address != "" && needsStickyIpCaching(p.Address) {
		if gOption.Log != nil && gOption.Log.IsLevelEnabled(logrus.DebugLevel) {
			gOption.Log.WithField("proxy_address", p.Address).Debug("[DialerRegister] Creating sticky IP dialer wrapper for proxy domain")
		}
		stickyWrapper = stickyip.NewStickyIpDialer(direct.SymmetricDirect, p.Address, globalProxyIpCache)

		// Re-create the protocol dialer with sticky wrapper as base
		d, _p, err = D.NewNetproxyDialerFromLink(stickyWrapper, &gOption.ExtraOption, normalizedLink)
		if err != nil {
			return nil, err
		}
		p = Property{
			Property:        *_p,
			SubscriptionTag: subscriptionTag,
		}
	} else if p.Address != "" {
		// Proxy is an IP address, no caching needed
		if gOption.Log != nil && gOption.Log.IsLevelEnabled(logrus.DebugLevel) {
			gOption.Log.WithField("proxy_address", p.Address).Debug("[DialerRegister] Proxy is IP address - no sticky IP caching needed")
		}
	}

	daeDialer := NewDialer(d, gOption, iOption, &p)

	// Store reference to sticky wrapper for health check cycle management
	if stickyWrapper != nil {
		daeDialer.stickyIpDialer = stickyWrapper
	}

	return daeDialer, nil
}

// needsStickyIpCaching checks if the given address needs sticky IP caching.
// Only domain addresses benefit from caching; IP addresses are already stable.
func needsStickyIpCaching(addr string) bool {
	host, _, err := stickyip.SplitHostPort(addr)
	if err != nil {
		return false
	}
	// If it's already an IP address, no need to cache
	if ip := net.ParseIP(host); ip != nil {
		return false
	}
	// It's a domain - cache it
	return true
}

// normalizeShadowTLSPluginOptions normalizes shadow-tls SIP003 plugin options in ss links.
//
// Compatibility cases:
//  1. Convert shadowtls;...;skipVerify=true to allowInsecure=true.
//  2. Convert flag-style booleans (allowInsecure/insecure without value) to "...=true".
//
// This keeps dae compatible with subscription links that use option names/forms
// not recognized by outbound's current ParseSip003Opts implementation.
func normalizeShadowTLSPluginOptions(link string) string {
	normalized, ok := normalizeShadowTLSPluginOptionsInURL(link)
	if ok {
		return normalized
	}
	return normalizeShadowTLSPluginOptionsInBase64Link(link)
}

func normalizeShadowTLSPluginOptionsInURL(link string) (string, bool) {
	u, err := url.Parse(link)
	if err != nil {
		return link, false
	}
	if !isSSScheme(u.Scheme) {
		return link, false
	}
	q := u.Query()
	plugin := q.Get("plugin")
	if plugin == "" {
		return link, false
	}

	normalizedPlugin, changed := normalizeShadowTLSSIP003Plugin(plugin)
	if !changed {
		return link, false
	}
	q.Set("plugin", normalizedPlugin)
	u.RawQuery = q.Encode()
	return u.String(), true
}

func normalizeShadowTLSPluginOptionsInBase64Link(link string) string {
	u, err := url.Parse(link)
	if err != nil || !isSSScheme(u.Scheme) {
		return link
	}

	_, payloadAndFragment, ok := strings.Cut(link, "://")
	if !ok {
		return link
	}
	payload, fragment, _ := strings.Cut(payloadAndFragment, "#")
	if payload == "" {
		return link
	}

	decodedPayload, ok := decodeSSBase64Payload(payload)
	if !ok {
		return link
	}

	decodedLink := "ss://" + decodedPayload
	if fragment != "" {
		decodedLink += "#" + fragment
	}

	normalized, changed := normalizeShadowTLSPluginOptionsInURL(decodedLink)
	if !changed {
		return link
	}
	return normalized
}

func decodeSSBase64Payload(payload string) (string, bool) {
	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.RawURLEncoding,
	}
	for _, enc := range encodings {
		decoded, err := enc.DecodeString(payload)
		if err == nil {
			return string(decoded), true
		}
	}
	return "", false
}

func isSSScheme(scheme string) bool {
	switch strings.ToLower(scheme) {
	case "ss", "shadowsocks":
		return true
	default:
		return false
	}
}

func normalizeShadowTLSSIP003Plugin(plugin string) (string, bool) {
	fields := strings.Split(plugin, ";")
	if len(fields) == 0 {
		return plugin, false
	}
	switch strings.ToLower(fields[0]) {
	case "shadowtls", "shadow-tls", "sstls":
	default:
		return plugin, false
	}

	changed := false
	for i := 1; i < len(fields); i++ {
		field := fields[i]
		if field == "" {
			continue
		}

		key, value, hasValue := strings.Cut(field, "=")
		lowerKey := strings.ToLower(key)

		switch lowerKey {
		case "skipverify":
			if !hasValue || value == "" {
				value = "true"
			}
			fields[i] = "allowInsecure=" + value
			changed = true
		case "allowinsecure", "allow_insecure", "insecure", "skip-cert-verify":
			if !hasValue || value == "" {
				fields[i] = key + "=true"
				changed = true
			}
		}
	}

	if !changed {
		return plugin, false
	}
	return strings.Join(fields, ";"), true
}
