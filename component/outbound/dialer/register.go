/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"net"

	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/protocol/direct"
	"github.com/daeuniverse/outbound/dialer/stickyip"
	"github.com/sirupsen/logrus"
)

func NewFromLink(gOption *GlobalOption, iOption InstanceOption, link string, subscriptionTag string) (*Dialer, error) {
	// First, create the protocol dialer with direct dialer to get the property
	d, _p, err := D.NewNetproxyDialerFromLink(direct.SymmetricDirect, &gOption.ExtraOption, link)
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
			"proxy_address":   p.Address,
			"needs_cache":     needsCache,
			"subscription":    subscriptionTag,
		}).Debug("[DialerRegister] Checking if sticky IP caching is needed")
	}

	// If the proxy address is a domain (not an IP), wrap with sticky IP dialer
	// This caches the proxy server's resolved IP to ensure stable connections
	// within a health check cycle, while allowing failover between cycles.
	var stickyWrapper *stickyip.StickyIpDialer
	if p.Address != "" && needsStickyIpCaching(p.Address) {
		if gOption.Log != nil {
			gOption.Log.WithField("proxy_address", p.Address).Info("[DialerRegister] Creating sticky IP dialer wrapper for proxy domain")
		}
		stickyWrapper = stickyip.NewStickyIpDialer(direct.SymmetricDirect, p.Address, globalProxyIpCache)

		// Re-create the protocol dialer with sticky wrapper as base
		d, _p, err = D.NewNetproxyDialerFromLink(stickyWrapper, &gOption.ExtraOption, link)
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
	host, _, err := net.SplitHostPort(addr)
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
