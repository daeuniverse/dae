/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2023, mzz2017 <mzz@tuta.io>
 */

package control

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
)

func resolveDnsUpstream(dnsUpstream *url.URL) (addrPort netip.AddrPort, err error) {
	if dnsUpstream.Scheme != "udp" {
		return netip.AddrPort{}, fmt.Errorf("dns_upstream now only supports udp://")
	}
	port := dnsUpstream.Port()
	if port == "" {
		port = "53"
	}
	hostname := dnsUpstream.Hostname()
	ips, _ := net.LookupIP(hostname)
	if len(ips) == 0 {
		return netip.AddrPort{}, fmt.Errorf("cannot resolve hostname of dns upstream: %v", hostname)
	}
	// resolve hostname
	dnsAddrPort, err := netip.ParseAddrPort(net.JoinHostPort(ips[0].String(), port))
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("failed to parse DNS upstream: \"%v\": %w", dnsUpstream.String(), err)
	}
	return dnsAddrPort, nil
}
