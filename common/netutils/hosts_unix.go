//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

// Read static host entries from /etc/hosts.

package netutils

import (
	"bufio"
	"net/netip"
	"os"
	"strings"
)

// hostsFilePath is a variable so tests can point it at a fixture.
var hostsFilePath = "/etc/hosts"

// HostsLookup returns the addresses for host from the system hosts file, in
// file order. Matching is case-insensitive and ignores a trailing dot. It never
// performs a DNS query, so it is safe to call before any resolver that could
// loop back into dae.
func HostsLookup(host string) []netip.Addr {
	host = strings.TrimSuffix(strings.TrimSpace(host), ".")
	if host == "" {
		return nil
	}
	f, err := os.Open(hostsFilePath)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()

	var addrs []netip.Addr
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		addr, err := netip.ParseAddr(fields[0])
		if err != nil {
			continue
		}
		for _, name := range fields[1:] {
			if strings.EqualFold(strings.TrimSuffix(name, "."), host) {
				addrs = append(addrs, addr)
				break
			}
		}
	}
	return addrs
}

// HostsResolveIp46 returns the first IPv4 and IPv6 address for host found in
// the system hosts file. ok is false when the host is absent.
func HostsResolveIp46(host string) (ip46 Ip46, ok bool) {
	for _, raw := range HostsLookup(host) {
		addr := raw.Unmap()
		if addr.Is4() && !ip46.Ip4.IsValid() {
			ip46.Ip4 = addr
			ok = true
		} else if addr.Is6() && !ip46.Ip6.IsValid() {
			ip46.Ip6 = addr
			ok = true
		}
	}
	return ip46, ok
}
