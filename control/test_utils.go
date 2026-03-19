//go:build !ignore_tests

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org
 */

package control

import "net/netip"

// mustParseAddrPort parses an address:port string or panics.
// Test helper for conciseness in test code.
func mustParseAddrPort(s string) netip.AddrPort {
	addr, err := netip.ParseAddrPort(s)
	if err != nil {
		panic(err)
	}
	return addr
}
