/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package config

import (
	"fmt"
	"net/netip"
	"strings"
)

var defaultBootstrapResolvers = []netip.AddrPort{
	netip.MustParseAddrPort("119.29.29.29:53"),
	netip.MustParseAddrPort("223.5.5.5:53"),
}

func BootstrapResolvers(global *Global) ([]netip.AddrPort, error) {
	if global == nil {
		return append([]netip.AddrPort(nil), defaultBootstrapResolvers...), nil
	}

	raw := strings.TrimSpace(global.BootstrapResolver)
	if raw == "" {
		return append([]netip.AddrPort(nil), defaultBootstrapResolvers...), nil
	}

	resolver, err := netip.ParseAddrPort(raw)
	if err != nil {
		return nil, fmt.Errorf("parse global.bootstrap_resolver: %w", err)
	}
	return []netip.AddrPort{resolver}, nil
}
