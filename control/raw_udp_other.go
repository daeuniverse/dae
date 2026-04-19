//go:build !linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"fmt"
	"net/netip"
)

func sendUDPv6RawInDaeNetns(_ []byte, from, realTo netip.AddrPort) error {
	return fmt.Errorf("raw IPv6 UDP fallback unsupported on this platform: from=%v to=%v", from, realTo)
}
