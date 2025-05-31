/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net"
	"net/netip"
	"strconv"
)

func RefineSourceToShow(src netip.AddrPort, dst netip.Addr) (srcToShow string) {
	if src.Addr() == dst {
		// If nothing else, this means this packet is sent from localhost.
		return net.JoinHostPort("localhost", strconv.Itoa(int(src.Port())))
	} else {
		return RefineAddrPortToShow(src)
	}
}

func RefineAddrPortToShow(addrPort netip.AddrPort) (srcToShow string) {
	return net.JoinHostPort(net.IP(addrPort.Addr().AsSlice()).String(), strconv.Itoa(int(addrPort.Port())))
}
