/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net"
	"net/netip"
	"structs"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/outbound/netproxy"
)

// canOffloadToEBPF checks if both connections are plain *net.TCPConn.
// This is primarily used in tests. Production code uses unwrapPlainTCPConn
// to avoid redundant type assertions.
func canOffloadToEBPF(left, right netproxy.Conn) bool {
	_, leftOK := left.(*net.TCPConn)
	_, rightOK := right.(*net.TCPConn)
	return leftOK && rightOK
}

func makeTuplesKey(src, dst netip.AddrPort, l4proto uint8) bpfTuplesKey {
	srcIP := src.Addr().As16()
	dstIP := dst.Addr().As16()
	return bpfTuplesKey{
		Sip: struct {
			_       structs.HostLayout
			U6Addr8 [16]uint8
		}{U6Addr8: srcIP},
		Sport: common.Htons(src.Port()),
		Dip: struct {
			_       structs.HostLayout
			U6Addr8 [16]uint8
		}{U6Addr8: dstIP},
		Dport:   common.Htons(dst.Port()),
		L4proto: l4proto,
	}
}
