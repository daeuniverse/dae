/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"errors"
	"net"
	"net/netip"
	"strings"
	"structs"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/outbound/netproxy"
)

// canOffloadToEBPF checks if both connections are plain *net.TCPConn.
// This is primarily used in tests to verify that sniffing/prefetch wrappers
// are correctly rejected. Production code in newTCPRelayOffloadSession uses
// unwrapPlainTCPConn for the left (client) side and unwrapRelayTCPConn for
// the right (outbound) side.
func canOffloadToEBPF(left, right netproxy.Conn) bool {
	_, leftOK := left.(*net.TCPConn)
	_, rightOK := right.(*net.TCPConn)
	return leftOK && rightOK
}

func tcpRelayOffloadReason(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	if errors.Is(err, errTCPRelayOffloadUnavailable) {
		prefix := errTCPRelayOffloadUnavailable.Error()
		msg = strings.TrimPrefix(msg, prefix)
		msg = strings.TrimPrefix(msg, ":")
		msg = strings.TrimSpace(msg)
		if msg == "" {
			return "unavailable"
		}
	}
	return msg
}

func canAnnotateTCPRelayOffload(conn netproxy.Conn) bool {
	if conn == nil {
		return false
	}
	_, ok := unwrapRelayTCPConn(conn)
	return ok
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
