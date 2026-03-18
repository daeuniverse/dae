/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"errors"
	"net/netip"
	"strings"
	"structs"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/outbound/netproxy"
)

// canOffloadToEBPF reports whether both connections resolve to concrete TCP
// sockets that dae can hand to the eBPF relay path. This is a capability
// predicate only: callers still need to flush any dae-local prefetched bytes
// (for example prefixedConn / ConnSniffer data) before attempting offload.
func canOffloadToEBPF(left, right netproxy.Conn) bool {
	return canResolveTCPRelayOffloadConn(left) && canResolveTCPRelayOffloadConn(right)
}

func canResolveTCPRelayOffloadConn(conn netproxy.Conn) bool {
	if conn == nil {
		return false
	}
	_, ok := unwrapRelayTCPConn(conn)
	return ok
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

func tcpRelayPrefetchOffloadSkipReason(sniffAttempted bool, clientPayloadReady bool) string {
	// Server-first/no-early-client-payload flow restriction removed:
	// eBPF offload works correctly regardless of whether client payload arrived
	// early. The kernel-side socket redirection (splice/sockmap) is independent
	// of userspace buffering state. As long as both connections can be unwrapped
	// to *net.TCPConn and have no pending kernel queue data, offload can proceed.
	//
	// This change significantly improves performance for server-first protocols
	// (like certain TLS configurations) where the client may not send data
	// immediately after connection establishment.
	return ""
}

func canAnnotateTCPRelayOffload(conn netproxy.Conn) bool {
	return canResolveTCPRelayOffloadConn(conn)
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
