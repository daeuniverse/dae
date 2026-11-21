/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// shouldTryRawUDPFallback decides whether a failed UDP reply may be retried
// through the raw-socket path. EINVAL is the errno the kernel returns when the
// bind address cannot be used as a source for the destination - a reply socket
// bound to 127.0.0.53 written to a LAN client for instance - so it has to be in
// scope, otherwise those replies are dropped without a retry.
func TestShouldTryRawUDPFallbackEINVAL(t *testing.T) {
	from := netip.MustParseAddrPort("127.0.0.53:53")
	to := netip.MustParseAddrPort("192.168.2.5:34545")

	for _, err := range []error{
		unix.EINVAL,
		os.NewSyscallError("sendto", unix.EINVAL),
		&net.OpError{Op: "write", Net: "udp", Err: os.NewSyscallError("sendto", unix.EINVAL)},
		errors.New("write udp 127.0.0.53:53->192.168.2.5:34545: sendto: invalid argument"),
	} {
		require.Truef(t, shouldTryRawUDPFallback(err, from, to),
			"EINVAL from %v should be retried through the raw-socket path", err)
	}
}

func TestShouldTryRawUDPFallbackStaysNarrow(t *testing.T) {
	from := netip.MustParseAddrPort("127.0.0.53:53")
	to := netip.MustParseAddrPort("192.168.2.5:34545")

	tests := []struct {
		name string
		err  error
		from netip.AddrPort
		to   netip.AddrPort
	}{
		{name: "nil error", err: nil, from: from, to: to},
		{name: "unrelated errno", err: unix.ECONNREFUSED, from: from, to: to},
		{name: "not a DNS response port", err: unix.EINVAL, from: netip.MustParseAddrPort("127.0.0.53:5353"), to: to},
		{name: "address family mismatch", err: unix.EINVAL, from: netip.MustParseAddrPort("[::1]:53"), to: to},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.False(t, shouldTryRawUDPFallback(tc.err, tc.from, tc.to))
		})
	}
}
