//go:build !linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"errors"
	"net/netip"
)

// rejectAllowed is the non-Linux stub; dae only runs on Linux, so this path is
// never exercised. It returns true so the caller falls through to the
// (also stubbed) sendICMPPortUnreachable.
func rejectAllowed(_ netip.AddrPort) bool { return true }

// sendICMPPortUnreachable is the non-Linux stub. ICMP injection requires raw
// sockets and is only implemented for Linux.
func sendICMPPortUnreachable(_ []byte, _ netip.AddrPort) error {
	return errors.New("icmp_inject: not supported on this platform")
}
