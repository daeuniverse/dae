/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"testing"
	"time"
)

// TestUpdateNatTimeoutSkipsUnchangedValue is a regression guard: the UDP fast
// paths recompute the same effective NAT timeout on every packet, and each call
// used to take the natTimeout write lock, force a deadline bump and refresh the
// cached reply sockets. An unchanged value must hand the renewal back to the
// throttled RefreshTtl instead of forcing it.
func TestUpdateNatTimeoutSkipsUnchangedValue(t *testing.T) {
	ue := &UdpEndpoint{}
	ue.setNatTimeout(QuicNatTimeout)
	// A recent refresh puts the throttled path to sleep, so any deadline change
	// below can only come from a forced update.
	ue.lastRefreshNano.Store(time.Now().UnixNano())
	const sentinel = int64(424242)
	ue.expiresAtNano.Store(sentinel)

	ue.UpdateNatTimeout(QuicNatTimeout)
	if got := ue.expiresAtNano.Load(); got != sentinel {
		t.Fatalf("unchanged timeout forced a deadline bump: expiresAtNano = %d, want %d", got, sentinel)
	}
	if got := ue.natTimeout(); got != QuicNatTimeout {
		t.Fatalf("natTimeout = %v, want %v", got, QuicNatTimeout)
	}

	// A real change must still force the update immediately.
	ue.UpdateNatTimeout(QuicNatTimeout * 2)
	if got := ue.natTimeout(); got != QuicNatTimeout*2 {
		t.Fatalf("natTimeout after change = %v, want %v", got, QuicNatTimeout*2)
	}
	if got := ue.expiresAtNano.Load(); got == sentinel {
		t.Fatal("changed timeout must refresh the deadline")
	}

	// Non-positive timeouts stay a no-op.
	before := ue.natTimeout()
	ue.expiresAtNano.Store(sentinel)
	ue.UpdateNatTimeout(0)
	ue.UpdateNatTimeout(-time.Second)
	if got := ue.natTimeout(); got != before {
		t.Fatalf("non-positive timeout changed natTimeout to %v, want %v", got, before)
	}
	if got := ue.expiresAtNano.Load(); got != sentinel {
		t.Fatalf("non-positive timeout changed the deadline: %d", got)
	}
}
