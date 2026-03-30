/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@daeuniverse.org>
 */

package control

import (
	"net/netip"
	"testing"
	"time"
)

func mustParseTcpSniffAddrPort(t *testing.T, s string) netip.AddrPort {
	t.Helper()
	return netip.MustParseAddrPort(s)
}

func TestNoteTcpSniffFailure_AssignsExpiry(t *testing.T) {
	now := time.Now()
	cp := &ControlPlane{
		tcpSniffNegSet: make(map[tcpSniffNegKey]tcpSniffNegEntry),
	}
	key := newTcpSniffNegKey(mustParseTcpSniffAddrPort(t, "198.51.100.20:443"), nil)

	cp.noteTcpSniffFailure(key, now)

	entry, ok := cp.tcpSniffNegSet[key]
	if !ok {
		t.Fatal("expected negative cache entry to be stored")
	}
	if entry.failures != tcpSniffFailureThreshold {
		t.Fatalf("failures = %d, want %d", entry.failures, tcpSniffFailureThreshold)
	}
	if entry.expiresAtUnixNano <= now.UnixNano() {
		t.Fatalf("expiresAtUnixNano = %d, want > %d", entry.expiresAtUnixNano, now.UnixNano())
	}
}

func TestCleanupNegativeCaches_RemovesExpiredTcpSniffEntries(t *testing.T) {
	now := time.Now()
	cp := &ControlPlane{
		tcpSniffNegSet: make(map[tcpSniffNegKey]tcpSniffNegEntry),
	}
	expiredKey := newTcpSniffNegKey(mustParseTcpSniffAddrPort(t, "198.51.100.20:443"), nil)
	liveKey := newTcpSniffNegKey(mustParseTcpSniffAddrPort(t, "198.51.100.21:443"), nil)

	cp.tcpSniffNegSet[expiredKey] = tcpSniffNegEntry{
		failures:          tcpSniffFailureThreshold,
		expiresAtUnixNano: now.Add(-time.Second).UnixNano(),
	}
	cp.tcpSniffNegSet[liveKey] = tcpSniffNegEntry{
		failures:          tcpSniffFailureThreshold,
		expiresAtUnixNano: now.Add(time.Second).UnixNano(),
	}

	cp.cleanupNegativeCaches(now)

	if _, ok := cp.tcpSniffNegSet[expiredKey]; ok {
		t.Fatal("expired tcp sniff negative cache entry should be removed")
	}
	if _, ok := cp.tcpSniffNegSet[liveKey]; !ok {
		t.Fatal("live tcp sniff negative cache entry should be kept")
	}
}
