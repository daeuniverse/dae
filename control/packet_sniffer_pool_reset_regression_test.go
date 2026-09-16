/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"testing"
	"time"
)

func TestPacketSnifferCreationWaitsForReset(t *testing.T) {
	pool := NewPacketSnifferPool()
	defer pool.Close()
	key := NewPacketSnifferKey(
		mustParseAddrPort("192.0.2.40:42000"),
		mustParseAddrPort("198.51.100.40:443"),
		makeLikelyQuicInitialPayload(0x31),
	)

	pool.resetMu.Lock()
	locked := true
	defer func() {
		if locked {
			pool.resetMu.Unlock()
		}
	}()

	started := make(chan struct{})
	done := make(chan struct{})
	var sniffer *PacketSniffer
	var isNew bool
	go func() {
		close(started)
		sniffer, isNew = pool.GetOrCreate(key, nil)
		close(done)
	}()
	<-started

	select {
	case <-done:
		t.Fatal("sniffer creation ran during Reset's exclusive section")
	case <-time.After(100 * time.Millisecond):
	}

	pool.resetMu.Unlock()
	locked = false
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("sniffer creation did not resume after Reset")
	}
	if sniffer == nil || !isNew {
		t.Fatal("expected a new sniffer after Reset completed")
	}
	if pool.loadFlowFamily(key) == nil {
		t.Fatal("sniffer creation did not register its flow family")
	}
}
