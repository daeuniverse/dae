/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

func TestUdpEndpointCreateShardUnlocksAfterPanic(t *testing.T) {
	pool := NewUdpEndpointPool()
	defer pool.Close()

	addr := netip.MustParseAddr("192.0.2.1")
	firstKey := UdpEndpointKey{Src: netip.AddrPortFrom(addr, 10000)}
	firstShard := pool.shardFor(firstKey)
	var secondKey UdpEndpointKey
	for port := uint16(10001); port != 0; port++ {
		candidate := UdpEndpointKey{Src: netip.AddrPortFrom(addr, port)}
		if pool.shardFor(candidate) == firstShard {
			secondKey = candidate
			break
		}
	}
	if !secondKey.Src.IsValid() {
		t.Fatal("could not find a second key in the same creation shard")
	}

	staleClosed := make(chan struct{})
	stale := &UdpEndpoint{
		poolRef:      pool,
		poolKey:      firstKey,
		drainRelease: func() { close(staleClosed) },
	}
	stale.dead.Store(true)
	firstShard.mu.Lock()
	firstShard.pool[firstKey] = stale
	firstShard.mu.Unlock()

	panicked := false
	func() {
		defer func() {
			panicked = recover() != nil
		}()
		_, _, _ = pool.GetOrCreate(firstKey, &UdpEndpointOptions{
			Handler: func(*UdpEndpoint, []byte, netip.AddrPort) error { return nil },
			GetDialOption: func(context.Context) (*DialOption, error) {
				panic("dial option panic")
			},
		})
	}()
	if !panicked {
		t.Fatal("expected GetDialOption panic")
	}
	select {
	case <-staleClosed:
	default:
		t.Fatal("stale endpoint was not closed during panic unwind")
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _, _ = pool.GetOrCreate(secondKey, &UdpEndpointOptions{})
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("creation shard remained locked after panic")
	}
}
