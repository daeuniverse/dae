/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestPacketSnifferPool_CreateMuMap_NoLeakUnderConcurrency(t *testing.T) {
	p := NewPacketSnifferPool()
	key := PacketSnifferKey{
		LAddr: netip.MustParseAddrPort("10.0.0.1:12345"),
		RAddr: netip.MustParseAddrPort("8.8.8.8:53"),
	}

	const workers = 64
	var created atomic.Int32
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sniffer, isNew := p.GetOrCreate(key, &PacketSnifferOptions{Ttl: time.Second})
			require.NotNil(t, sniffer)
			if isNew {
				created.Add(1)
			}
		}()
	}

	wg.Wait()
	require.EqualValues(t, 1, created.Load(), "only one packet sniffer should be created for the same key")

	sniffer := p.Get(key)
	require.NotNil(t, sniffer)
	require.NoError(t, p.Remove(key, sniffer))
	require.Nil(t, p.Get(key), "sniffer should be removed after Remove")
}

func TestUdpEndpointPool_CreateMuMap_NoLeakOnConcurrentError(t *testing.T) {
	p := NewUdpEndpointPool()
	lAddr := netip.MustParseAddrPort("10.0.0.2:54321")

	const workers = 64
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, err := p.GetOrCreate(lAddr, &UdpEndpointOptions{})
			require.Error(t, err)
		}()
	}

	wg.Wait()

	ue, ok := p.Get(lAddr)
	require.False(t, ok)
	require.Nil(t, ue)

}
