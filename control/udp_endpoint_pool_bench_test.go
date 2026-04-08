/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"io"
	"testing"

	componentdialer "github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/sirupsen/logrus"
)

func benchmarkLegacyEndpointGenerationCurrent(p *UdpEndpointPool, ue *UdpEndpoint) bool {
	if ue == nil || ue.Dialer == nil {
		return true
	}
	if udpEndpointIgnoresDialerHealth(ue) {
		return true
	}
	return ue.dialerGeneration == p.currentDialerGeneration(ue.Dialer, udpEndpointNetworkType(ue))
}

func benchmarkLegacyUdpEndpointPoolGet(p *UdpEndpointPool, key UdpEndpointKey) (*UdpEndpoint, bool) {
	shard := p.shardFor(key)
	shard.mu.RLock()
	defer shard.mu.RUnlock()

	ue, ok := shard.pool[key]
	if !ok {
		return nil, false
	}
	if ue.failed.Load() || ue.IsDead() || (!benchmarkLegacyEndpointGenerationCurrent(p, ue) && !p.endpointSurvivesDialerInvalidation(ue)) {
		return nil, false
	}
	return ue, true
}

func newBenchmarkUdpEndpointPool(b *testing.B) (*UdpEndpointPool, UdpEndpointKey, *UdpEndpoint) {
	b.Helper()

	logger := logrus.New()
	logger.SetOutput(io.Discard)

	pool := NewUdpEndpointPool()
	b.Cleanup(pool.Close)

	d := newTestProxyEndpointDialer("hysteria2", "proxy.example:443")
	key := UdpEndpointKey{
		Src: mustParseAddrPort("192.0.2.10:40000"),
		Dst: mustParseAddrPort("198.51.100.20:443"),
	}
	networkType := componentdialer.NetworkType{
		L4Proto:         "udp",
		IpVersion:       "4",
		UdpHealthDomain: componentdialer.UdpHealthDomainData,
	}
	counter := pool.dialerEpochCounter(d, networkType)

	ue := &UdpEndpoint{
		Dialer:              d,
		Outbound:            nil,
		log:                 logger,
		lAddr:               key.Src,
		poolRef:             pool,
		poolKey:             key,
		dialerGeneration:    counter.Load(),
		dialerGenerationRef: counter,
		endpointNetworkType: networkType,
		lifecycleProfile:    newDataSessionLifecycleProfile(d),
	}
	ue.expiresAtNano.Store(1<<62 - 1)

	shard := pool.shardFor(key)
	shard.mu.Lock()
	shard.pool[key] = ue
	shard.mu.Unlock()

	return pool, key, ue
}

func BenchmarkUdpEndpointGenerationCurrent(b *testing.B) {
	pool, _, ue := newBenchmarkUdpEndpointPool(b)

	b.Run("Current", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = pool.endpointGenerationCurrent(ue)
		}
	})

	b.Run("Legacy", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = benchmarkLegacyEndpointGenerationCurrent(pool, ue)
		}
	})
}

func BenchmarkUdpEndpointPoolGet(b *testing.B) {
	pool, key, _ := newBenchmarkUdpEndpointPool(b)

	b.Run("Current", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, _ = pool.Get(key)
		}
	})

	b.Run("Legacy", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, _ = benchmarkLegacyUdpEndpointPoolGet(pool, key)
		}
	})
}
