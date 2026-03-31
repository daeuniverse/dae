/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"io"
	"net"
	"net/netip"
	"testing"

	"github.com/sirupsen/logrus"
)

func countPooledAnyfromConns(p *AnyfromPool) int {
	total := 0
	for i := range anyfromPoolShardCount {
		shard := &p.shards[i]
		shard.mu.RLock()
		total += len(shard.pool)
		shard.mu.RUnlock()
	}
	return total
}

func newShutdownTestControlPlane() *ControlPlane {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	ctx, cancel := context.WithCancel(context.Background())
	coreCtx, coreCancel := context.WithCancel(context.Background())

	return &ControlPlane{
		log:                 logger,
		ctx:                 ctx,
		cancel:              cancel,
		core:                &controlPlaneCore{closed: coreCtx, close: coreCancel},
		failedQuicDcidCache: newFailedQuicDcidCache(1),
	}
}

func TestControlPlaneClose_ResetsGlobalUdpPoolsAndClosesSockets(t *testing.T) {
	oldEndpointPool := DefaultUdpEndpointPool
	oldAnyfromPool := DefaultAnyfromPool
	oldTaskPool := DefaultUdpTaskPool
	oldSnifferPool := DefaultPacketSnifferSessionMgr

	DefaultUdpEndpointPool = NewUdpEndpointPool()
	DefaultAnyfromPool = newTestAnyfromPoolWithoutJanitor()
	DefaultUdpTaskPool = NewUdpTaskPool()
	DefaultPacketSnifferSessionMgr = NewPacketSnifferPool()

	defer func() {
		DefaultUdpEndpointPool.Reset()
		DefaultAnyfromPool.Reset()
		DefaultUdpTaskPool.Reset()
		DefaultPacketSnifferSessionMgr.Reset()
		DefaultUdpEndpointPool = oldEndpointPool
		DefaultAnyfromPool = oldAnyfromPool
		DefaultUdpTaskPool = oldTaskPool
		DefaultPacketSnifferSessionMgr = oldSnifferPool
	}()

	endpointKey := UdpEndpointKey{Src: netip.MustParseAddrPort("127.0.0.1:15001")}
	endpointConn := &scriptedPacketConn{
		reads:   make(chan scriptedPacketRead),
		closeCh: make(chan struct{}),
	}
	endpoint := &UdpEndpoint{
		conn:       endpointConn,
		NatTimeout: DefaultNatTimeout,
		handler:    func(_ *UdpEndpoint, _ []byte, _ netip.AddrPort) error { return nil },
		poolRef:    DefaultUdpEndpointPool,
		poolKey:    endpointKey,
	}
	endpointShard := DefaultUdpEndpointPool.shardFor(endpointKey)
	endpointShard.mu.Lock()
	endpointShard.pool[endpointKey] = endpoint
	endpointShard.mu.Unlock()

	anyfromConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP(anyfrom): %v", err)
	}
	anyfromAddr := anyfromConn.LocalAddr().(*net.UDPAddr).AddrPort()
	anyfrom := &Anyfrom{
		UDPConn: anyfromConn,
		ttl:     AnyfromTimeout,
	}
	anyfrom.RefreshTtl()
	anyfromShard := DefaultAnyfromPool.shardFor(anyfromAddr)
	anyfromShard.mu.Lock()
	anyfromShard.pool[anyfromAddr] = anyfrom
	anyfromShard.mu.Unlock()

	plane := newShutdownTestControlPlane()
	if err := plane.Close(); err != nil {
		t.Fatalf("ControlPlane.Close() error = %v", err)
	}

	waitForCloseSignal(t, endpointConn.closeCh, "control plane shutdown closes udp endpoint")

	if got := countPooledUdpEndpoints(DefaultUdpEndpointPool); got != 0 {
		t.Fatalf("pooled udp endpoint count after close = %d, want 0", got)
	}
	if got := countPooledAnyfromConns(DefaultAnyfromPool); got != 0 {
		t.Fatalf("pooled anyfrom conn count after close = %d, want 0", got)
	}
	if plane.ctx.Err() == nil {
		t.Fatal("expected control plane context to be canceled on close")
	}

	rebound, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(anyfromAddr))
	if err != nil {
		t.Fatalf("rebind anyfrom addr after close: %v", err)
	}
	_ = rebound.Close()
}
