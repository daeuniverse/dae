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
	"strings"
	"sync"
	"testing"
	"time"

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

	// Note: ControlPlane.Close() no longer resets global UDP pools (ResetGlobalUdpState)
	// to prevent inter-generational interference during hot reloads.
	// Instead, we verify that the generation's own context and core are cleaned up.

	if plane.ctx.Err() == nil {
		t.Fatal("expected control plane context to be canceled on close")
	}

	// Verify that global state can still be reset explicitly (manual cleanup or full stop)
	ResetGlobalUdpState()
	waitForCloseSignal(t, endpointConn.closeCh, "explicit global reset closes udp endpoint")

	if got := countPooledUdpEndpoints(DefaultUdpEndpointPool); got != 0 {
		t.Fatalf("pooled udp endpoint count after explicit reset = %d, want 0", got)
	}
	if got := countPooledAnyfromConns(DefaultAnyfromPool); got != 0 {
		t.Fatalf("pooled anyfrom conn count after explicit reset = %d, want 0", got)
	}

	rebound, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(anyfromAddr))
	if err != nil {
		t.Fatalf("rebind anyfrom addr after close: %v", err)
	}
	_ = rebound.Close()
}

func TestControlPlaneClose_TimesOutSlowDeferredCleanup(t *testing.T) {
	oldTimeout := controlPlaneDeferredCleanupTimeout
	controlPlaneDeferredCleanupTimeout = 50 * time.Millisecond
	t.Cleanup(func() {
		controlPlaneDeferredCleanupTimeout = oldTimeout
	})

	plane := newShutdownTestControlPlane()
	release := make(chan struct{})
	done := make(chan struct{})
	plane.deferFuncs = []func() error{
		func() error {
			defer close(done)
			<-release
			return nil
		},
	}

	start := time.Now()
	err := plane.Close()
	elapsed := time.Since(start)

	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("ControlPlane.Close() error = %v, want timeout", err)
	}
	if elapsed >= 250*time.Millisecond {
		t.Fatalf("ControlPlane.Close() took %v, want < 250ms", elapsed)
	}
	if plane.ctx.Err() == nil {
		t.Fatal("expected control plane context to be canceled on timeout path")
	}

	close(release)
	<-done
}

func TestControlPlaneClose_Idempotent(t *testing.T) {
	plane := newShutdownTestControlPlane()
	var wg sync.WaitGroup
	count := 50
	errs := make(chan error, count)

	wg.Add(count)
	for i := 0; i < count; i++ {
		go func() {
			defer wg.Done()
			errs <- plane.Close()
		}()
	}

	// wait with timeout to detect deadlock
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(gracefulShutdownWaitTimeout + 2*time.Second):
		t.Fatal("ControlPlane.Close() deadlocked during concurrent calls")
	}

	if plane.ctx.Err() == nil {
		t.Fatal("expected control plane context to be canceled")
	}

	// Verify all callers got the same (nil) result if no errors occurred
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("expected nil error from concurrent Close(), got %v", err)
		}
	}
}
