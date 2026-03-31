/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"io"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	ob "github.com/daeuniverse/dae/component/outbound"
	componentdialer "github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/sirupsen/logrus"
)

type recordedSimulationConnFactory struct {
	mu    sync.Mutex
	conns []*udpReuseSimulationConn
}

func (f *recordedSimulationConnFactory) newConn() netproxy.Conn {
	conn := &udpReuseSimulationConn{
		reads:      make(chan scriptedPacketRead, 1),
		readExitCh: make(chan error, 1),
		closeCh:    make(chan struct{}),
	}
	f.mu.Lock()
	f.conns = append(f.conns, conn)
	f.mu.Unlock()
	return conn
}

func (f *recordedSimulationConnFactory) connAt(t *testing.T, idx int) *udpReuseSimulationConn {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		f.mu.Lock()
		if len(f.conns) > idx {
			conn := f.conns[idx]
			f.mu.Unlock()
			return conn
		}
		f.mu.Unlock()
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for conn index %d", idx)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func newTestRandomOutboundGroup(dialers ...*componentdialer.Dialer) *ob.DialerGroup {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	annotations := make([]*componentdialer.Annotation, 0, len(dialers))
	for range dialers {
		annotations = append(annotations, &componentdialer.Annotation{})
	}
	return ob.NewDialerGroup(
		&componentdialer.GlobalOption{
			Log:           logger,
			CheckInterval: time.Second,
		},
		"random-test",
		dialers,
		annotations,
		ob.DialerSelectionPolicy{
			Policy: consts.DialerSelectionPolicy_Random,
		},
		func(bool, *componentdialer.NetworkType, bool) {},
	)
}

func waitForUdpEndpointRemoval(t *testing.T, key UdpEndpointKey) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, ok := DefaultUdpEndpointPool.Get(key); !ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for UDP endpoint removal: %v", key)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func injectHardReadErrorAndWait(t *testing.T, conn *udpReuseSimulationConn) {
	t.Helper()
	conn.reads <- scriptedPacketRead{err: io.ErrUnexpectedEOF}
	select {
	case err := <-conn.readExitCh:
		if err != io.ErrUnexpectedEOF {
			t.Fatalf("read loop err = %v, want %v", err, io.ErrUnexpectedEOF)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for hard read error to retire endpoint")
	}
	select {
	case <-conn.closeCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for endpoint close after hard read error")
	}
}

func udp4NetworkType() *componentdialer.NetworkType {
	return &componentdialer.NetworkType{
		L4Proto:   consts.L4ProtoStr_UDP,
		IpVersion: consts.IpVersionStr_4,
		IsDns:     false,
	}
}

func TestHandlePkt_UpstreamHardErrorsCauseSameFlowRedial(t *testing.T) {
	oldPool := DefaultUdpEndpointPool
	DefaultUdpEndpointPool = NewUdpEndpointPool()
	defer func() {
		DefaultUdpEndpointPool.Reset()
		DefaultUdpEndpointPool = oldPool
	}()

	factory := &recordedSimulationConnFactory{}
	d, underlay := newFactoryProxyEndpointDialer("hysteria2", "proxy.example:443", factory.newConn)
	cp := newUdpReuseSimulationControlPlane(newTestFixedOutboundGroup(d))

	src := mustParseAddrPort("192.168.89.3:42687")
	dst := mustParseAddrPort("52.199.194.44:23002")
	payload := []byte{0x31, 0x32, 0x33, 0x34}
	flowDecision := ClassifyUdpFlow(src, dst, payload)
	key := flowDecision.FullConeNatEndpointKey()

	for i := 0; i < 3; i++ {
		routingResult := &bpfRoutingResult{
			Outbound: uint8(consts.OutboundUserDefinedMin),
		}
		if err := cp.handlePkt(nil, payload, src, dst, routingResult, flowDecision, false); err != nil {
			t.Fatalf("handlePkt(%d): %v", i+1, err)
		}
		if got := underlay.calls.Load(); got != int32(i+1) {
			t.Fatalf("DialContext calls after packet %d = %d, want %d", i+1, got, i+1)
		}
		ue, ok := DefaultUdpEndpointPool.Get(key)
		if !ok || ue == nil {
			t.Fatalf("expected endpoint to exist after packet %d", i+1)
		}
		if i == 2 {
			break
		}
		conn := factory.connAt(t, i)
		injectHardReadErrorAndWait(t, conn)
		waitForUdpEndpointRemoval(t, key)
	}
}

func TestHandlePkt_HealthDeathStopsNewUdpDialSelection(t *testing.T) {
	oldPool := DefaultUdpEndpointPool
	DefaultUdpEndpointPool = NewUdpEndpointPool()
	defer func() {
		DefaultUdpEndpointPool.Reset()
		DefaultUdpEndpointPool = oldPool
	}()

	conn := &udpReuseSimulationConn{
		reads:   make(chan scriptedPacketRead),
		closeCh: make(chan struct{}),
	}
	d, underlay := newCountingProxyEndpointDialer("hysteria2", "proxy.example:443", conn)
	cp := newUdpReuseSimulationControlPlane(newTestRandomOutboundGroup(d))

	src := mustParseAddrPort("192.168.89.3:42687")
	dst := mustParseAddrPort("52.199.194.44:23002")
	payload := []byte{0x41, 0x42, 0x43, 0x44}
	flowDecision := ClassifyUdpFlow(src, dst, payload)
	key := flowDecision.FullConeNatEndpointKey()

	routingResult := &bpfRoutingResult{
		Outbound: uint8(consts.OutboundUserDefinedMin),
	}
	if err := cp.handlePkt(nil, payload, src, dst, routingResult, flowDecision, false); err != nil {
		t.Fatalf("first handlePkt: %v", err)
	}
	if got := underlay.calls.Load(); got != 1 {
		t.Fatalf("DialContext calls after first packet = %d, want 1", got)
	}

	d.ReportUnavailableForced(udp4NetworkType(), io.ErrUnexpectedEOF)
	removed := DefaultUdpEndpointPool.InvalidateDialerNetworkType(d, udp4NetworkType())
	if removed != 1 {
		t.Fatalf("InvalidateDialerNetworkType removed = %d, want 1", removed)
	}
	waitForUdpEndpointRemoval(t, key)

	if err := cp.handlePkt(nil, payload, src, dst, routingResult, flowDecision, false); err != nil {
		t.Fatalf("second handlePkt after health death: %v", err)
	}
	if got := underlay.calls.Load(); got != 1 {
		t.Fatalf("DialContext calls after health death = %d, want 1", got)
	}
	if _, ok := DefaultUdpEndpointPool.Get(key); ok {
		t.Fatal("expected no endpoint to be recreated while dialer is unhealthy")
	}
}

func TestHandlePkt_NewEndpointOnlyAppearsAfterInstabilityEventOrReset(t *testing.T) {
	oldPool := DefaultUdpEndpointPool
	DefaultUdpEndpointPool = NewUdpEndpointPool()
	defer func() {
		DefaultUdpEndpointPool.Reset()
		DefaultUdpEndpointPool = oldPool
	}()

	factory := &recordedSimulationConnFactory{}
	d, underlay := newFactoryProxyEndpointDialer("hysteria2", "proxy.example:443", factory.newConn)
	cp := newUdpReuseSimulationControlPlane(newTestFixedOutboundGroup(d))

	src := mustParseAddrPort("192.168.89.3:42687")
	dst := mustParseAddrPort("52.199.194.44:23002")
	payload := []byte{0x51, 0x52, 0x53, 0x54}
	flowDecision := ClassifyUdpFlow(src, dst, payload)
	key := flowDecision.FullConeNatEndpointKey()

	routingResult := &bpfRoutingResult{
		Outbound: uint8(consts.OutboundUserDefinedMin),
	}
	if err := cp.handlePkt(nil, payload, src, dst, routingResult, flowDecision, false); err != nil {
		t.Fatalf("packet 1: %v", err)
	}
	if err := cp.handlePkt(nil, payload, src, dst, routingResult, flowDecision, false); err != nil {
		t.Fatalf("packet 2: %v", err)
	}
	if got := underlay.calls.Load(); got != 1 {
		t.Fatalf("DialContext calls after stable packets = %d, want 1", got)
	}

	conn0 := factory.connAt(t, 0)
	injectHardReadErrorAndWait(t, conn0)
	waitForUdpEndpointRemoval(t, key)

	if err := cp.handlePkt(nil, payload, src, dst, routingResult, flowDecision, false); err != nil {
		t.Fatalf("packet 3 after instability: %v", err)
	}
	if err := cp.handlePkt(nil, payload, src, dst, routingResult, flowDecision, false); err != nil {
		t.Fatalf("packet 4 after instability: %v", err)
	}
	if got := underlay.calls.Load(); got != 2 {
		t.Fatalf("DialContext calls after hard error recovery = %d, want 2", got)
	}

	DefaultUdpEndpointPool.Reset()
	waitForUdpEndpointRemoval(t, key)

	if err := cp.handlePkt(nil, payload, src, dst, routingResult, flowDecision, false); err != nil {
		t.Fatalf("packet 5 after reset: %v", err)
	}
	if err := cp.handlePkt(nil, payload, src, dst, routingResult, flowDecision, false); err != nil {
		t.Fatalf("packet 6 after reset: %v", err)
	}
	if got := underlay.calls.Load(); got != 3 {
		t.Fatalf("DialContext calls after reset recovery = %d, want 3", got)
	}
}
