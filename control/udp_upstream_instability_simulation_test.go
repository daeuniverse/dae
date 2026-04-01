/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"io"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	daerrors "github.com/daeuniverse/dae/common/errors"
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
		L4Proto:         consts.L4ProtoStr_UDP,
		IpVersion:       consts.IpVersionStr_4,
		UdpHealthDomain: componentdialer.UdpHealthDomainData,
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

func TestHandlePkt_HealthDeathAllowsFallbackNewUdpDialSelection(t *testing.T) {
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
	core := &controlPlaneCore{
		log:    cp.log,
		closed: context.Background(),
	}
	d.RegisterAliveTransitionCallback(core.dialerAliveTransitionCallback(d))

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
	d.ReportUnavailableForced(&componentdialer.NetworkType{
		L4Proto:   consts.L4ProtoStr_UDP,
		IpVersion: consts.IpVersionStr_6,
		IsDns:     false,
	}, io.ErrUnexpectedEOF)
	waitForUdpEndpointRemoval(t, key)

	if err := cp.handlePkt(nil, payload, src, dst, routingResult, flowDecision, false); err != nil {
		t.Fatalf("second handlePkt after health death: %v", err)
	}
	if got := underlay.calls.Load(); got != 2 {
		t.Fatalf("DialContext calls after health death = %d, want 2", got)
	}
	if !d.MustGetAlive(udp4NetworkType()) {
		t.Fatal("expected successful fallback traffic to restore data-UDP health")
	}
	if _, ok := DefaultUdpEndpointPool.Get(key); !ok {
		t.Fatal("expected endpoint to be recreated through fallback admission")
	}
}

func TestHandlePkt_EstablishedFlowSurvivesTransientHealthFailure(t *testing.T) {
	oldPool := DefaultUdpEndpointPool
	DefaultUdpEndpointPool = NewUdpEndpointPool()
	defer func() {
		DefaultUdpEndpointPool.Reset()
		DefaultUdpEndpointPool = oldPool
	}()

	conn := &udpReuseSimulationConn{
		reads:      make(chan scriptedPacketRead, 4),
		readExitCh: make(chan error, 1),
		closeCh:    make(chan struct{}),
	}
	d, underlay := newCountingProxyEndpointDialer("hysteria2", "proxy.example:443", conn)
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	src := mustParseAddrPort("192.168.89.3:42687")
	dst := mustParseAddrPort("52.199.194.44:23002")
	from := mustParseAddrPort("52.199.194.44:23002")
	payload := []byte{0x81, 0x82, 0x83, 0x84}
	flowDecision := ClassifyUdpFlow(src, dst, payload)
	key := flowDecision.FullConeNatEndpointKey()
	cp := newUdpReuseSimulationControlPlane(newTestRandomOutboundGroup(d))
	core := &controlPlaneCore{
		log:    cp.log,
		closed: context.Background(),
	}
	d.RegisterAliveTransitionCallback(core.dialerAliveTransitionCallback(d))
	routingResult := &bpfRoutingResult{
		Outbound: uint8(consts.OutboundUserDefinedMin),
	}

	created, isNew, err := DefaultUdpEndpointPool.GetOrCreate(key, &UdpEndpointOptions{
		Handler:    func(_ *UdpEndpoint, _ []byte, _ netip.AddrPort) error { return nil },
		NatTimeout: DefaultNatTimeout,
		Log:        logger,
		GetDialOption: func(ctx context.Context) (*DialOption, error) {
			return &DialOption{
				Target:      dst.String(),
				Dialer:      d,
				Outbound:    newTestRandomOutboundGroup(d),
				Network:     "udp",
				NetworkType: udp4NetworkType(),
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("GetOrCreate initial endpoint: %v", err)
	}
	if !isNew {
		t.Fatal("expected initial GetOrCreate to create a new endpoint")
	}

	conn.reads <- scriptedPacketRead{data: []byte{0x01}, from: from}
	ue := waitForUdpEndpointReplyState(t, key)

	d.ReportUnavailableForced(udp4NetworkType(), io.ErrUnexpectedEOF)

	if err := cp.handlePkt(nil, payload, src, dst, routingResult, flowDecision, false); err != nil {
		t.Fatalf("second handlePkt after transient health failure: %v", err)
	}
	got, ok := DefaultUdpEndpointPool.Get(key)
	if !ok || got == nil {
		t.Fatal("expected established endpoint to remain pooled after transient health failure")
	}
	if got != created {
		t.Fatal("expected established flow to reuse existing endpoint instead of redialing")
	}
	if dials := underlay.calls.Load(); dials != 1 {
		t.Fatalf("DialContext calls = %d, want 1", dials)
	}

	if err := ue.Close(); err != nil {
		t.Fatalf("unexpected close error: %v", err)
	}
}

func TestHandlePkt_ShadowsocksEstablishedFlowSurvivesTransientHealthFailure(t *testing.T) {
	oldPool := DefaultUdpEndpointPool
	DefaultUdpEndpointPool = NewUdpEndpointPool()
	defer func() {
		DefaultUdpEndpointPool.Reset()
		DefaultUdpEndpointPool = oldPool
	}()

	conn := &udpReuseSimulationConn{
		reads:      make(chan scriptedPacketRead, 4),
		readExitCh: make(chan error, 1),
		closeCh:    make(chan struct{}),
	}
	d, underlay := newCountingProxyEndpointDialer("shadowsocks", "proxy.example:443", conn)
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	src := mustParseAddrPort("192.168.89.3:42687")
	dst := mustParseAddrPort("52.199.194.44:23002")
	from := mustParseAddrPort("52.199.194.44:23002")
	payload := []byte{0x91, 0x92, 0x93, 0x94}
	flowDecision := ClassifyUdpFlow(src, dst, payload)
	key := flowDecision.FullConeNatEndpointKey()
	cp := newUdpReuseSimulationControlPlane(newTestRandomOutboundGroup(d))
	core := &controlPlaneCore{
		log:    cp.log,
		closed: context.Background(),
	}
	d.RegisterAliveTransitionCallback(core.dialerAliveTransitionCallback(d))
	routingResult := &bpfRoutingResult{
		Outbound: uint8(consts.OutboundUserDefinedMin),
	}

	created, isNew, err := DefaultUdpEndpointPool.GetOrCreate(key, &UdpEndpointOptions{
		Handler:    func(_ *UdpEndpoint, _ []byte, _ netip.AddrPort) error { return nil },
		NatTimeout: DefaultNatTimeout,
		Log:        logger,
		GetDialOption: func(ctx context.Context) (*DialOption, error) {
			return &DialOption{
				Target:      dst.String(),
				Dialer:      d,
				Outbound:    newTestRandomOutboundGroup(d),
				Network:     "udp",
				NetworkType: udp4NetworkType(),
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("GetOrCreate initial endpoint: %v", err)
	}
	if !isNew {
		t.Fatal("expected initial GetOrCreate to create a new endpoint")
	}

	conn.reads <- scriptedPacketRead{data: []byte{0x11}, from: from}
	ue := waitForUdpEndpointReplyState(t, key)

	d.ReportUnavailableForced(udp4NetworkType(), io.ErrUnexpectedEOF)

	if err := cp.handlePkt(nil, payload, src, dst, routingResult, flowDecision, false); err != nil {
		t.Fatalf("second handlePkt after transient Shadowsocks health failure: %v", err)
	}
	got, ok := DefaultUdpEndpointPool.Get(key)
	if !ok || got == nil {
		t.Fatal("expected established Shadowsocks endpoint to remain pooled after transient health failure")
	}
	if got != created {
		t.Fatal("expected established Shadowsocks flow to reuse existing endpoint instead of redialing")
	}
	if dials := underlay.calls.Load(); dials != 1 {
		t.Fatalf("DialContext calls = %d, want 1", dials)
	}

	if err := ue.Close(); err != nil {
		t.Fatalf("unexpected close error: %v", err)
	}
}

func TestHandlePkt_CreateFailureFromNetworkUnreachableKeepsFallbackAdmissionAlive(t *testing.T) {
	oldPool := DefaultUdpEndpointPool
	DefaultUdpEndpointPool = NewUdpEndpointPool()
	defer func() {
		DefaultUdpEndpointPool.Reset()
		DefaultUdpEndpointPool = oldPool
	}()

	d, underlay := newFailingProxyEndpointDialer("hysteria2", "proxy.example:443", daerrors.ErrNetworkUnreachable)
	cp := newUdpReuseSimulationControlPlane(newTestRandomOutboundGroup(d))
	cp.lastConnectionErrorLogTime.Store(time.Now().UnixNano())

	dst := mustParseAddrPort("52.199.194.44:23002")
	payload := []byte{0x61, 0x62, 0x63, 0x64}
	routingResult := &bpfRoutingResult{
		Outbound: uint8(consts.OutboundUserDefinedMin),
	}

	src1 := mustParseAddrPort("192.168.89.3:42687")
	flow1 := ClassifyUdpFlow(src1, dst, payload)
	if err := cp.handlePkt(nil, payload, src1, dst, routingResult, flow1, false); err != nil {
		t.Fatalf("first handlePkt after create failure: %v", err)
	}
	if got := underlay.calls.Load(); got != 2 {
		t.Fatalf("DialContext calls after first failure = %d, want 2", got)
	}
	if d.MustGetAlive(udp4NetworkType()) {
		t.Fatal("expected create-time network unreachable to mark udp4 unavailable immediately")
	}
	dnsUDP4 := &componentdialer.NetworkType{
		L4Proto:         consts.L4ProtoStr_UDP,
		IpVersion:       consts.IpVersionStr_4,
		IsDns:           true,
		UdpHealthDomain: componentdialer.UdpHealthDomainDns,
	}
	if !d.MustGetAlive(dnsUDP4) {
		t.Fatal("expected DNS-UDP admission health to remain alive after data-UDP failure")
	}

	src2 := mustParseAddrPort("192.168.89.3:42688")
	flow2 := ClassifyUdpFlow(src2, dst, payload)
	if err := cp.handlePkt(nil, payload, src2, dst, routingResult, flow2, false); err != nil {
		t.Fatalf("second handlePkt after forced death: %v", err)
	}
	if got := underlay.calls.Load(); got != 4 {
		t.Fatalf("DialContext calls after forced death = %d, want 4", got)
	}
	if _, ok := DefaultUdpEndpointPool.Get(flow2.FullConeNatEndpointKey()); ok {
		t.Fatal("expected no endpoint to be pooled after repeated create failures")
	}
}

func TestHandlePkt_CreateFailureImmediatelyRetriesAlternateFamilyOnSameDialer(t *testing.T) {
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
	d, underlay := newSequenceProxyEndpointDialer(
		"shadowsocks_2022",
		"proxy.example:443",
		scriptedDialResult{err: daerrors.ErrNetworkUnreachable},
		scriptedDialResult{conn: conn},
	)
	cp := newUdpReuseSimulationControlPlane(newTestFixedOutboundGroup(d))
	cp.lastConnectionErrorLogTime.Store(time.Now().UnixNano())

	src := mustParseAddrPort("[2001:db8::10]:42687")
	dst := mustParseAddrPort("[2606:4700:4700::1111]:443")
	payload := []byte{0x71, 0x72, 0x73, 0x74}
	flowDecision := ClassifyUdpFlow(src, dst, payload)
	key := flowDecision.FullConeNatEndpointKey()
	routingResult := &bpfRoutingResult{
		Outbound: uint8(consts.OutboundUserDefinedMin),
	}

	if err := cp.handlePkt(nil, payload, src, dst, routingResult, flowDecision, false); err != nil {
		t.Fatalf("handlePkt after family fallback retry: %v", err)
	}
	if got := underlay.calls.Load(); got != 2 {
		t.Fatalf("DialContext calls after family fallback retry = %d, want 2", got)
	}

	ue, ok := DefaultUdpEndpointPool.Get(key)
	if !ok || ue == nil {
		t.Fatal("expected endpoint to be created after alternate-family retry")
	}
	if got := ue.endpointNetworkType.IpVersion; got != consts.IpVersionStr_4 {
		t.Fatalf("endpoint network type = %v, want %v", got, consts.IpVersionStr_4)
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
