/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	daerrors "github.com/daeuniverse/dae/common/errors"
	ob "github.com/daeuniverse/dae/component/outbound"
	componentdialer "github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/sirupsen/logrus"
)

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

func udp4NetworkType() *componentdialer.NetworkType {
	return &componentdialer.NetworkType{
		L4Proto:         consts.L4ProtoStr_UDP,
		IpVersion:       consts.IpVersionStr_4,
		UdpHealthDomain: componentdialer.UdpHealthDomainData,
	}
}

func TestHandlePkt_HealthDeathKeepsProxyBackedEndpoint(t *testing.T) {
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

	// Mark dialer not-alive. Proxy-backed unreplied endpoints should survive
	// because they hold a working transport connection.
	d.ReportUnavailableForced(udp4NetworkType(), io.ErrUnexpectedEOF)
	d.ReportUnavailableForced(&componentdialer.NetworkType{
		L4Proto:   consts.L4ProtoStr_UDP,
		IpVersion: consts.IpVersionStr_6,
		IsDns:     false,
	}, io.ErrUnexpectedEOF)

	// Endpoint should still exist (proxy-backed endpoints survive invalidation).
	if _, ok := DefaultUdpEndpointPool.Get(key); !ok {
		t.Fatal("expected proxy-backed unreplied endpoint to survive health death")
	}

	if err := cp.handlePkt(nil, payload, src, dst, routingResult, flowDecision, false); err != nil {
		t.Fatalf("second handlePkt after health death: %v", err)
	}
	// Should reuse the existing endpoint, not dial a new one.
	if got := underlay.calls.Load(); got != 1 {
		t.Fatalf("DialContext calls after health death = %d, want 1 (reused)", got)
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
