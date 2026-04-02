/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@daeuniverse.org>
 */

package control

import (
	"net/netip"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
)

func makeLikelyQuicInitialPayload(dcidSeed byte) []byte {
	return []byte{
		0xc0,
		0x00, 0x00, 0x00, 0x01,
		0x08,
		dcidSeed, dcidSeed + 1, dcidSeed + 2, dcidSeed + 3,
		dcidSeed + 4, dcidSeed + 5, dcidSeed + 6, dcidSeed + 7,
		0x08,
		0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98,
		0x00,
		0x04,
		0x00, 0x00, 0x00, 0x01,
	}
}

func setupQuicInitialRegressionTestState(t *testing.T) func() {
	t.Helper()

	oldUdpPool := DefaultUdpEndpointPool
	DefaultUdpEndpointPool = NewUdpEndpointPool()

	oldAnyfromPool := DefaultAnyfromPool
	DefaultAnyfromPool = newTestAnyfromPoolWithoutJanitor()

	oldSnifferPool := DefaultPacketSnifferSessionMgr
	DefaultPacketSnifferSessionMgr = NewPacketSnifferPool()

	oldFailedCache := getFailedQuicDcidCache()
	SetFailedQuicDcidCache(newFailedQuicDcidCache(failedQuicDcidCacheShardCount))

	return func() {
		DefaultUdpEndpointPool.Reset()
		DefaultUdpEndpointPool = oldUdpPool

		DefaultAnyfromPool.Reset()
		DefaultAnyfromPool = oldAnyfromPool

		DefaultPacketSnifferSessionMgr.Close()
		DefaultPacketSnifferSessionMgr = oldSnifferPool

		SetFailedQuicDcidCache(oldFailedCache)
	}
}

func newQuicInitialRegressionFlow(t *testing.T, payload []byte) (src, dst netip.AddrPort, decision UdpFlowDecision) {
	t.Helper()

	src = mustParseAddrPort("192.168.89.3:42687")
	dst = mustParseAddrPort("52.199.194.44:23002")
	decision = ClassifyUdpFlow(src, dst, payload)
	if !decision.IsQuicInitial {
		t.Fatal("expected test payload to be classified as QUIC Initial")
	}
	return src, dst, decision.EnsureSnifferSession()
}

func primeQuicRegressionAnyfrom(src, dst netip.AddrPort) {
	bindAddr, _ := normalizeSendPktAddrFamily(dst, src)
	af := &Anyfrom{ttl: AnyfromTimeout}
	af.RefreshTtl()

	shard := DefaultAnyfromPool.shardFor(bindAddr)
	shard.mu.Lock()
	shard.pool[bindAddr] = af
	shard.mu.Unlock()
}

func TestHandlePkt_FailedQuicDcidKeepsExistingDomainlessEndpoint(t *testing.T) {
	defer setupQuicInitialRegressionTestState(t)()

	conn := &udpReuseSimulationConn{
		reads:   make(chan scriptedPacketRead),
		closeCh: make(chan struct{}),
	}
	d, underlay := newCountingProxyEndpointDialer("hysteria2", "proxy.example:443", conn)
	cp := newUdpReuseSimulationControlPlane(newTestFixedOutboundGroup(d))

	payload := makeLikelyQuicInitialPayload(0x10)
	src, dst, flowDecision := newQuicInitialRegressionFlow(t, payload)
	primeQuicRegressionAnyfrom(src, dst)
	key := flowDecision.SymmetricNatEndpointKey()
	routingResult := &bpfRoutingResult{
		Outbound: uint8(consts.OutboundUserDefinedMin),
	}

	if err := cp.handlePkt(nil, payload, src, dst, routingResult, flowDecision, false); err != nil {
		t.Fatalf("first handlePkt: %v", err)
	}
	if got := underlay.calls.Load(); got != 1 {
		t.Fatalf("DialContext calls after first packet = %d, want 1", got)
	}
	if _, ok := DefaultUdpEndpointPool.Get(key); !ok {
		t.Fatal("expected domain-less UDP endpoint to exist after first packet")
	}

	MarkQuicDcidFailed(NewPacketSnifferKey(src, dst, payload), quicDcidFailureReasonDecryptFailure)

	if err := cp.handlePkt(nil, payload, src, dst, routingResult, flowDecision, false); err != nil {
		t.Fatalf("second handlePkt: %v", err)
	}
	if got := underlay.calls.Load(); got != 1 {
		t.Fatalf("DialContext calls after failed-DCID reuse = %d, want 1", got)
	}
	if _, ok := DefaultUdpEndpointPool.Get(key); !ok {
		t.Fatal("expected existing UDP endpoint to survive failed-DCID reuse")
	}
}

func TestHandlePkt_EstablishedDomainlessEndpointSurvivesQuicInitialHeuristic(t *testing.T) {
	defer setupQuicInitialRegressionTestState(t)()

	conn := &udpReuseSimulationConn{
		reads:   make(chan scriptedPacketRead),
		closeCh: make(chan struct{}),
	}
	d, underlay := newCountingProxyEndpointDialer("hysteria2", "proxy.example:443", conn)
	cp := newUdpReuseSimulationControlPlane(newTestFixedOutboundGroup(d))

	payload := makeLikelyQuicInitialPayload(0x20)
	src, dst, flowDecision := newQuicInitialRegressionFlow(t, payload)
	primeQuicRegressionAnyfrom(src, dst)
	key := flowDecision.SymmetricNatEndpointKey()
	routingResult := &bpfRoutingResult{
		Outbound: uint8(consts.OutboundUserDefinedMin),
	}

	if err := cp.handlePkt(nil, payload, src, dst, routingResult, flowDecision, false); err != nil {
		t.Fatalf("first handlePkt: %v", err)
	}
	if got := underlay.calls.Load(); got != 1 {
		t.Fatalf("DialContext calls after first packet = %d, want 1", got)
	}

	ue, ok := DefaultUdpEndpointPool.Get(key)
	if !ok || ue == nil {
		t.Fatal("expected pooled endpoint after first packet")
	}
	ue.markReplied(0)
	if !ue.hasReply.Load() {
		t.Fatal("expected endpoint to enter established state after upstream reply")
	}

	if err := cp.handlePkt(nil, payload, src, dst, routingResult, flowDecision, false); err != nil {
		t.Fatalf("second handlePkt: %v", err)
	}
	if got := underlay.calls.Load(); got != 1 {
		t.Fatalf("DialContext calls after established reuse = %d, want 1", got)
	}
	if got := conn.writeCalls.Load(); got != 2 {
		t.Fatalf("WriteTo calls after reuse = %d, want 2", got)
	}
}
