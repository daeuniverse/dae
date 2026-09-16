/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

// This suite measures the pin-release timing that gates warning 1
// ("routing epoch execution owner is unavailable"). A tuple pinned by a live
// endpoint blocks the current-policy fallback; the pin is only released when
// the owning endpoint closes (releaseTrackedUdpConnState).

func newEpochPinTestControlPlane(t *testing.T) (*ControlPlane, *SessionManager) {
	t.Helper()
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	manager := NewSessionManager(context.Background())
	cp := &ControlPlane{
		log:            logger,
		sessionManager: manager,
	}
	return cp, manager
}

func TestRetireUnpinnedUDPConnState_PinBlocksUntilReleased(t *testing.T) {
	manager := NewSessionManager(context.Background())
	src := netip.MustParseAddrPort("192.168.1.100:40000")
	dst := netip.MustParseAddrPort("8.8.8.8:53")

	// Unpinned tuple: retirement succeeds immediately.
	retired, err := manager.retireUnpinnedUDPConnState(src, dst)
	if err != nil || !retired {
		t.Fatalf("unpinned retire = (%v, %v), want (true, nil)", retired, err)
	}

	// A live flow pins the tuple: retirement is blocked (the warning-1 gate).
	key := bpfTuplesKeyFromAddrPorts(src, dst, uint8(unix.IPPROTO_UDP))
	manager.RetainUdpConnStateTuples([]bpfTuplesKey{key})
	retired, err = manager.retireUnpinnedUDPConnState(src, dst)
	if err != nil || retired {
		t.Fatalf("pinned retire = (%v, %v), want (false, nil)", retired, err)
	}

	// Pin released: retirement works again.
	if err := manager.ReleaseUdpConnStateTuples([]bpfTuplesKey{key}); err != nil {
		t.Fatalf("release: %v", err)
	}
	retired, err = manager.retireUnpinnedUDPConnState(src, dst)
	if err != nil || !retired {
		t.Fatalf("retire after release = (%v, %v), want (true, nil)", retired, err)
	}
}

func TestPrepareUnownedUDPCurrentPolicyFallback_PinBlocksFallback(t *testing.T) {
	resetActiveControlPlanePublicationForTest(t)
	cp, manager := newEpochPinTestControlPlane(t)
	src := netip.MustParseAddrPort("192.168.1.100:40001")
	dst := netip.MustParseAddrPort("8.8.8.8:443")
	stale := &bpfRoutingResult{
		RoutingEpochSlot:   bpfRoutingEpochSlot1Encoded,
		DatapathGeneration: 1,
	}

	// Mirror the removed isPublishedActiveControlPlane helper: the plane must
	// be the published active plane (or none published) to exercise the path.
	if published := activeControlPlanePublication.plane.Load(); published != nil && published != cp {
		t.Fatal("test plane must be active to exercise the fallback path")
	}
	if !cp.ownsActiveRoutingEpoch() {
		t.Fatal("test plane must be active to exercise the fallback path")
	}

	// Unpinned: fallback rewrites to current-policy routing.
	result, ok, _ := cp.prepareUnownedUDPCurrentPolicyFallback(src, dst, stale)
	if !ok {
		t.Fatal("fallback should be available while the tuple is unpinned")
	}
	if result.Outbound != uint8(consts.OutboundControlPlaneRouting) {
		t.Fatalf("fallback outbound = %d, want control-plane routing", result.Outbound)
	}

	// Pinned by a live endpoint: fallback blocked, exactly the drop path.
	key := bpfTuplesKeyFromAddrPorts(src, dst, uint8(unix.IPPROTO_UDP))
	manager.RetainUdpConnStateTuples([]bpfTuplesKey{key})
	if _, ok, _ := cp.prepareUnownedUDPCurrentPolicyFallback(src, dst, stale); ok {
		t.Fatal("fallback should be blocked while the tuple is pinned")
	}

	// Pin released (endpoint closed): fallback available again.
	if err := manager.ReleaseUdpConnStateTuples([]bpfTuplesKey{key}); err != nil {
		t.Fatalf("release: %v", err)
	}
	if _, ok, _ := cp.prepareUnownedUDPCurrentPolicyFallback(src, dst, stale); !ok {
		t.Fatal("fallback should be available after pin release")
	}
}

// TestHandlePkt_EpochOwnerUnavailableWhenTuplePinned exercises the
// SessionManager-pin gate in isolation: with the SessionManager as the
// conn-state owner, a held pin blocks the current-policy fallback. Note this
// is NOT the production main path (production UDP endpoints pin through
// controlPlaneCore's udpConnStateTracker, which retireUnpinnedUDPConnState
// does not consult); the production-real trigger is
// TestHandlePkt_EpochOwnerUnavailable_RetiringPlane below.
func TestHandlePkt_EpochOwnerUnavailableWhenTuplePinned(t *testing.T) {
	resetActiveControlPlanePublicationForTest(t)
	cp, manager := newEpochPinTestControlPlane(t)
	// Fresh limiter state so the warning path is exercised.
	cp.lastHandlePktEpochWarnTime.Store(0)

	src := netip.MustParseAddrPort("192.168.1.100:40002")
	dst := netip.MustParseAddrPort("8.8.8.8:53")
	payload := []byte{0x01, 0x02, 0x03}
	routingResult := &bpfRoutingResult{
		RoutingEpochSlot:   bpfRoutingEpochSlot1Encoded,
		DatapathGeneration: 1,
	}
	flowDecision := ClassifyUdpFlow(src, dst, payload)

	key := bpfTuplesKeyFromAddrPorts(src, dst, uint8(unix.IPPROTO_UDP))
	manager.RetainUdpConnStateTuples([]bpfTuplesKey{key})
	defer func() { _ = manager.ReleaseUdpConnStateTuples([]bpfTuplesKey{key}) }()

	err := cp.handlePktWithPrefetch(payload, src, dst, routingResult, flowDecision, nil, UdpEndpointKey{}, false)
	if !errors.Is(err, errRoutingEpochOwnerUnavailable) {
		t.Fatalf("handlePkt err = %v, want errRoutingEpochOwnerUnavailable", err)
	}
}

// TestUdpEndpointCloseReleasesTrackedTuples measures the pin-release timing at
// the endpoint layer: TrackUdpConnStateTuplePair pins immediately and Close
// releases synchronously, leaving no lingering window at the manager level.
func TestUdpEndpointCloseReleasesTrackedTuples(t *testing.T) {
	manager := NewSessionManager(context.Background())
	src := netip.MustParseAddrPort("192.168.1.100:40003")
	dst := netip.MustParseAddrPort("8.8.8.8:53")
	key := bpfTuplesKeyFromAddrPorts(src, dst, uint8(unix.IPPROTO_UDP))

	ue := &UdpEndpoint{
		udpConnStateOwner: manager,
	}

	ue.TrackUdpConnStateTuplePair(src, dst)
	manager.udpStateMu.RLock()
	pinned := manager.pinnedUDP[key]
	manager.udpStateMu.RUnlock()
	if pinned != 1 {
		t.Fatalf("pinned refs after Track = %d, want 1", pinned)
	}

	ue.releaseTrackedUdpConnState()
	manager.udpStateMu.RLock()
	pinned = manager.pinnedUDP[key]
	manager.udpStateMu.RUnlock()
	if pinned != 0 {
		t.Fatalf("pinned refs after release = %d, want 0 (pin released synchronously)", pinned)
	}
}

// TestMarkDeadIfOwnedBy_PinRetainedUntilClose measures the only dead-but-open
// pin window: markDeadIfOwnedBy flags the endpoint dead without releasing the
// pin (AbortEndpointsOwnedBy closes immediately afterwards, so the window is
// ms-scale). Every other dead path (retire/Close) releases the pin
// synchronously.
func TestMarkDeadIfOwnedBy_PinRetainedUntilClose(t *testing.T) {
	manager := NewSessionManager(context.Background())
	src := netip.MustParseAddrPort("192.168.1.100:40004")
	dst := netip.MustParseAddrPort("8.8.8.8:53")
	key := bpfTuplesKeyFromAddrPorts(src, dst, uint8(unix.IPPROTO_UDP))

	ue := &UdpEndpoint{udpConnStateOwner: manager}
	ue.TrackUdpConnStateTuplePair(src, dst)

	if !ue.markDeadIfOwnedBy(manager) {
		t.Fatal("markDeadIfOwnedBy should mark the endpoint")
	}
	if !ue.IsDead() {
		t.Fatal("endpoint should be dead after markDeadIfOwnedBy")
	}
	manager.udpStateMu.RLock()
	pinned := manager.pinnedUDP[key]
	manager.udpStateMu.RUnlock()
	if pinned != 1 {
		t.Fatalf("pin released by markDeadIfOwnedBy (got %d, want 1): dead-but-open window lost", pinned)
	}

	if err := ue.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	manager.udpStateMu.RLock()
	pinned = manager.pinnedUDP[key]
	manager.udpStateMu.RUnlock()
	if pinned != 0 {
		t.Fatalf("pin still held after Close (got %d, want 0)", pinned)
	}
}

// TestRetainedUDPEndpoint_DeadEndpointNotFoundButPinHeld closes the warning-1
// mechanism loop: a live old-epoch flow is found by retainedUDPEndpoint (no
// drop), but a dead-but-open flow (markDeadIfOwnedBy, the only path that
// separates dead marking from Close) is not found while its pin is still held.
func TestRetainedUDPEndpoint_DeadEndpointNotFoundButPinHeld(t *testing.T) {
	manager := NewSessionManager(context.Background())
	src := netip.MustParseAddrPort("192.166.1.100:40005")
	dst := netip.MustParseAddrPort("8.8.8.8:53")
	key := bpfTuplesKeyFromAddrPorts(src, dst, uint8(unix.IPPROTO_UDP))
	result := &bpfRoutingResult{
		Outbound:           uint8(consts.OutboundUserDefinedMin),
		RoutingEpochSlot:   bpfRoutingEpochSlot1Encoded,
		DatapathGeneration: 1,
	}

	ue := &UdpEndpoint{
		poolKey: UdpEndpointKey{
			Src:        src,
			Dst:        dst,
			RouteScope: newUdpEndpointRouteScope(result),
		},
		udpConnStateOwner: manager,
	}
	flow := &UDPFlowRuntime{
		manager:  manager,
		endpoint: ue,
		binding:  UdpFlowBinding{Route: UdpRouteBinding{PolicyEpoch: 1}},
	}
	manager.appendUDPFlowSourceLocked(src, flow)
	ue.TrackUdpConnStateTuplePair(src, dst)

	if found, ok := manager.retainedUDPEndpoint(src, dst, result, 2); !ok || found != ue {
		t.Fatalf("live old-epoch flow not found by retainedUDPEndpoint (ok=%v, found=%v)", ok, found)
	}

	if !ue.markDeadIfOwnedBy(manager) {
		t.Fatal("markDeadIfOwnedBy failed")
	}
	if found, ok := manager.retainedUDPEndpoint(src, dst, result, 2); ok || found != nil {
		t.Fatalf("dead endpoint should not be found by retainedUDPEndpoint (ok=%v)", ok)
	}
	manager.udpStateMu.RLock()
	pinned := manager.pinnedUDP[key]
	manager.udpStateMu.RUnlock()
	if pinned != 1 {
		t.Fatalf("pin should be held while dead-but-open (got %d, want 1)", pinned)
	}
}

// TestHandlePkt_EpochOwnerUnavailable_RetiringPlaneClosedDrops verifies the
// conservative boundary of the fallback relaxation: a retiring generation
// whose execution has closed (rejectNewConnections set, e.g. after abort)
// still drops stale-attribution packets with errRoutingEpochOwnerUnavailable.
// A retiring-but-accepting generation instead re-routes them (see
// TestPrepareUnownedUDPCurrentPolicyFallback_RetiringPlane).
func TestHandlePkt_EpochOwnerUnavailable_RetiringPlaneClosedDrops(t *testing.T) {
	resetActiveControlPlanePublicationForTest(t)
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	// A distinct plane is published active, making cp the retiring one.
	active := &ControlPlane{log: logger}
	active.publishActiveControlPlane()
	defer active.unpublishActiveControlPlane()

	manager := NewSessionManager(context.Background())
	cp := &ControlPlane{
		log:            logger,
		sessionManager: manager,
	}
	cp.lastHandlePktEpochWarnTime.Store(0)
	// Execution closed: the fallback stays unavailable (conservative drop).
	cp.rejectNewConnections.Store(true)

	if published := activeControlPlanePublication.plane.Load(); published == cp {
		t.Fatal("test plane must not be the published active plane")
	}

	src := netip.MustParseAddrPort("192.168.1.100:40002")
	dst := netip.MustParseAddrPort("8.8.8.8:53")
	payload := []byte{0x01, 0x02, 0x03}
	// Attribution from a closed generation: neither plane matches slot 1.
	routingResult := &bpfRoutingResult{
		RoutingEpochSlot:   bpfRoutingEpochSlot1Encoded,
		DatapathGeneration: 1,
	}
	flowDecision := ClassifyUdpFlow(src, dst, payload)

	err := cp.handlePktWithPrefetch(payload, src, dst, routingResult, flowDecision, nil, UdpEndpointKey{}, false)
	if !errors.Is(err, errRoutingEpochOwnerUnavailable) {
		t.Fatalf("handlePkt err = %v, want errRoutingEpochOwnerUnavailable", err)
	}
}

// TestPrepareUnownedUDPCurrentPolicyFallback_RetiringPlane locks the relaxed
// fallback semantics: a retiring generation that still accepts work re-routes
// stale-attribution packets (no drop), while one whose execution has closed
// keeps the conservative drop path.
func TestPrepareUnownedUDPCurrentPolicyFallback_RetiringPlane(t *testing.T) {
	resetActiveControlPlanePublicationForTest(t)
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	active := &ControlPlane{log: logger}
	active.publishActiveControlPlane()
	defer active.unpublishActiveControlPlane()

	src := netip.MustParseAddrPort("192.168.1.100:40006")
	dst := netip.MustParseAddrPort("8.8.8.8:53")
	stale := &bpfRoutingResult{
		RoutingEpochSlot:   bpfRoutingEpochSlot1Encoded,
		DatapathGeneration: 1,
	}

	// Accepting retiring plane: fallback re-routes.
	accepting := &ControlPlane{log: logger, sessionManager: NewSessionManager(context.Background())}
	result, ok, _ := accepting.prepareUnownedUDPCurrentPolicyFallback(src, dst, stale)
	if !ok {
		t.Fatal("accepting retiring plane should re-route stale-attribution packets")
	}
	if result.Outbound != uint8(consts.OutboundControlPlaneRouting) {
		t.Fatalf("fallback outbound = %d, want control-plane routing", result.Outbound)
	}

	// Closed retiring plane: fallback stays unavailable.
	closed := &ControlPlane{log: logger, sessionManager: NewSessionManager(context.Background())}
	closed.rejectNewConnections.Store(true)
	if _, ok, _ := closed.prepareUnownedUDPCurrentPolicyFallback(src, dst, stale); ok {
		t.Fatal("closed retiring plane must not fall back")
	}
}
