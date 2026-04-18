/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/protocol/direct"
	"github.com/sirupsen/logrus"
)

func TestControlPlaneDrainTrackerAcquireRelease(t *testing.T) {
	tracker := newControlPlaneDrainTracker()
	if tracker.Count() != 0 {
		t.Fatalf("initial Count() = %d, want 0", tracker.Count())
	}

	releaseA := tracker.Acquire()
	releaseB := tracker.Acquire()
	if tracker.Count() != 2 {
		t.Fatalf("Count() after acquire = %d, want 2", tracker.Count())
	}

	releaseA()
	if tracker.Count() != 1 {
		t.Fatalf("Count() after first release = %d, want 1", tracker.Count())
	}

	select {
	case <-tracker.IdleCh():
		t.Fatal("idle channel closed while tracker still has active sessions")
	default:
	}

	releaseB()
	if tracker.Count() != 0 {
		t.Fatalf("Count() after second release = %d, want 0", tracker.Count())
	}

	select {
	case <-tracker.IdleCh():
	default:
		t.Fatal("idle channel should be closed after all sessions release")
	}
}

func TestUdpEndpointAdoptGenerationTransfersDrainOwnership(t *testing.T) {
	oldTracker := newControlPlaneDrainTracker()
	newTracker := newControlPlaneDrainTracker()
	ue := &UdpEndpoint{
		drainTracker: oldTracker,
		drainRelease: oldTracker.Acquire(),
	}

	if oldTracker.Count() != 1 {
		t.Fatalf("oldTracker Count() = %d, want 1", oldTracker.Count())
	}

	ue.adoptGeneration(nil, newTracker)

	if oldTracker.Count() != 0 {
		t.Fatalf("oldTracker Count() after adoption = %d, want 0", oldTracker.Count())
	}
	if newTracker.Count() != 1 {
		t.Fatalf("newTracker Count() after adoption = %d, want 1", newTracker.Count())
	}

	if err := ue.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if newTracker.Count() != 0 {
		t.Fatalf("newTracker Count() after close = %d, want 0", newTracker.Count())
	}
}

func TestControlPlaneAbortConnectionsRejectsNewConnections(t *testing.T) {
	cp := &ControlPlane{}

	connA, peerA := net.Pipe()
	defer func() { _ = peerA.Close() }()
	if !cp.registerIncomingConnection(connA) {
		t.Fatal("registerIncomingConnection() = false, want true before abort")
	}

	if err := cp.AbortConnections(); err != nil {
		t.Fatalf("AbortConnections() error = %v", err)
	}
	if _, err := peerA.Write([]byte("x")); err == nil {
		t.Fatal("expected tracked connection to be closed by AbortConnections")
	}

	connB, peerB := net.Pipe()
	defer func() { _ = peerB.Close() }()
	if cp.registerIncomingConnection(connB) {
		t.Fatal("registerIncomingConnection() = true, want false after abort")
	}
	if _, err := peerB.Write([]byte("x")); err == nil {
		t.Fatal("expected newly registered connection to be rejected after abort")
	}
}

func TestControlPlaneReleaseRetainedStateClosesDnsHandoffController(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	janitorStop := make(chan struct{})
	janitorDone := make(chan struct{})
	evictorDone := make(chan struct{})
	close(janitorDone)
	close(evictorDone)

	controller := &DnsController{
		janitorStop: janitorStop,
		janitorDone: janitorDone,
		evictorDone: evictorDone,
	}
	cp := &ControlPlane{
		ctx: ctx,
	}
	cp.EnableDNSHandoff(controller, time.Hour)
	cp.releaseRetainedState()

	select {
	case <-janitorStop:
	case <-time.After(time.Second):
		t.Fatal("expected releaseRetainedState to close handoff controller")
	}
	if got := cp.dnsHandoffController.Load(); got != nil {
		t.Fatalf("dnsHandoffController = %v, want nil", got)
	}
}

func TestControlPlaneReleaseRetainedStateKeepsSharedDnsHandoffControllerAlive(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	janitorStop := make(chan struct{})
	janitorDone := make(chan struct{})
	evictorDone := make(chan struct{})
	close(janitorDone)
	close(evictorDone)

	oldController := &DnsController{
		janitorStop: janitorStop,
		janitorDone: janitorDone,
		evictorDone: evictorDone,
	}
	oldCP := &ControlPlane{
		log:           logger,
		ctx:           context.Background(),
		dnsController: oldController,
	}
	newCP := &ControlPlane{
		log:           logger,
		ctx:           context.Background(),
		dnsController: &DnsController{},
		dnsRouting:    &dns.Dns{},
	}

	if !newCP.ReuseDNSControllerFrom(oldCP) {
		t.Fatal("ReuseDNSControllerFrom() = false, want true")
	}

	oldCP.releaseRetainedState()

	select {
	case <-janitorStop:
		t.Fatal("expected releaseRetainedState to keep shared handoff controller alive")
	default:
	}
	if oldCP.ActiveDnsController() != nil {
		t.Fatal("expected old control plane to clear handoff pointer on release")
	}

	if err := newCP.dnsController.Close(); err != nil {
		t.Fatalf("shared dns controller Close() error = %v", err)
	}
	select {
	case <-janitorStop:
	case <-time.After(time.Second):
		t.Fatal("expected shared dns controller to close when owned controller closes")
	}
}

func TestCommitPreparedDatapathStartsConnStateJanitor(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cp := &ControlPlane{
		log:                    logger,
		ctx:                    ctx,
		preparedDatapathCommit: true,
		connStateJanitorStop:   make(chan struct{}),
		connStateJanitorDone:   make(chan struct{}),
	}

	if cp.connStateJanitorStarted.Load() {
		t.Fatal("expected conn-state janitor to start disabled")
	}

	if err := cp.CommitPreparedDatapath(); err != nil {
		t.Fatalf("CommitPreparedDatapath() error = %v", err)
	}
	if !cp.connStateJanitorStarted.Load() {
		t.Fatal("expected CommitPreparedDatapath to start conn-state janitor")
	}
	if cp.preparedDatapathCommit {
		t.Fatal("expected preparedDatapathCommit to be cleared after commit")
	}

	cp.stopConnStateJanitor()
}

func TestStartPreparedDNSListenerOnlyRunsWhenDeferred(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	cp := &ControlPlane{
		log: logger,
		dnsListener: &DNSListener{
			log: logger,
		},
	}

	if err := cp.StartPreparedDNSListener(); err != nil {
		t.Fatalf("StartPreparedDNSListener() without deferred flag error = %v", err)
	}
	if cp.dnsListenerStopRegistered {
		t.Fatal("expected StartPreparedDNSListener to no-op when deferred flag is false")
	}

	cp.delayDNSListenerStart = true
	if err := cp.StartPreparedDNSListener(); err != nil {
		t.Fatalf("StartPreparedDNSListener() with deferred flag error = %v", err)
	}
	if cp.delayDNSListenerStart {
		t.Fatal("expected deferred DNS listener flag to be cleared")
	}
	if !cp.dnsListenerStopRegistered {
		t.Fatal("expected DNS listener stop hook to be registered after deferred start")
	}
}

func TestStartPreparedDNSListenerRunsCutoverHook(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	var hookCalls atomic.Int32
	cp := &ControlPlane{
		log: logger,
		dnsListener: &DNSListener{
			log: logger,
		},
		delayDNSListenerStart: true,
		preparedDNSStartHook: func() error {
			hookCalls.Add(1)
			return nil
		},
	}

	if err := cp.StartPreparedDNSListener(); err != nil {
		t.Fatalf("StartPreparedDNSListener() error = %v", err)
	}
	if hookCalls.Load() != 1 {
		t.Fatalf("preparedDNSStartHook calls = %d, want 1", hookCalls.Load())
	}
	if cp.preparedDNSStartHook != nil {
		t.Fatal("expected preparedDNSStartHook to be cleared after execution")
	}
}

func TestStartPreparedDNSListenerWaitsForDNSAvailabilityBeforeReuseHook(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	reuseCalled := make(chan struct{})
	cp := &ControlPlane{
		log:                   logger,
		ctx:                   context.Background(),
		dnsUpstreamAvailable:  make(chan struct{}),
		delayDNSListenerStart: true,
		preparedDNSReuseHook: func() error {
			close(reuseCalled)
			return nil
		},
	}

	done := make(chan error, 1)
	go func() {
		done <- cp.StartPreparedDNSListener()
	}()

	select {
	case <-reuseCalled:
		t.Fatal("expected DNS reuse hook to wait for upstream availability")
	case <-time.After(20 * time.Millisecond):
	}

	close(cp.dnsUpstreamAvailable)

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("StartPreparedDNSListener() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("expected StartPreparedDNSListener to finish after upstream availability")
	}

	select {
	case <-reuseCalled:
	default:
		t.Fatal("expected DNS reuse hook to run after upstream availability")
	}
}

func TestReuseDNSListenerFromTransfersOwnership(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	oldCP := &ControlPlane{log: logger}
	newCP := &ControlPlane{
		log:                   logger,
		dnsListener:           &DNSListener{log: logger, endpoint: Endpoint{UDP: true, Addr: "0.0.0.0:53"}},
		delayDNSListenerStart: true,
	}
	listener := &DNSListener{log: logger, endpoint: Endpoint{UDP: true, Addr: "0.0.0.0:53"}}
	listener.SwapController(oldCP)
	oldCP.dnsListener = listener

	if !newCP.ReuseDNSListenerFrom(oldCP) {
		t.Fatal("ReuseDNSListenerFrom() = false, want true")
	}
	if oldCP.dnsListener != nil {
		t.Fatal("expected old control plane to detach DNS listener")
	}
	if newCP.dnsListener != listener {
		t.Fatal("expected new control plane to own transferred DNS listener")
	}
	if listener.Controller() != newCP {
		t.Fatal("expected transferred DNS listener to point at new control plane")
	}
	if newCP.delayDNSListenerStart {
		t.Fatal("expected DNS listener reuse to clear delayed start flag")
	}
}

func TestReuseDNSListenerFromRejectsProtocolMismatch(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	oldCP := &ControlPlane{
		log:         logger,
		dnsListener: &DNSListener{log: logger, endpoint: Endpoint{UDP: true, Addr: "0.0.0.0:53"}},
	}
	newCP := &ControlPlane{
		log:                   logger,
		dnsListener:           &DNSListener{log: logger, endpoint: Endpoint{TCP: true, UDP: true, Addr: "0.0.0.0:53"}},
		delayDNSListenerStart: true,
	}

	if newCP.ReuseDNSListenerFrom(oldCP) {
		t.Fatal("ReuseDNSListenerFrom() = true, want false for protocol mismatch")
	}
	if oldCP.dnsListener == nil {
		t.Fatal("expected previous DNS listener to remain owned by old control plane")
	}
}

func TestReuseDNSControllerFromUpdatesRuntime(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	oldController := &DnsController{}
	oldCP := &ControlPlane{
		log:           logger,
		ctx:           context.Background(),
		dnsController: oldController,
	}
	newCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	newRouting := &dns.Dns{}
	newCP := &ControlPlane{
		log:           logger,
		ctx:           newCtx,
		dnsController: &DnsController{},
		dnsRouting:    newRouting,
		dnsFixedDomainTtl: map[string]int{
			"example.com": 60,
		},
	}

	if !newCP.ReuseDNSControllerFrom(oldCP) {
		t.Fatal("ReuseDNSControllerFrom() = false, want true")
	}
	if oldCP.dnsController != nil {
		t.Fatal("expected previous control plane to detach DNS controller")
	}
	if newCP.dnsController != oldController {
		t.Fatal("expected new control plane to own reused DNS controller")
	}
	if oldCP.ActiveDnsController() != oldController {
		t.Fatal("expected previous control plane to hand off active DNS controller without a nil gap")
	}
	if !oldCP.SharesActiveDnsControllerWith(newCP) {
		t.Fatal("expected old and new control planes to share the active DNS controller after reuse")
	}

	rt := newCP.dnsController.runtime()
	if rt == nil {
		t.Fatal("expected reused DNS controller runtime to be configured")
	}
	if rt.routing != newRouting {
		t.Fatal("expected reused DNS controller runtime to use new routing")
	}
	if rt.lifecycleCtx != newCtx {
		t.Fatal("expected reused DNS controller runtime to use new lifecycle context")
	}
	if rt.bestDialerChooser == nil {
		t.Fatal("expected reused DNS controller runtime to install bestDialerChooser")
	}
	if rt.fixedDomainTtl["example.com"] != 60 {
		t.Fatal("expected reused DNS controller runtime to use new fixedDomainTtl")
	}
}

func TestDnsRequestContextUsesNewLifecycleDuringDNSHandoff(t *testing.T) {
	oldCtx, oldCancel := context.WithCancel(context.Background())
	defer oldCancel()
	newCtx, newCancel := context.WithCancel(context.Background())
	defer newCancel()

	oldController := &DnsController{}
	oldCP := &ControlPlane{
		ctx:           oldCtx,
		dnsController: oldController,
	}
	newCP := &ControlPlane{
		ctx:           newCtx,
		dnsController: &DnsController{},
		dnsRouting:    &dns.Dns{},
	}

	if !newCP.ReuseDNSControllerFrom(oldCP) {
		t.Fatal("ReuseDNSControllerFrom() = false, want true")
	}

	oldCancel()
	got := oldCP.dnsRequestContext(oldCtx, oldCP.ActiveDnsController())
	if got != newCtx {
		t.Fatal("expected old control plane DNS handoff requests to use new lifecycle context")
	}
	select {
	case <-got.Done():
		t.Fatal("expected handoff DNS request context to remain active after old control plane cancellation")
	default:
	}

	type requestContextKey struct{}
	requestCtx := context.WithValue(context.Background(), requestContextKey{}, "request")
	if got := newCP.dnsRequestContext(requestCtx, newCP.ActiveDnsController()); got != requestCtx {
		t.Fatal("expected new control plane DNS requests to preserve caller context")
	}
}

func TestInheritDialerHealthFromUsesReloadSafeSnapshot(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	newTestDialer := func(name string) *dialer.Dialer {
		return dialer.NewDialer(
			direct.SymmetricDirect,
			&dialer.GlobalOption{
				Log:            logger,
				CheckInterval:  30 * time.Second,
				CheckTolerance: time.Second,
			},
			dialer.InstanceOption{},
			&dialer.Property{
				Property: D.Property{Name: name},
			},
		)
	}

	oldDialer := newTestDialer("node-a")
	defer func() { _ = oldDialer.Close() }()
	newDialer := newTestDialer("node-a")
	defer func() { _ = newDialer.Close() }()

	oldGroup := outbound.NewDialerGroup(
		&dialer.GlobalOption{
			Log:            logger,
			CheckInterval:  30 * time.Second,
			CheckTolerance: time.Second,
		},
		"group-a",
		[]*dialer.Dialer{oldDialer},
		[]*dialer.Annotation{{}},
		outbound.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_MinLastLatency},
		func(bool, *dialer.NetworkType, bool) {},
	)
	defer func() { _ = oldGroup.Close() }()
	newGroup := outbound.NewDialerGroup(
		&dialer.GlobalOption{
			Log:            logger,
			CheckInterval:  30 * time.Second,
			CheckTolerance: time.Second,
		},
		"group-a",
		[]*dialer.Dialer{newDialer},
		[]*dialer.Annotation{{}},
		outbound.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_MinLastLatency},
		func(bool, *dialer.NetworkType, bool) {},
	)
	defer func() { _ = newGroup.Close() }()

	tcp4 := &dialer.NetworkType{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_4}
	oldDialer.ReportUnavailableForced(tcp4, nil)
	oldDialer.NotifyHealthCheckResult(tcp4, false, false)
	if oldDialer.MustGetAlive(tcp4) {
		t.Fatal("expected source dialer to be unavailable before inheritance")
	}

	oldCP := &ControlPlane{outbounds: []*outbound.DialerGroup{oldGroup}}
	newCP := &ControlPlane{outbounds: []*outbound.DialerGroup{newGroup}}

	if got := newCP.InheritDialerHealthFrom(oldCP); !got {
		t.Fatal("expected InheritDialerHealthFrom to return true when dialers overlap")
	}

	if !newDialer.MustGetAlive(tcp4) {
		t.Fatal("expected reload selection floor to keep the only group candidate alive")
	}
	if got := newDialer.GetBackoffLevel(consts.L4ProtoStr_TCP); got != 0 {
		t.Fatalf("inherited backoff level = %d, want 0", got)
	}
}

func TestInheritDialerHealthFromDoesNotReviveDeadDialerWhenGroupHasCandidate(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	newTestDialer := func(name string) *dialer.Dialer {
		return dialer.NewDialer(
			direct.SymmetricDirect,
			&dialer.GlobalOption{
				Log:            logger,
				CheckInterval:  30 * time.Second,
				CheckTolerance: time.Second,
			},
			dialer.InstanceOption{},
			&dialer.Property{
				Property: D.Property{Name: name},
			},
		)
	}

	oldDialerA := newTestDialer("node-a")
	defer func() { _ = oldDialerA.Close() }()
	oldDialerB := newTestDialer("node-b")
	defer func() { _ = oldDialerB.Close() }()
	newDialerA := newTestDialer("node-a")
	defer func() { _ = newDialerA.Close() }()
	newDialerB := newTestDialer("node-b")
	defer func() { _ = newDialerB.Close() }()

	oldGroup := outbound.NewDialerGroup(
		&dialer.GlobalOption{
			Log:            logger,
			CheckInterval:  30 * time.Second,
			CheckTolerance: time.Second,
		},
		"group-a",
		[]*dialer.Dialer{oldDialerA, oldDialerB},
		[]*dialer.Annotation{{}, {}},
		outbound.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_MinLastLatency},
		func(bool, *dialer.NetworkType, bool) {},
	)
	defer func() { _ = oldGroup.Close() }()
	newGroup := outbound.NewDialerGroup(
		&dialer.GlobalOption{
			Log:            logger,
			CheckInterval:  30 * time.Second,
			CheckTolerance: time.Second,
		},
		"group-a",
		[]*dialer.Dialer{newDialerA, newDialerB},
		[]*dialer.Annotation{{}, {}},
		outbound.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_MinLastLatency},
		func(bool, *dialer.NetworkType, bool) {},
	)
	defer func() { _ = newGroup.Close() }()

	tcp4 := &dialer.NetworkType{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_4}
	oldDialerA.ReportUnavailableForced(tcp4, nil)
	oldDialerA.NotifyHealthCheckResult(tcp4, false, false)
	if oldDialerA.MustGetAlive(tcp4) {
		t.Fatal("expected source dialer A to be unavailable before inheritance")
	}
	if !oldDialerB.MustGetAlive(tcp4) {
		t.Fatal("expected source dialer B to remain available before inheritance")
	}

	oldCP := &ControlPlane{outbounds: []*outbound.DialerGroup{oldGroup}}
	newCP := &ControlPlane{outbounds: []*outbound.DialerGroup{newGroup}}

	if got := newCP.InheritDialerHealthFrom(oldCP); !got {
		t.Fatal("expected InheritDialerHealthFrom to return true when dialers overlap")
	}

	if newDialerA.MustGetAlive(tcp4) {
		t.Fatal("expected dead dialer A to remain unavailable while group has another candidate")
	}
	if !newDialerB.MustGetAlive(tcp4) {
		t.Fatal("expected dialer B to remain available after inheritance")
	}
}

func TestInheritDialerHealthFromReturnsFalseWhenNoOverlap(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	newTestDialer := func(name string) *dialer.Dialer {
		return dialer.NewDialer(
			direct.SymmetricDirect,
			&dialer.GlobalOption{
				Log:            logger,
				CheckInterval:  30 * time.Second,
				CheckTolerance: time.Second,
			},
			dialer.InstanceOption{},
			&dialer.Property{
				Property: D.Property{Name: name},
			},
		)
	}

	oldDialer := newTestDialer("node-a")
	defer func() { _ = oldDialer.Close() }()
	newDialer := newTestDialer("node-b")
	defer func() { _ = newDialer.Close() }()

	oldGroup := outbound.NewDialerGroup(
		&dialer.GlobalOption{
			Log:            logger,
			CheckInterval:  30 * time.Second,
			CheckTolerance: time.Second,
		},
		"group-x",
		[]*dialer.Dialer{oldDialer},
		[]*dialer.Annotation{{}},
		outbound.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_MinLastLatency},
		func(bool, *dialer.NetworkType, bool) {},
	)
	defer func() { _ = oldGroup.Close() }()
	newGroup := outbound.NewDialerGroup(
		&dialer.GlobalOption{
			Log:            logger,
			CheckInterval:  30 * time.Second,
			CheckTolerance: time.Second,
		},
		"group-y",
		[]*dialer.Dialer{newDialer},
		[]*dialer.Annotation{{}},
		outbound.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_MinLastLatency},
		func(bool, *dialer.NetworkType, bool) {},
	)
	defer func() { _ = newGroup.Close() }()

	oldCP := &ControlPlane{outbounds: []*outbound.DialerGroup{oldGroup}}
	newCP := &ControlPlane{outbounds: []*outbound.DialerGroup{newGroup}}

	if got := newCP.InheritDialerHealthFrom(oldCP); got {
		t.Fatal("expected InheritDialerHealthFrom to return false when no dialers overlap")
	}
}

func TestWaitDNSUpstreamsReadyReturnsWhenChannelCloses(t *testing.T) {
	cp := &ControlPlane{
		ctx:                  context.Background(),
		ready:                make(chan struct{}),
		dnsUpstreamAvailable: make(chan struct{}),
	}
	done := make(chan struct{})
	go func() {
		_ = cp.dnsUpstreamReadyCallback(nil)
		close(done)
	}()

	select {
	case <-cp.dnsUpstreamAvailable:
	case <-time.After(time.Second):
		t.Fatal("expected dnsUpstreamAvailable to close before ready")
	}

	select {
	case <-done:
		t.Fatal("expected callback to remain blocked on ready")
	default:
	}

	cp.markReady()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("expected callback to finish after ready")
	}
}
