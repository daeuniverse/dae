/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

// Unit tests for the reload state machine, reload manager bookkeeping, and
// signal shutdown teardown. Recovered from the run_shutdown_test.go pruned in
// the Sprint 5 test reduction and adapted to the current tree:
//   - shutdownAfterSignal was folded into shutdownAfterSignalWithHandoff, so
//     its tests pass a nil handoff;
//   - shutdown now tears down the dae netns even on fast exit, so fast-exit
//     expectations include one netns.Close call.
package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/control"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/mohae/deepcopy"
	"github.com/sirupsen/logrus"
)

type shutdownCallRecorder struct {
	order []string
}

func (r *shutdownCallRecorder) add(call string) {
	r.order = append(r.order, call)
}

type fakeShutdownListener struct {
	recorder *shutdownCallRecorder
}

func (f *fakeShutdownListener) Close() error {
	if f.recorder != nil {
		f.recorder.add("listener.Close")
	}
	return nil
}

type fakeShutdownControlPlane struct {
	recorder    *shutdownCallRecorder
	detachCalls int
	abortCalls  int
	closeCalls  int
	detachErr   error
	abortErr    error
	closeErr    error
	onClose     func()
}

func (f *fakeShutdownControlPlane) DetachBpfHooks() error {
	f.detachCalls++
	if f.recorder != nil {
		f.recorder.add("control.DetachBpfHooks")
	}
	return f.detachErr
}

func (f *fakeShutdownControlPlane) AbortConnections() error {
	f.abortCalls++
	if f.recorder != nil {
		f.recorder.add("control.AbortConnections")
	}
	return f.abortErr
}

func (f *fakeShutdownControlPlane) Close() error {
	f.closeCalls++
	if f.recorder != nil {
		f.recorder.add("control.Close")
	}
	if f.onClose != nil {
		f.onClose()
	}
	return f.closeErr
}

type fakeShutdownNetns struct {
	recorder   *shutdownCallRecorder
	closeCalls int
	closeErr   error
}

func (f *fakeShutdownNetns) Close() error {
	f.closeCalls++
	if f.recorder != nil {
		f.recorder.add("netns.Close")
	}
	return f.closeErr
}

type fakeRetirementControlPlane struct {
	active int32
	idleCh chan struct{}
}

func newFakeRetirementControlPlane(active int32) *fakeRetirementControlPlane {
	f := &fakeRetirementControlPlane{
		active: active,
		idleCh: make(chan struct{}),
	}
	if active == 0 {
		close(f.idleCh)
	}
	return f
}

func (f *fakeRetirementControlPlane) ActiveSessionCount() int {
	return int(atomic.LoadInt32(&f.active))
}

func (f *fakeRetirementControlPlane) DrainIdleCh() <-chan struct{} {
	return f.idleCh
}

func newDiscardLogger() *logrus.Logger {
	log := logrus.New()
	log.SetOutput(io.Discard)
	return log
}

func isolateGlobalUdpState(t *testing.T) {
	t.Helper()

	oldEndpointPool := control.DefaultUdpEndpointPool
	oldAnyfromPool := control.DefaultAnyfromPool
	oldTaskPool := control.DefaultUdpTaskPool
	oldSnifferPool := control.DefaultPacketSnifferSessionMgr

	endpointPool := control.NewUdpEndpointPool()
	anyfromPool := control.NewAnyfromPool()
	taskPool := control.NewUdpTaskPool()
	snifferPool := control.NewPacketSnifferPool()

	control.DefaultUdpEndpointPool = endpointPool
	control.DefaultAnyfromPool = anyfromPool
	control.DefaultUdpTaskPool = taskPool
	control.DefaultPacketSnifferSessionMgr = snifferPool

	t.Cleanup(func() {
		endpointPool.Close()
		anyfromPool.Close()
		taskPool.Close()
		snifferPool.Close()

		control.DefaultUdpEndpointPool = oldEndpointPool
		control.DefaultAnyfromPool = oldAnyfromPool
		control.DefaultUdpTaskPool = oldTaskPool
		control.DefaultPacketSnifferSessionMgr = oldSnifferPool
	})
}

func seedPacketSnifferSession(t *testing.T) control.PacketSnifferKey {
	t.Helper()

	key := control.NewPacketSnifferKey(
		netip.MustParseAddrPort("192.0.2.10:40000"),
		netip.MustParseAddrPort("198.51.100.20:443"),
		[]byte{0x01, 0x02, 0x03},
	)
	if _, isNew := control.DefaultPacketSnifferSessionMgr.GetOrCreate(key, nil); !isNew {
		t.Fatal("expected test packet sniffer session to be newly created")
	}
	if got := control.DefaultPacketSnifferSessionMgr.Get(key); got == nil {
		t.Fatal("expected seeded packet sniffer session to be present")
	}
	return key
}

func TestShutdownAfterSignalFastExitSkipsGracefulTeardown(t *testing.T) {
	recorder := &shutdownCallRecorder{}
	listener := &fakeShutdownListener{recorder: recorder}
	plane := &fakeShutdownControlPlane{recorder: recorder}
	netns := &fakeShutdownNetns{recorder: recorder}

	if err := shutdownAfterSignalWithHandoff(newDiscardLogger(), listener, plane, netns, true, nil); err != nil {
		t.Fatalf("shutdownAfterSignalWithHandoff() error = %v", err)
	}

	if plane.detachCalls != 1 {
		t.Fatalf("DetachBpfHooks calls = %d, want 1", plane.detachCalls)
	}
	if plane.abortCalls != 0 {
		t.Fatalf("AbortConnections calls = %d, want 0", plane.abortCalls)
	}
	if plane.closeCalls != 0 {
		t.Fatalf("Close calls = %d, want 0", plane.closeCalls)
	}
	if netns.closeCalls != 1 {
		t.Fatalf("netns.Close calls = %d, want 1 (netns is torn down even on fast exit)", netns.closeCalls)
	}

	wantOrder := []string{
		"listener.Close",
		"control.DetachBpfHooks",
		"netns.Close",
	}
	if !reflect.DeepEqual(recorder.order, wantOrder) {
		t.Fatalf("call order = %v, want %v", recorder.order, wantOrder)
	}
}

func TestShutdownAfterSignalGracefulExitRunsFullTeardown(t *testing.T) {
	isolateGlobalUdpState(t)

	recorder := &shutdownCallRecorder{}
	listener := &fakeShutdownListener{recorder: recorder}
	plane := &fakeShutdownControlPlane{
		recorder: recorder,
		closeErr: errors.New("close failed"),
	}
	netns := &fakeShutdownNetns{recorder: recorder}

	err := shutdownAfterSignalWithHandoff(newDiscardLogger(), listener, plane, netns, false, nil)
	if err == nil || err.Error() != "close control plane: close failed" {
		t.Fatalf("shutdownAfterSignalWithHandoff() error = %v, want close control plane: close failed", err)
	}

	if plane.detachCalls != 1 {
		t.Fatalf("DetachBpfHooks calls = %d, want 1", plane.detachCalls)
	}
	if plane.abortCalls != 1 {
		t.Fatalf("AbortConnections calls = %d, want 1", plane.abortCalls)
	}
	if plane.closeCalls != 1 {
		t.Fatalf("Close calls = %d, want 1", plane.closeCalls)
	}
	if netns.closeCalls != 1 {
		t.Fatalf("netns.Close calls = %d, want 1", netns.closeCalls)
	}

	wantOrder := []string{
		"listener.Close",
		"control.DetachBpfHooks",
		"netns.Close",
		"control.AbortConnections",
		"control.Close",
	}
	if !reflect.DeepEqual(recorder.order, wantOrder) {
		t.Fatalf("call order = %v, want %v", recorder.order, wantOrder)
	}
}

func TestShutdownAfterSignalGracefulExitCancelsGenerationContexts(t *testing.T) {
	isolateGlobalUdpState(t)

	var oldCancelCalls atomic.Int32
	var newCancelCalls atomic.Int32
	handoff := &signalShutdownStagedHandoff{
		oldListener:     &fakeShutdownListener{},
		oldControlPlane: &fakeShutdownControlPlane{},
		oldCancel:       func() { oldCancelCalls.Add(1) },
		newListener:     &fakeShutdownListener{},
		newControlPlane: &fakeShutdownControlPlane{},
		newCancel:       func() { newCancelCalls.Add(1) },
	}

	if err := shutdownAfterSignalWithHandoff(
		newDiscardLogger(),
		&fakeShutdownListener{},
		&fakeShutdownControlPlane{},
		&fakeShutdownNetns{},
		false,
		handoff,
	); err != nil {
		t.Fatalf("shutdownAfterSignalWithHandoff() error = %v", err)
	}
	if got := oldCancelCalls.Load(); got != 1 {
		t.Fatalf("old generation cancel calls = %d, want 1", got)
	}
	if got := newCancelCalls.Load(); got != 1 {
		t.Fatalf("new generation cancel calls = %d, want 1", got)
	}
}

func TestShutdownAfterSignalGracefulExitResetsGlobalUdpStateAfterClose(t *testing.T) {
	isolateGlobalUdpState(t)

	key := seedPacketSnifferSession(t)
	plane := &fakeShutdownControlPlane{
		onClose: func() {
			if got := control.DefaultPacketSnifferSessionMgr.Get(key); got == nil {
				t.Fatal("global UDP state was reset before control plane close")
			}
		},
	}

	if err := shutdownAfterSignalWithHandoff(newDiscardLogger(), &fakeShutdownListener{}, plane, &fakeShutdownNetns{}, false, nil); err != nil {
		t.Fatalf("shutdownAfterSignalWithHandoff() error = %v", err)
	}

	if plane.closeCalls != 1 {
		t.Fatalf("Close calls = %d, want 1", plane.closeCalls)
	}
	if got := control.DefaultPacketSnifferSessionMgr.Get(key); got != nil {
		t.Fatal("expected graceful shutdown to reset global UDP packet sniffer state")
	}
}

func TestShutdownAfterSignalFastExitDoesNotResetGlobalUdpState(t *testing.T) {
	isolateGlobalUdpState(t)

	key := seedPacketSnifferSession(t)

	if err := shutdownAfterSignalWithHandoff(newDiscardLogger(), &fakeShutdownListener{}, &fakeShutdownControlPlane{}, &fakeShutdownNetns{}, true, nil); err != nil {
		t.Fatalf("shutdownAfterSignalWithHandoff() error = %v", err)
	}

	if got := control.DefaultPacketSnifferSessionMgr.Get(key); got == nil {
		t.Fatal("expected fast shutdown to leave global UDP packet sniffer state intact")
	}
}

func TestShutdownAfterSignalTypedNilResourcesAreSkipped(t *testing.T) {
	var listener *control.Listener
	var plane *control.ControlPlane
	var netns *control.DaeNetns

	if err := shutdownAfterSignalWithHandoff(newDiscardLogger(), listener, plane, netns, true, nil); err != nil {
		t.Fatalf("shutdownAfterSignalWithHandoff() error = %v, want nil", err)
	}
}

func TestShutdownAfterSignalWithPendingHandoffFastExitDetachesBothGenerations(t *testing.T) {
	recorder := &shutdownCallRecorder{}
	newListener := &fakeShutdownListener{recorder: recorder}
	oldListener := &fakeShutdownListener{recorder: recorder}
	newPlane := &fakeShutdownControlPlane{recorder: recorder}
	oldPlane := &fakeShutdownControlPlane{recorder: recorder}
	netns := &fakeShutdownNetns{recorder: recorder}

	err := shutdownAfterSignalWithHandoff(
		newDiscardLogger(),
		newListener,
		newPlane,
		netns,
		true,
		&signalShutdownStagedHandoff{
			oldListener:     oldListener,
			oldControlPlane: oldPlane,
			newListener:     newListener,
			newControlPlane: newPlane,
		},
	)
	if err != nil {
		t.Fatalf("shutdownAfterSignalWithHandoff() error = %v", err)
	}

	if newPlane.detachCalls != 1 {
		t.Fatalf("newPlane DetachBpfHooks calls = %d, want 1", newPlane.detachCalls)
	}
	if oldPlane.detachCalls != 1 {
		t.Fatalf("oldPlane DetachBpfHooks calls = %d, want 1", oldPlane.detachCalls)
	}
	if newPlane.abortCalls != 0 || oldPlane.abortCalls != 0 {
		t.Fatalf("AbortConnections calls = (%d, %d), want (0, 0)", newPlane.abortCalls, oldPlane.abortCalls)
	}
	if newPlane.closeCalls != 0 || oldPlane.closeCalls != 0 {
		t.Fatalf("Close calls = (%d, %d), want (0, 0)", newPlane.closeCalls, oldPlane.closeCalls)
	}
	if netns.closeCalls != 1 {
		t.Fatalf("netns.Close calls = %d, want 1 (netns is torn down even on fast exit)", netns.closeCalls)
	}

	wantOrder := []string{
		"listener.Close",
		"listener.Close",
		"control.DetachBpfHooks",
		"control.DetachBpfHooks",
		"netns.Close",
	}
	if !reflect.DeepEqual(recorder.order, wantOrder) {
		t.Fatalf("call order = %v, want %v", recorder.order, wantOrder)
	}
}

func TestNotifyRunStateChangeCoalescesPendingNotification(t *testing.T) {
	runStateChanges := make(chan struct{}, 1)

	notifyRunStateChange(runStateChanges)
	notifyRunStateChange(runStateChanges)

	select {
	case <-runStateChanges:
	default:
		t.Fatal("expected a pending run-state notification")
	}

	select {
	case <-runStateChanges:
		t.Fatal("expected notifications to coalesce while the channel is full")
	default:
	}
}

func TestTryQueueReloadRequestRejectsConcurrentReload(t *testing.T) {
	reqs := make(chan reloadRequest, 1)
	var reloadActive atomic.Bool
	var reloadPending atomic.Bool

	if !tryQueueReloadRequest(newDiscardLogger(), reqs, &reloadActive, &reloadPending, reloadRequest{isSuspend: false}) {
		t.Fatal("expected first reload request to be queued")
	}
	if !reloadPending.Load() {
		t.Fatal("expected reloadPending to remain set after queuing reload")
	}
	if tryQueueReloadRequest(newDiscardLogger(), reqs, &reloadActive, &reloadPending, reloadRequest{isSuspend: true}) {
		t.Fatal("expected concurrent reload request to be rejected")
	}

	select {
	case req := <-reqs:
		if req.isSuspend {
			t.Fatal("expected first queued reload request to be preserved")
		}
	default:
		t.Fatal("expected queued reload request")
	}
}

func TestRestoreRejectedReloadProgressUsesBusyWhileSettling(t *testing.T) {
	progressPath := filepath.Join(t.TempDir(), "dae.progress")
	oldWriter := setRunSignalProgress
	oldReader := getRunSignalProgress
	setRunSignalProgress = func(code byte, content string) error {
		return writeSignalProgressFile(progressPath, code, content)
	}
	getRunSignalProgress = func() (byte, string, error) {
		return readSignalProgressFile(progressPath)
	}
	t.Cleanup(func() {
		setRunSignalProgress = oldWriter
		getRunSignalProgress = oldReader
	})

	restoreRejectedReloadProgress(nil, false)

	code, content, err := readSignalProgressFile(progressPath)
	if err != nil {
		t.Fatalf("readSignalProgressFile() error = %v", err)
	}
	if code != consts.ReloadBusy {
		t.Fatalf("code = %q, want ReloadBusy", code)
	}
	if content == "" {
		t.Fatal("expected settling rejection to write a human-readable message")
	}
}

func TestRestoreRejectedReloadProgressUsesBusyWhileActive(t *testing.T) {
	progressPath := filepath.Join(t.TempDir(), "dae.progress")
	oldWriter := setRunSignalProgress
	oldReader := getRunSignalProgress
	setRunSignalProgress = func(code byte, content string) error {
		return writeSignalProgressFile(progressPath, code, content)
	}
	getRunSignalProgress = func() (byte, string, error) {
		return readSignalProgressFile(progressPath)
	}
	t.Cleanup(func() {
		setRunSignalProgress = oldWriter
		getRunSignalProgress = oldReader
	})

	var reloadActive atomic.Bool
	reloadActive.Store(true)

	restoreRejectedReloadProgress(&reloadActive, false)

	code, content, err := readSignalProgressFile(progressPath)
	if err != nil {
		t.Fatalf("readSignalProgressFile() error = %v", err)
	}
	if code != consts.ReloadBusy {
		t.Fatalf("code = %q, want ReloadBusy", code)
	}
	if content == "" {
		t.Fatal("expected active rejection to write a human-readable message")
	}
}

func TestReleaseReloadPendingAfterRetirementWaitsForCompletion(t *testing.T) {
	progressPath := filepath.Join(t.TempDir(), "dae.progress")
	oldWriter := setRunSignalProgress
	oldReader := getRunSignalProgress
	setRunSignalProgress = func(code byte, content string) error {
		return writeSignalProgressFile(progressPath, code, content)
	}
	getRunSignalProgress = func() (byte, string, error) {
		return readSignalProgressFile(progressPath)
	}
	t.Cleanup(func() {
		setRunSignalProgress = oldWriter
		getRunSignalProgress = oldReader
	})

	if err := writeSignalProgressFile(progressPath, consts.ReloadBusy, reloadBusyRetiringMessage); err != nil {
		t.Fatalf("writeSignalProgressFile() error = %v", err)
	}

	var reloadPending atomic.Bool
	reloadPending.Store(true)
	retirementDone := make(chan struct{})
	reloadReqs := make(chan reloadRequest, 1)
	var reloadActive atomic.Bool

	releaseReloadPendingAfterRetirement(&reloadPending, retirementDone)
	if !reloadPending.Load() {
		t.Fatal("expected reloadPending to remain set before retirement completes")
	}
	if tryQueueReloadRequest(newDiscardLogger(), reloadReqs, &reloadActive, &reloadPending, reloadRequest{}) {
		t.Fatal("expected a third staged reload to stay blocked while retirement holds an epoch slot")
	}
	close(retirementDone)
	deadline := time.After(time.Second)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if !reloadPending.Load() {
			code, content, err := readSignalProgressFile(progressPath)
			if err != nil {
				t.Fatalf("readSignalProgressFile() error = %v", err)
			}
			if code == consts.ReloadDone && content == "" {
				break
			}
		}
		select {
		case <-deadline:
			t.Fatal("expected reloadPending and progress file to settle after retirement completes")
		case <-ticker.C:
		}
	}
	if !tryQueueReloadRequest(newDiscardLogger(), reloadReqs, &reloadActive, &reloadPending, reloadRequest{}) {
		t.Fatal("expected reload request to be accepted after retirement releases epoch slots")
	}
	clearReloadPending(&reloadPending)
}

func TestRemainingReloadRetirementBudgetUsesElapsedTime(t *testing.T) {
	budget := 10 * time.Second
	remaining := remainingReloadRetirementBudget(time.Now().Add(-3*time.Second), budget)
	if remaining <= 0 {
		t.Fatal("expected positive remaining budget")
	}
	if remaining >= budget {
		t.Fatal("expected elapsed time to reduce remaining budget")
	}
}

func TestRemainingReloadRetirementBudgetClampsAtZero(t *testing.T) {
	if remaining := remainingReloadRetirementBudget(time.Now().Add(-15*time.Second), 10*time.Second); remaining != 0 {
		t.Fatalf("remaining = %v, want 0", remaining)
	}
}

func TestBeginReloadHandoffSetsReloadingBeforeNotification(t *testing.T) {
	var reloading atomic.Bool
	runStateChanges := make(chan struct{}, 1)

	beginReloadHandoff(&reloading, runStateChanges)

	select {
	case <-runStateChanges:
	default:
		t.Fatal("expected a pending run-state notification")
	}

	if !reloading.Load() {
		t.Fatal("expected reload handoff to remain latched until the consumer clears it")
	}
}

func TestReloadManagerBuildShutdownHandoffUsesPendingStagedHandoff(t *testing.T) {
	oldListener := &control.Listener{}
	newListener := &control.Listener{}
	oldPlane := &control.ControlPlane{}
	newPlane := &control.ControlPlane{}

	manager := newReloadManager(make(chan reloadRequest, 1), make(chan struct{}, 1), make(chan os.Signal, 1))
	manager.setPendingStagedHandoff(&stagedReloadHandoff{
		oldControlPlane: oldPlane,
		oldListener:     oldListener,
		newControlPlane: newPlane,
		newListener:     newListener,
	}, time.Now(), 123)

	handoff := manager.buildShutdownHandoff()
	if handoff == nil {
		t.Fatal("buildShutdownHandoff() = nil, want non-nil handoff")
	}
	if handoff.oldControlPlane != oldPlane || handoff.newControlPlane != newPlane {
		t.Fatal("expected shutdown handoff to preserve control plane ownership")
	}
	if handoff.oldListener != oldListener || handoff.newListener != newListener {
		t.Fatal("expected shutdown handoff to preserve listener ownership")
	}
}

func TestReloadManagerTransitionReleaseAllowsNextTransitionAndShutdown(t *testing.T) {
	manager := newReloadManager(make(chan reloadRequest, 1), make(chan struct{}, 1), make(chan os.Signal, 1))
	supervisor := newRuntimeSupervisor(newTestRuntimeGeneration())

	if !manager.beginReloadTransition() {
		t.Fatal("first beginReloadTransition() = false, want true")
	}
	manager.endReloadTransition()
	if !manager.beginReloadTransition() {
		t.Fatal("second beginReloadTransition() = false after release, want true")
	}
	manager.endReloadTransition()

	_ = manager.shutdownSupervisor(supervisor)
	if manager.beginReloadTransition() {
		manager.endReloadTransition()
		t.Fatal("beginReloadTransition() succeeded after shutdown")
	}
}

func TestReloadManagerShutdownSupervisorWaitsForTransition(t *testing.T) {
	manager := newReloadManager(make(chan reloadRequest, 1), make(chan struct{}, 1), make(chan os.Signal, 1))
	active := newTestRuntimeGeneration()
	supervisor := newRuntimeSupervisor(active)
	if !manager.beginReloadTransition() {
		t.Fatal("beginReloadTransition() = false, want true")
	}

	shutdownDone := make(chan runtimeSupervisorSnapshot, 1)
	go func() {
		shutdownDone <- manager.shutdownSupervisor(supervisor)
	}()

	select {
	case <-shutdownDone:
		t.Fatal("shutdownSupervisor() returned before the reload transition released")
	case <-time.After(20 * time.Millisecond):
	}

	manager.endReloadTransition()
	select {
	case snapshot := <-shutdownDone:
		if snapshot.active != active {
			t.Fatal("shutdownSupervisor() did not return the active generation")
		}
	case <-time.After(time.Second):
		t.Fatal("shutdownSupervisor() did not finish after transition release")
	}
}

func TestReloadManagerShutdownSupervisorExcludesWorkerOwnedRetirement(t *testing.T) {
	manager := newReloadManager(make(chan reloadRequest, 1), make(chan struct{}, 1), make(chan os.Signal, 1))
	oldGeneration := newTestRuntimeGeneration()
	newGeneration := newTestRuntimeGeneration()
	supervisor := newRuntimeSupervisor(oldGeneration)
	if err := supervisor.installPrepared(newGeneration); err != nil {
		t.Fatalf("installPrepared() error = %v", err)
	}
	retiring, err := supervisor.publishPrepared(newGeneration)
	if err != nil {
		t.Fatalf("publishPrepared() error = %v", err)
	}

	canceled := make(chan struct{})
	task := &activeRetirementTask{
		generation: retiring,
		cancel:     func() { close(canceled) },
		done:       make(chan struct{}),
	}
	manager.lastRetirementMu.Lock()
	manager.activeRetirement = task
	manager.lastRetirementMu.Unlock()

	shutdownDone := make(chan runtimeSupervisorSnapshot, 1)
	go func() {
		shutdownDone <- manager.shutdownSupervisor(supervisor)
	}()
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("shutdownSupervisor() did not cancel the active retirement task")
	}
	select {
	case <-shutdownDone:
		t.Fatal("shutdownSupervisor() returned before the worker-owned retirement completed")
	case <-time.After(20 * time.Millisecond):
	}

	close(task.done)
	var snapshot runtimeSupervisorSnapshot
	select {
	case snapshot = <-shutdownDone:
	case <-time.After(time.Second):
		t.Fatal("shutdownSupervisor() did not join the retirement task")
	}
	if snapshot.retiring != nil {
		t.Fatal("worker-owned retiring generation remained in the shutdown snapshot")
	}
	if handoff := manager.buildShutdownHandoffWithSupervisor(snapshot, newGeneration); handoff != nil {
		t.Fatal("worker-owned retiring generation was returned for duplicate shutdown cleanup")
	}
}

func TestBuildRunShutdownHandoffFastExitBypassesSupervisorFreeze(t *testing.T) {
	manager := newReloadManager(make(chan reloadRequest, 1), make(chan struct{}, 1), make(chan os.Signal, 1))
	active := newTestRuntimeGeneration()
	supervisor := newRuntimeSupervisor(active)

	if handoff := buildRunShutdownHandoff(manager, supervisor, active, true); handoff != nil {
		t.Fatal("fast-exit shutdown unexpectedly built supervisor cleanup handoff")
	}
	if snapshot := supervisorSnapshotForTest(supervisor); snapshot.active != active {
		t.Fatal("fast-exit shutdown froze the active supervisor generation")
	}
	if !manager.beginReloadTransition() {
		t.Fatal("fast-exit shutdown closed the reload transition barrier")
	}
	manager.endReloadTransition()
}

func TestBuildRunShutdownHandoffCarriesCurrentGenerationCancel(t *testing.T) {
	manager := newReloadManager(make(chan reloadRequest, 1), make(chan struct{}, 1), make(chan os.Signal, 1))
	var cancelCalls atomic.Int32
	active := newTestRuntimeGeneration()
	active.cancel = func() { cancelCalls.Add(1) }
	supervisor := newRuntimeSupervisor(active)

	handoff := buildRunShutdownHandoff(manager, supervisor, active, false)
	if handoff == nil || handoff.newCancel == nil {
		t.Fatal("graceful shutdown handoff omitted current generation cancel")
	}
	handoff.newCancel()
	if got := cancelCalls.Load(); got != 1 {
		t.Fatalf("current generation cancel calls = %d, want 1", got)
	}
}

func TestReloadManagerShutdownSupervisorIncludesUnclaimedRetirement(t *testing.T) {
	manager := newReloadManager(make(chan reloadRequest, 1), make(chan struct{}, 1), make(chan os.Signal, 1))
	oldGeneration := newTestRuntimeGeneration()
	newGeneration := newTestRuntimeGeneration()
	supervisor := newRuntimeSupervisor(oldGeneration)
	if err := supervisor.installPrepared(newGeneration); err != nil {
		t.Fatalf("installPrepared() error = %v", err)
	}
	if _, err := supervisor.publishPrepared(newGeneration); err != nil {
		t.Fatalf("publishPrepared() error = %v", err)
	}

	snapshot := manager.shutdownSupervisor(supervisor)
	handoff := manager.buildShutdownHandoffWithSupervisor(snapshot, newGeneration)
	if handoff == nil || handoff.oldControlPlane != oldGeneration.controlPlane || handoff.oldListener != oldGeneration.listener {
		t.Fatal("unclaimed retiring generation is missing from shutdown cleanup")
	}
}

func TestReloadManagerStartRetirementSkipsClosedSupervisor(t *testing.T) {
	manager := newReloadManager(make(chan reloadRequest, 1), make(chan struct{}, 1), make(chan os.Signal, 1))
	oldGeneration := newTestRuntimeGeneration()
	newGeneration := newTestRuntimeGeneration()
	supervisor := newRuntimeSupervisor(oldGeneration)
	if err := supervisor.installPrepared(newGeneration); err != nil {
		t.Fatalf("installPrepared() error = %v", err)
	}
	retiring, err := supervisor.publishPrepared(newGeneration)
	if err != nil {
		t.Fatalf("publishPrepared() error = %v", err)
	}
	_ = supervisor.shutdown()

	manager.startControlPlaneRetirement(newDiscardLogger(), oldGeneration.controlPlane, nil, oldGeneration.cancel, false, supervisor, retiring)
	manager.lastRetirementMu.Lock()
	task := manager.activeRetirement
	manager.lastRetirementMu.Unlock()
	if task != nil {
		t.Fatal("startControlPlaneRetirement() started work after supervisor shutdown")
	}
}

func TestReloadManagerCoalesceReloadRequestKeepsLatestQueuedRequest(t *testing.T) {
	reloadReqs := make(chan reloadRequest, 2)
	manager := newReloadManager(reloadReqs, make(chan struct{}, 1), make(chan os.Signal, 1))

	now := time.Now()
	latest := reloadRequest{
		isSuspend:       true,
		requestedAt:     now.Add(time.Second),
		requestedAtMono: 99,
	}
	reloadReqs <- latest

	got := manager.coalesceReloadRequest(reloadRequest{
		isSuspend:       false,
		requestedAt:     now,
		requestedAtMono: 11,
	})

	if got != latest {
		t.Fatalf("coalesceReloadRequest() = %+v, want latest queued %+v", got, latest)
	}
}

func TestDNSConfigEqualUsesStableFingerprint(t *testing.T) {
	oldConf := &config.Config{
		Dns: config.Dns{
			Bind:               "127.0.0.1:53",
			IpVersionPrefer:    4,
			Upstream:           []config.KeyableString{"google:udp://8.8.8.8:53"},
			OptimisticCache:    true,
			OptimisticCacheTtl: 60,
		},
	}
	newConf := &config.Config{Dns: oldConf.Dns}
	if !dnsConfigEqual(oldConf, newConf) {
		t.Fatal("expected identical DNS configs to compare equal")
	}

	newConf.Dns.Bind = "127.0.0.1:5353"
	if dnsConfigEqual(oldConf, newConf) {
		t.Fatal("expected changed DNS config to compare unequal")
	}
}

func TestDNSConfigFingerprintCoversAllDnsFields(t *testing.T) {
	// Fields that MUST be covered by dnsConfigFingerprint because they
	// affect BPF datapath state (domain_routing_map, routing rules, upstream).
	covered := map[string]struct{}{
		"IpVersionPrefer": {},
		"FixedDomainTtl":  {},
		"Upstream":        {},
		"Routing":         {},
		"Bind":            {},
	}

	// Fields that are intentionally EXCLUDED from dnsConfigFingerprint
	// because they are runtime-tunable via DnsController.UpdateRuntime
	// (atomic stores) and do not affect BPF map state. Including them
	// would cause unnecessary domain_routing_map clear+replay during
	// staged handoff (dae#1013).
	excluded := map[string]struct{}{
		"OptimisticCache":         {},
		"OptimisticCacheTtl":      {},
		"OptimisticStaleReplyTtl": {},
		"MaxCacheSize":            {},
	}

	dnsType := reflect.TypeFor[config.Dns]()
	for field := range dnsType.Fields() {
		name := field.Name
		if _, isExcluded := excluded[name]; isExcluded {
			continue
		}
		if _, ok := covered[name]; !ok {
			t.Fatalf("dnsConfigFingerprint does not cover config.Dns.%s", name)
		}
		delete(covered, name)
	}
	for name := range covered {
		t.Fatalf("dnsConfigFingerprint coverage references missing config.Dns.%s", name)
	}
}

func baseReloadDatapathConfig() *config.Config {
	return &config.Config{
		Global: config.Global{
			TproxyPort:            12345,
			LanInterface:          []string{"eth0"},
			WanInterface:          []string{"wan0"},
			BpfConnStateMapSize:   262144,
			SoMarkFromDae:         0x8000000,
			SoMarkFromDaeSet:      true,
			FallbackResolver:      "8.8.8.8:53",
			DialMode:              "ip",
			DisableWaitingNetwork: true,
		},
		Group: []config.Group{
			{Name: "proxy", Policy: config.FunctionListOrString("fixed(0)")},
		},
		Routing: config.Routing{
			Fallback: "direct",
		},
		Dns: config.Dns{
			Bind:               "127.0.0.1:53",
			IpVersionPrefer:    4,
			Upstream:           []config.KeyableString{"google:udp://8.8.8.8:53"},
			OptimisticCache:    true,
			OptimisticCacheTtl: 60,
			MaxCacheSize:       1024,
		},
	}
}

func TestBpfDatapathChangedIgnoresDnsRuntimeParameters(t *testing.T) {
	oldConf := baseReloadDatapathConfig()
	newConf := deepcopy.Copy(oldConf).(*config.Config)
	newConf.Dns.OptimisticCache = !oldConf.Dns.OptimisticCache
	newConf.Dns.OptimisticCacheTtl = oldConf.Dns.OptimisticCacheTtl + 30
	newConf.Dns.MaxCacheSize = oldConf.Dns.MaxCacheSize + 2048

	if bpfDatapathChanged(oldConf, newConf) {
		t.Fatal("DNS runtime-only changes must stay on shared staged handoff")
	}
}

func TestBpfDatapathChangedDetectsKernelDatapathInputs(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*config.Config)
	}{
		{
			name: "lan interface",
			mutate: func(conf *config.Config) {
				conf.Global.LanInterface = []string{"eth1"}
			},
		},
		{
			name: "wan interface",
			mutate: func(conf *config.Config) {
				conf.Global.WanInterface = []string{"ppp0"}
			},
		},
		{
			name: "conn state map size",
			mutate: func(conf *config.Config) {
				conf.Global.BpfConnStateMapSize *= 2
			},
		},
		{
			name: "socket mark",
			mutate: func(conf *config.Config) {
				conf.Global.SoMarkFromDae++
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oldConf := baseReloadDatapathConfig()
			newConf := deepcopy.Copy(oldConf).(*config.Config)
			tt.mutate(newConf)
			if !bpfDatapathChanged(oldConf, newConf) {
				t.Fatal("expected datapath-affecting change")
			}
		})
	}
}

func TestPreserveReloadInterfaceBindingsOnlyAddsDuringHotReload(t *testing.T) {
	oldConf := &config.Config{Global: config.Global{
		LanInterface: []string{"lan0", "shared0"},
		WanInterface: []string{"wan0"},
	}}
	newConf := &config.Config{Global: config.Global{
		LanInterface: []string{"lan1", "wan0"},
		WanInterface: []string{"wan1", "lan0"},
	}}

	deferred := preserveReloadInterfaceBindings(oldConf, newConf)
	if got, want := fmt.Sprint(deferred), "[lan:lan0 lan:shared0 wan:wan0]"; got != want {
		t.Fatalf("deferred bindings = %s, want %s", got, want)
	}
	if got, want := fmt.Sprint(newConf.Global.LanInterface), "[lan1 lan0 shared0]"; got != want {
		t.Fatalf("effective LAN interfaces = %s, want %s", got, want)
	}
	if got, want := fmt.Sprint(newConf.Global.WanInterface), "[wan1 wan0]"; got != want {
		t.Fatalf("effective WAN interfaces = %s, want %s", got, want)
	}
}

// TestBpfDatapathChangedRoutesPolicyChangesViaStagedHandoff verifies that
// policy-level config changes (routing rules, fallback, groups, DNS upstream)
// do NOT trigger a fresh BPF reload. These changes are delivered via BPF map
// updates and Go-side rebuilds, so the staged-hot-handoff path handles them
// without aborting established connections.
func TestBpfDatapathChangedRoutesPolicyChangesViaStagedHandoff(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*config.Config)
	}{
		{
			name: "dns upstream",
			mutate: func(conf *config.Config) {
				conf.Dns.Upstream = []config.KeyableString{"cloudflare:udp://1.1.1.1:53"}
			},
		},
		{
			name: "routing rules",
			mutate: func(conf *config.Config) {
				conf.Routing.Rules = []*config_parser.RoutingRule{
					{
						AndFunctions: []*config_parser.Function{
							{Name: "domain", Params: []*config_parser.Param{{Key: "suffix", Val: "new.com"}}},
						},
						Outbound: config_parser.Function{Name: "proxy"},
					},
				}
			},
		},
		{
			name: "routing fallback",
			mutate: func(conf *config.Config) {
				conf.Routing.Fallback = "block"
			},
		},
		{
			name: "group definition",
			mutate: func(conf *config.Config) {
				conf.Group = append(conf.Group, config.Group{Name: "backup", Policy: config.FunctionListOrString("fixed(0)")})
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oldConf := baseReloadDatapathConfig()
			newConf := deepcopy.Copy(oldConf).(*config.Config)
			tt.mutate(newConf)
			if bpfDatapathChanged(oldConf, newConf) {
				t.Fatal("policy-level change must route through staged handoff, not fresh datapath reload")
			}
		})
	}
}

func TestBuildPreparedDNSHandoffHooksReuseHookReusesControllerAndListener(t *testing.T) {
	var reuseControllerCalls int
	var reuseListenerCalls int
	hooks := buildPreparedDNSHandoffHooks(newDiscardLogger(), true, preparedDNSHandoffHookCallbacks{
		reuseController: func() bool {
			reuseControllerCalls++
			return true
		},
		reuseListener: func() bool {
			reuseListenerCalls++
			return true
		},
	})
	if hooks.reuseHook == nil {
		t.Fatal("reuseHook = nil, want non-nil")
	}
	if err := hooks.reuseHook(); err != nil {
		t.Fatalf("reuseHook() error = %v", err)
	}
	if reuseControllerCalls != 1 {
		t.Fatalf("reuseControllerCalls = %d, want 1", reuseControllerCalls)
	}
	if reuseListenerCalls != 1 {
		t.Fatalf("reuseListenerCalls = %d, want 1", reuseListenerCalls)
	}
}

func TestBuildPreparedDNSHandoffHooksReuseHookRejectsControllerFailure(t *testing.T) {
	var reuseListenerCalls int
	hooks := buildPreparedDNSHandoffHooks(newDiscardLogger(), true, preparedDNSHandoffHookCallbacks{
		reuseController: func() bool { return false },
		reuseListener: func() bool {
			reuseListenerCalls++
			return true
		},
	})
	if hooks.reuseHook == nil {
		t.Fatal("reuseHook = nil, want non-nil")
	}
	if err := hooks.reuseHook(); err == nil {
		t.Fatal("reuseHook() error = nil after controller reuse failure")
	}
	if reuseListenerCalls != 0 {
		t.Fatalf("reuseListenerCalls = %d, want 0 after controller failure", reuseListenerCalls)
	}
}

func TestBuildPreparedDNSHandoffHooksStartHookStopsOldListenerWhenReuseFails(t *testing.T) {
	var stopCalls int
	hooks := buildPreparedDNSHandoffHooks(newDiscardLogger(), false, preparedDNSHandoffHookCallbacks{
		reuseListener: func() bool { return false },
		stopOldListener: func() error {
			stopCalls++
			return nil
		},
	})
	if hooks.startHook == nil {
		t.Fatal("startHook = nil, want non-nil")
	}
	if err := hooks.startHook(); err != nil {
		t.Fatalf("startHook() error = %v", err)
	}
	if stopCalls != 1 {
		t.Fatalf("stopCalls = %d, want 1", stopCalls)
	}
}

func TestBuildPreparedDNSHandoffHooksStartHookPropagatesStopError(t *testing.T) {
	wantErr := errors.New("stop failed")
	hooks := buildPreparedDNSHandoffHooks(newDiscardLogger(), false, preparedDNSHandoffHookCallbacks{
		reuseListener:   func() bool { return false },
		stopOldListener: func() error { return wantErr },
	})
	if err := hooks.startHook(); !errors.Is(err, wantErr) {
		t.Fatalf("startHook() error = %v, want %v", err, wantErr)
	}
}

func TestReloadManagerStartControlPlaneRetirementCompletesAndCancelsOldContext(t *testing.T) {
	manager := newReloadManager(make(chan reloadRequest, 1), make(chan struct{}, 1), make(chan os.Signal, 1))
	manager.setPendingReloadMetadata(time.Now(), 0)

	oldCtx, oldCancel := context.WithCancel(context.Background())
	oldGeneration := newTestRuntimeGeneration()
	oldGeneration.cancel = oldCancel
	newGeneration := newTestRuntimeGeneration()
	supervisor := newRuntimeSupervisor(oldGeneration)
	if err := supervisor.installPrepared(newGeneration); err != nil {
		t.Fatalf("installPrepared() error = %v", err)
	}
	retiringGeneration, err := supervisor.publishPrepared(newGeneration)
	if err != nil {
		t.Fatalf("publishPrepared() error = %v", err)
	}
	manager.startControlPlaneRetirement(newDiscardLogger(), oldGeneration.controlPlane, nil, oldCancel, false, supervisor, retiringGeneration)

	manager.mu.Lock()
	retirementDone := manager.pendingRetirementDone
	manager.mu.Unlock()
	if retirementDone == nil {
		t.Fatal("pendingRetirementDone = nil, want retirement completion channel")
	}

	select {
	case <-retirementDone:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for retirement goroutine to finish")
	}

	select {
	case <-oldCtx.Done():
	default:
		t.Fatal("expected old generation cancel function to be called")
	}
	if snapshot := supervisorSnapshotForTest(supervisor); snapshot.retiring != nil {
		t.Fatal("expected retirement completion to release the exact supervisor generation")
	}
}

func TestReloadManagerRepeatedRetirementLifecycleReclaimsGeneration(t *testing.T) {
	for iteration := range 64 {
		manager := newReloadManager(make(chan reloadRequest, 1), make(chan struct{}, 1), make(chan os.Signal, 1))
		manager.setPendingReloadMetadata(time.Now(), 0)

		oldContext, oldCancel := context.WithCancel(context.Background())
		oldGeneration := newTestRuntimeGeneration()
		oldGeneration.cancel = oldCancel
		newGeneration := newTestRuntimeGeneration()
		supervisor := newRuntimeSupervisor(oldGeneration)
		if err := supervisor.installPrepared(newGeneration); err != nil {
			t.Fatalf("iteration %d installPrepared() error = %v", iteration, err)
		}
		retiring, err := supervisor.publishPrepared(newGeneration)
		if err != nil {
			t.Fatalf("iteration %d publishPrepared() error = %v", iteration, err)
		}

		manager.startControlPlaneRetirement(
			newDiscardLogger(),
			oldGeneration.controlPlane,
			nil,
			oldCancel,
			false,
			supervisor,
			retiring,
		)
		manager.mu.Lock()
		retirementDone := manager.pendingRetirementDone
		manager.mu.Unlock()
		if retirementDone == nil {
			t.Fatalf("iteration %d pendingRetirementDone = nil", iteration)
		}
		select {
		case <-retirementDone:
		case <-time.After(time.Second):
			t.Fatalf("iteration %d retirement did not complete", iteration)
		}

		select {
		case <-oldContext.Done():
		default:
			t.Fatalf("iteration %d old generation context was not canceled", iteration)
		}
		if snapshot := supervisorSnapshotForTest(supervisor); snapshot.active != newGeneration || snapshot.prepared != nil || snapshot.retiring != nil {
			t.Fatalf("iteration %d supervisor retained stale ownership: %#v", iteration, snapshot)
		}
		manager.lastRetirementMu.Lock()
		activeRetirement := manager.activeRetirement
		manager.lastRetirementMu.Unlock()
		if activeRetirement != nil {
			t.Fatalf("iteration %d manager retained active retirement task", iteration)
		}
		manager.finishReloadSuccess()
		if pending := manager.takePendingRetirementDone(); pending != nil {
			t.Fatalf("iteration %d pending retirement channel remained after success", iteration)
		}
	}
}

func TestWaitReloadReadyOrSignalReturnsOnReady(t *testing.T) {
	sigs := make(chan os.Signal, 1)
	readyChan := make(chan bool, 1)
	readyChan <- true

	result, termSig := waitReloadReadyOrSignal(newDiscardLogger(), sigs, readyChan, time.Second)
	if result != reloadReadyWaitReady {
		t.Fatalf("result = %v, want reloadReadyWaitReady", result)
	}
	if termSig != nil {
		t.Fatalf("termSig = %v, want nil", termSig)
	}
}

func TestWaitReloadReadyOrSignalReturnsOnTerminationSignal(t *testing.T) {
	sigs := make(chan os.Signal, 1)
	readyChan := make(chan bool)
	sigs <- syscall.SIGINT

	result, termSig := waitReloadReadyOrSignal(newDiscardLogger(), sigs, readyChan, time.Second)
	if result != reloadReadyWaitSignal {
		t.Fatalf("result = %v, want reloadReadyWaitSignal", result)
	}
	if termSig != syscall.SIGINT {
		t.Fatalf("termSig = %v, want SIGINT", termSig)
	}
}

func TestWaitReloadReadyOrSignalIgnoresReloadSignalsUntilReady(t *testing.T) {
	sigs := make(chan os.Signal, 1)
	readyChan := make(chan bool, 1)
	sigs <- syscall.SIGUSR1

	go func() {
		time.Sleep(10 * time.Millisecond)
		readyChan <- true
	}()

	result, termSig := waitReloadReadyOrSignal(newDiscardLogger(), sigs, readyChan, time.Second)
	if result != reloadReadyWaitReady {
		t.Fatalf("result = %v, want reloadReadyWaitReady", result)
	}
	if termSig != nil {
		t.Fatalf("termSig = %v, want nil", termSig)
	}
}

func TestWaitReloadReadyOrSignalReturnsTimeout(t *testing.T) {
	sigs := make(chan os.Signal, 1)
	readyChan := make(chan bool)

	result, termSig := waitReloadReadyOrSignal(newDiscardLogger(), sigs, readyChan, 10*time.Millisecond)
	if result != reloadReadyWaitTimeout {
		t.Fatalf("result = %v, want reloadReadyWaitTimeout", result)
	}
	if termSig != nil {
		t.Fatalf("termSig = %v, want nil", termSig)
	}
}

func TestReloadManagerFailReloadAttemptClearsBusyState(t *testing.T) {
	progressPath := filepath.Join(t.TempDir(), "dae.progress")
	oldWriter := setRunSignalProgress
	setRunSignalProgress = func(code byte, content string) error {
		return writeSignalProgressFile(progressPath, code, content)
	}
	t.Cleanup(func() { setRunSignalProgress = oldWriter })

	manager := newReloadManager(make(chan reloadRequest, 1), make(chan struct{}, 1), make(chan os.Signal, 1))
	manager.reloadActive.Store(true)
	manager.reloadPending.Store(true)

	manager.failReloadAttempt(errors.New("boom"))

	if manager.reloadActive.Load() {
		t.Fatal("expected reloadActive to be cleared")
	}
	if manager.reloadPending.Load() {
		t.Fatal("expected reloadPending to be cleared")
	}
	code, content, err := readSignalProgressFile(progressPath)
	if err != nil {
		t.Fatalf("readSignalProgressFile() error = %v", err)
	}
	if code != consts.ReloadError || content != "boom" {
		t.Fatalf("progress = (%d, %q), want (ReloadError, %q)", code, content, "boom")
	}
}

func TestReloadManagerFailPublishedReloadAttemptClearsHandoffState(t *testing.T) {
	progressPath := filepath.Join(t.TempDir(), "dae.progress")
	oldWriter := setRunSignalProgress
	setRunSignalProgress = func(code byte, content string) error {
		return writeSignalProgressFile(progressPath, code, content)
	}
	t.Cleanup(func() { setRunSignalProgress = oldWriter })

	manager := newReloadManager(make(chan reloadRequest, 1), make(chan struct{}, 1), make(chan os.Signal, 1))
	manager.reloading.Store(true)
	manager.reloadActive.Store(true)
	manager.reloadPending.Store(true)

	manager.failPublishedReloadAttempt(errors.New("publish failed"))

	if manager.reloading.Load() {
		t.Fatal("expected reloading to be cleared after a published-path failure")
	}
	if manager.reloadActive.Load() {
		t.Fatal("expected reloadActive to be cleared")
	}
	if manager.reloadPending.Load() {
		t.Fatal("expected reloadPending to be cleared")
	}
	code, content, err := readSignalProgressFile(progressPath)
	if err != nil {
		t.Fatalf("readSignalProgressFile() error = %v", err)
	}
	if code != consts.ReloadError || content != "publish failed" {
		t.Fatalf("progress = (%d, %q), want (ReloadError, %q)", code, content, "publish failed")
	}
}

func TestShouldUseStagedHotHandoff(t *testing.T) {
	if !shouldUseStagedHotHandoff(false, true) {
		t.Fatal("same-port reload with a live listener must use staged hot handoff")
	}
	if shouldUseStagedHotHandoff(true, true) {
		t.Fatal("fresh datapath reload must not overlap generations")
	}
	if shouldUseStagedHotHandoff(false, false) {
		t.Fatal("cold start without a listener cannot stage a hot handoff")
	}
}

func TestCanRecoverReloadReadinessFailureOnlyAfterServeReturns(t *testing.T) {
	tests := []struct {
		result reloadReadyWaitResult
		want   bool
	}{
		{result: reloadReadyWaitReady},
		{result: reloadReadyWaitFailed, want: true},
		{result: reloadReadyWaitSignal},
		{result: reloadReadyWaitTimeout},
	}
	for _, test := range tests {
		if got := canRecoverReloadReadinessFailure(test.result); got != test.want {
			t.Fatalf("canRecoverReloadReadinessFailure(%d) = %t, want %t", test.result, got, test.want)
		}
	}
}

func TestWaitForControlPlaneDrainReturnsIdleImmediately(t *testing.T) {
	result := waitForControlPlaneDrain(newDiscardLogger(), context.Background(), newFakeRetirementControlPlane(0), time.Second, 0)
	if result != controlPlaneDrainIdle {
		t.Fatalf("result = %v, want controlPlaneDrainIdle", result)
	}
}

func TestWaitForControlPlaneDrainReturnsIdleAfterSignal(t *testing.T) {
	plane := newFakeRetirementControlPlane(1)
	go func() {
		time.Sleep(10 * time.Millisecond)
		atomic.StoreInt32(&plane.active, 0)
		close(plane.idleCh)
	}()

	result := waitForControlPlaneDrain(newDiscardLogger(), context.Background(), plane, time.Second, 0)
	if result != controlPlaneDrainIdle {
		t.Fatalf("result = %v, want controlPlaneDrainIdle", result)
	}
}

func TestWaitForControlPlaneDrainReturnsCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	plane := newFakeRetirementControlPlane(1)
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()

	result := waitForControlPlaneDrain(newDiscardLogger(), ctx, plane, time.Second, 0)
	if result != controlPlaneDrainCanceled {
		t.Fatalf("result = %v, want controlPlaneDrainCanceled", result)
	}
}

func TestWaitForControlPlaneDrainReturnsTimeout(t *testing.T) {
	result := waitForControlPlaneDrain(newDiscardLogger(), context.Background(), newFakeRetirementControlPlane(1), 10*time.Millisecond, 0)
	if result != controlPlaneDrainTimeout {
		t.Fatalf("result = %v, want controlPlaneDrainTimeout", result)
	}
}

// retirementBehaviorPlane extends fakeRetirementControlPlane with abort
// tracking to prove the three-way retirement precedence rule:
// abort → !overlap → drain.
type retirementBehaviorPlane struct {
	*fakeRetirementControlPlane
	abortCalled         atomic.Bool
	pendingAbortCalled  atomic.Bool
	stopExecutionCalled atomic.Bool
	abortErr            error
	pendingAbortErr     error
}

type blockingStopRetirementPlane struct {
	*retirementBehaviorPlane
	stopStarted chan struct{}
	stopRelease chan struct{}
}

func (r *blockingStopRetirementPlane) StopRoutingEpochExecution() {
	r.StopRoutingEpochExecutionWithTimeout(0)
}

func (r *blockingStopRetirementPlane) StopRoutingEpochExecutionWithTimeout(time.Duration) {
	close(r.stopStarted)
	<-r.stopRelease
	r.retirementBehaviorPlane.StopRoutingEpochExecution()
}

func (r *retirementBehaviorPlane) AbortConnections() error {
	r.abortCalled.Store(true)
	return r.abortErr
}

func (r *retirementBehaviorPlane) AbortPendingConnections() error {
	r.pendingAbortCalled.Store(true)
	return r.pendingAbortErr
}

func (r *retirementBehaviorPlane) StopRoutingEpochExecution() {
	r.stopExecutionCalled.Store(true)
}

func (r *retirementBehaviorPlane) StopRoutingEpochExecutionWithTimeout(time.Duration) {
	r.StopRoutingEpochExecution()
}

func TestReloadRetirementBehavior(t *testing.T) {
	// The retired address-overlap dimension is gone: retirement is two-stage
	// and no longer varies with whether the generations share listen addresses.
	tests := []struct {
		name        string
		abort       bool
		expectDrain bool
	}{
		{"staged_no_abortfile_graceful", false, true},
		{"staged_abortfile_immediate_abort", true, false},
		{"nonstaged_no_abortfile_graceful", false, true},
		{"nonstaged_abortfile_immediate_abort", true, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plane := &retirementBehaviorPlane{
				fakeRetirementControlPlane: newFakeRetirementControlPlane(1),
			}
			done := make(chan struct{})

			go func() {
				defer close(done)
				retireControlPlaneConnections(newDiscardLogger(), context.Background(), plane, tt.abort, 10*time.Second)
			}()

			if tt.expectDrain {
				select {
				case <-done:
					t.Fatal("graceful retirement completed while drain was still blocked")
				case <-time.After(50 * time.Millisecond):
				}
				atomic.StoreInt32(&plane.active, 0)
				close(plane.idleCh)
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Fatal("graceful retirement did not complete after drain release")
				}
				if !plane.stopExecutionCalled.Load() {
					t.Fatal("graceful retirement did not seal routing epoch execution")
				}
			} else {
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Fatal("immediate-abort retirement did not complete in time")
				}
				if !plane.abortCalled.Load() {
					t.Fatal("expected AbortConnections to be called for immediate-abort case")
				}
				if !plane.stopExecutionCalled.Load() {
					t.Fatal("immediate-abort retirement did not seal routing epoch execution")
				}
			}
		})
	}
}

func TestReloadRetirementAbortWaitsForRoutingExecutionLeases(t *testing.T) {
	plane := &blockingStopRetirementPlane{
		retirementBehaviorPlane: &retirementBehaviorPlane{
			fakeRetirementControlPlane: newFakeRetirementControlPlane(1),
		},
		stopStarted: make(chan struct{}),
		stopRelease: make(chan struct{}),
	}
	done := make(chan struct{})
	go func() {
		retireControlPlaneConnections(newDiscardLogger(), context.Background(), plane, true, time.Second)
		close(done)
	}()

	select {
	case <-plane.stopStarted:
	case <-time.After(time.Second):
		t.Fatal("abort retirement did not begin routing execution shutdown")
	}
	if !plane.abortCalled.Load() {
		t.Fatal("abort retirement reached execution shutdown before AbortConnections")
	}
	select {
	case <-done:
		t.Fatal("abort retirement returned before routing execution leases drained")
	case <-time.After(50 * time.Millisecond):
	}
	close(plane.stopRelease)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("abort retirement did not finish after routing execution leases drained")
	}
}

func TestReloadRetirementAbortsPendingWorkAfterDrainTimeout(t *testing.T) {
	plane := &retirementBehaviorPlane{
		fakeRetirementControlPlane: newFakeRetirementControlPlane(1),
	}

	retireControlPlaneConnections(newDiscardLogger(), context.Background(), plane, false, 10*time.Millisecond)

	if !plane.pendingAbortCalled.Load() || plane.abortCalled.Load() {
		t.Fatal("expected only AbortPendingConnections after drain timeout")
	}
}

func TestReloadRetirementAbortsPendingWorkAfterDrainCancel(t *testing.T) {
	plane := &retirementBehaviorPlane{
		fakeRetirementControlPlane: newFakeRetirementControlPlane(1),
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	retireControlPlaneConnections(newDiscardLogger(), ctx, plane, false, time.Second)

	if !plane.pendingAbortCalled.Load() || plane.abortCalled.Load() {
		t.Fatal("expected only AbortPendingConnections after drain cancellation")
	}
}
