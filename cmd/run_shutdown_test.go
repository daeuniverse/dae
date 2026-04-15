package cmd

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/control"
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

func TestShutdownAfterSignalFastExitSkipsGracefulTeardown(t *testing.T) {
	recorder := &shutdownCallRecorder{}
	listener := &fakeShutdownListener{recorder: recorder}
	plane := &fakeShutdownControlPlane{recorder: recorder}
	netns := &fakeShutdownNetns{recorder: recorder}

	if err := shutdownAfterSignal(newDiscardLogger(), listener, plane, netns, true); err != nil {
		t.Fatalf("shutdownAfterSignal() error = %v", err)
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
	if netns.closeCalls != 0 {
		t.Fatalf("netns.Close calls = %d, want 0", netns.closeCalls)
	}

	wantOrder := []string{
		"listener.Close",
		"control.DetachBpfHooks",
	}
	if !reflect.DeepEqual(recorder.order, wantOrder) {
		t.Fatalf("call order = %v, want %v", recorder.order, wantOrder)
	}
}

func TestShutdownAfterSignalGracefulExitRunsFullTeardown(t *testing.T) {
	recorder := &shutdownCallRecorder{}
	listener := &fakeShutdownListener{recorder: recorder}
	plane := &fakeShutdownControlPlane{
		recorder: recorder,
		closeErr: errors.New("close failed"),
	}
	netns := &fakeShutdownNetns{recorder: recorder}

	err := shutdownAfterSignal(newDiscardLogger(), listener, plane, netns, false)
	if err == nil || err.Error() != "close control plane: close failed" {
		t.Fatalf("shutdownAfterSignal() error = %v, want close control plane: close failed", err)
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

func TestShutdownAfterSignalTypedNilResourcesAreSkipped(t *testing.T) {
	var listener *control.Listener
	var plane *control.ControlPlane
	var netns *control.DaeNetns

	if err := shutdownAfterSignal(newDiscardLogger(), listener, plane, netns, true); err != nil {
		t.Fatalf("shutdownAfterSignal() error = %v, want nil", err)
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
	if netns.closeCalls != 0 {
		t.Fatalf("netns.Close calls = %d, want 0", netns.closeCalls)
	}

	wantOrder := []string{
		"listener.Close",
		"listener.Close",
		"control.DetachBpfHooks",
		"control.DetachBpfHooks",
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
	setRunSignalProgress = func(code byte, content string) error {
		return writeSignalProgressFile(progressPath, code, content)
	}
	t.Cleanup(func() {
		setRunSignalProgress = oldWriter
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
	setRunSignalProgress = func(code byte, content string) error {
		return writeSignalProgressFile(progressPath, code, content)
	}
	t.Cleanup(func() {
		setRunSignalProgress = oldWriter
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
	setRunSignalProgress = func(code byte, content string) error {
		return writeSignalProgressFile(progressPath, code, content)
	}
	t.Cleanup(func() {
		setRunSignalProgress = oldWriter
	})

	if err := writeSignalProgressFile(progressPath, consts.ReloadBusy, reloadBusyRetiringMessage); err != nil {
		t.Fatalf("writeSignalProgressFile() error = %v", err)
	}

	var reloadPending atomic.Bool
	reloadPending.Store(true)
	retirementDone := make(chan struct{})

	releaseReloadPendingAfterRetirement(&reloadPending, retirementDone)
	if !reloadPending.Load() {
		t.Fatal("expected reloadPending to remain set before retirement completes")
	}
	close(retirementDone)
	time.Sleep(10 * time.Millisecond)
	if reloadPending.Load() {
		t.Fatal("expected reloadPending to clear after retirement completes")
	}

	code, content, err := readSignalProgressFile(progressPath)
	if err != nil {
		t.Fatalf("readSignalProgressFile() error = %v", err)
	}
	if code != consts.ReloadDone {
		t.Fatalf("code = %q, want ReloadDone", code)
	}
	if content != "" {
		t.Fatalf("content = %q, want empty after retirement completes", content)
	}
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
