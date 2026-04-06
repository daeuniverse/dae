package cmd

import (
	"errors"
	"io"
	"reflect"
	"testing"

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
