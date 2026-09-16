/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	stderrors "errors"
	"runtime"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

func newDaeNetnsWithCurrentHandles(t *testing.T) *DaeNetns {
	t.Helper()
	hostNs, err := netns.Get()
	if err != nil {
		t.Fatalf("get host netns: %v", err)
	}
	daeNs, err := netns.Get()
	if err != nil {
		_ = hostNs.Close()
		t.Fatalf("get dae netns: %v", err)
	}
	ns := &DaeNetns{
		hostNs:             hostNs,
		daeNs:              daeNs,
		handlesInitialized: true,
	}
	ns.setupDone.Store(true)
	t.Cleanup(func() {
		if ns.hostNs.IsOpen() {
			_ = ns.hostNs.Close()
		}
		if ns.daeNs.IsOpen() {
			_ = ns.daeNs.Close()
		}
	})
	return ns
}

func TestDaeNetnsWithReportsCallbackAndRestoreFailures(t *testing.T) {
	previousSetNetns := setNetnsFunc
	t.Cleanup(func() { setNetnsFunc = previousSetNetns })

	ns := newDaeNetnsWithCurrentHandles(t)

	callbackErr := stderrors.New("callback failed")
	restoreErr := stderrors.New("restore failed")
	var calls int
	var targets []netns.NsHandle
	setNetnsFunc = func(target netns.NsHandle) error {
		calls++
		targets = append(targets, target)
		if calls == 2 {
			return restoreErr
		}
		return nil
	}

	err := ns.With(func() error { return callbackErr })
	if !stderrors.Is(err, callbackErr) || !stderrors.Is(err, restoreErr) {
		t.Fatalf("With() error = %v, want callback and restore failures", err)
	}
	if calls != 2 {
		t.Fatalf("netns switch calls = %d, want 2", calls)
	}
	if targets[0] == ns.daeNs || targets[1] == ns.hostNs {
		t.Fatalf("With() used original netns handles instead of snapshots: %v", targets)
	}
}

func TestDaeNetnsWithDoesNotRunCallbackAfterSwitchFailure(t *testing.T) {
	previousSetNetns := setNetnsFunc
	t.Cleanup(func() { setNetnsFunc = previousSetNetns })

	ns := newDaeNetnsWithCurrentHandles(t)
	wantErr := stderrors.New("switch failed")
	setNetnsFunc = func(netns.NsHandle) error { return wantErr }

	called := false
	err := ns.With(func() error {
		called = true
		return nil
	})
	if !stderrors.Is(err, wantErr) {
		t.Fatalf("With() error = %v, want %v", err, wantErr)
	}
	if called {
		t.Fatal("callback ran after netns switch failure")
	}
}

func TestDaeNetnsWithRestoresHostBeforePropagatingPanic(t *testing.T) {
	previousSetNetns := setNetnsFunc
	t.Cleanup(func() { setNetnsFunc = previousSetNetns })

	ns := newDaeNetnsWithCurrentHandles(t)
	var calls int
	setNetnsFunc = func(netns.NsHandle) error {
		calls++
		return nil
	}

	wantPanic := stderrors.New("callback panic")
	var gotPanic any
	func() {
		defer func() { gotPanic = recover() }()
		_ = ns.With(func() error { panic(wantPanic) })
	}()
	if gotPanic != wantPanic {
		t.Fatalf("With() panic = %v, want %v", gotPanic, wantPanic)
	}
	if calls != 2 {
		t.Fatalf("netns switch calls = %d, want 2", calls)
	}
}

func TestDaeNetnsWithRestoresHostWhenCallbackCallsGoexit(t *testing.T) {
	previousSetNetns := setNetnsFunc
	t.Cleanup(func() { setNetnsFunc = previousSetNetns })

	ns := newDaeNetnsWithCurrentHandles(t)
	var calls int
	setNetnsFunc = func(netns.NsHandle) error {
		calls++
		return nil
	}

	err := ns.With(func() error {
		runtime.Goexit()
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "exited without returning") {
		t.Fatalf("With() error = %v, want callback exit failure", err)
	}
	if calls != 2 {
		t.Fatalf("netns switch calls = %d, want 2", calls)
	}
}

func TestDaeNetnsWithUsesSnapshotsWhileOriginalHandlesClose(t *testing.T) {
	previousSetNetns := setNetnsFunc
	t.Cleanup(func() { setNetnsFunc = previousSetNetns })

	ns := newDaeNetnsWithCurrentHandles(t)
	var targets []netns.NsHandle
	setNetnsFunc = func(target netns.NsHandle) error {
		if _, err := unix.FcntlInt(uintptr(target), unix.F_GETFD, 0); err != nil {
			return err
		}
		targets = append(targets, target)
		return nil
	}

	callbackStarted := make(chan struct{})
	releaseCallback := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- ns.With(func() error {
			close(callbackStarted)
			<-releaseCallback
			return nil
		})
	}()
	<-callbackStarted

	ns.mu.Lock()
	if err := ns.daeNs.Close(); err != nil {
		ns.mu.Unlock()
		t.Fatalf("close original dae handle: %v", err)
	}
	if err := ns.hostNs.Close(); err != nil {
		ns.mu.Unlock()
		t.Fatalf("close original host handle: %v", err)
	}
	ns.daeNs = netns.None()
	ns.hostNs = netns.None()
	ns.handlesInitialized = false
	ns.setupDone.Store(false)
	ns.mu.Unlock()

	close(releaseCallback)
	if err := <-done; err != nil {
		t.Fatalf("With() error after original handles closed = %v", err)
	}
	if len(targets) != 2 {
		t.Fatalf("netns switch targets = %v, want dae and host snapshots", targets)
	}
	for _, target := range targets {
		if _, err := unix.FcntlInt(uintptr(target), unix.F_GETFD, 0); !stderrors.Is(err, unix.EBADF) {
			t.Fatalf("snapshot handle %d remains open after With(): %v", target, err)
		}
	}
}

func TestDaeNetnsSetupPublishesInitialSwitchFailure(t *testing.T) {
	previousSetNetns := setNetnsFunc
	t.Cleanup(func() { setNetnsFunc = previousSetNetns })

	wantErr := stderrors.New("initial host namespace switch failed")
	calls := 0
	setNetnsFunc = func(netns.NsHandle) error {
		calls++
		if calls == 1 {
			return wantErr
		}
		return nil
	}

	ns := &DaeNetns{log: logrus.New()}
	err := ns.setup()
	if !stderrors.Is(err, wantErr) {
		t.Fatalf("setup() error = %v, want %v", err, wantErr)
	}
	if calls != 2 {
		t.Fatalf("setup namespace switch calls = %d, want initial failure plus restore", calls)
	}
	if ns.hostNs.IsOpen() {
		_ = ns.hostNs.Close()
	}
}
