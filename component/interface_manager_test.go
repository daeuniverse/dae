/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package component

import (
	"context"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

func newTestInterfaceManager() *InterfaceManager {
	closed, closeFunc := context.WithCancel(context.Background())
	log := logrus.New()
	log.SetOutput(testingWriter{})
	return &InterfaceManager{
		log:       log,
		callbacks: make([]callbackSet, 0),
		closed:    closed,
		close:     closeFunc,
		upLinks:   make(map[string]bool),
	}
}

type testingWriter struct{}

func (testingWriter) Write(p []byte) (int, error) {
	return len(p), nil
}

func TestInterfaceManagerMonitorStopsOnClosedUpdateChannel(t *testing.T) {
	mgr := newTestInterfaceManager()
	ch := make(chan netlink.LinkUpdate)
	done := make(chan struct{})
	close(ch)

	go mgr.monitor(ch, done)

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("monitor did not stop after link update channel closed")
	}
}

func TestInterfaceManagerEnqueueJobWaitsWhenFull(t *testing.T) {
	mgr := newTestInterfaceManager()
	jobChan := make(chan job, 1)
	jobChan <- job{ifName: "eth0", fn: func() {}}

	returned := make(chan struct{})
	go func() {
		defer close(returned)
		mgr.enqueueJob(jobChan, job{ifName: "eth0", fn: func() {}})
	}()

	select {
	case <-returned:
		t.Fatal("enqueueJob returned while the queue was full")
	case <-time.After(50 * time.Millisecond):
	}

	<-jobChan
	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("enqueueJob did not return after queue space became available")
	}
}

func TestInterfaceManagerEnqueueJobReturnsWhenClosed(t *testing.T) {
	mgr := newTestInterfaceManager()
	jobChan := make(chan job, 1)
	jobChan <- job{ifName: "eth0", fn: func() {}}

	returned := make(chan struct{})
	go func() {
		defer close(returned)
		mgr.enqueueJob(jobChan, job{ifName: "eth0", fn: func() {}})
	}()

	mgr.close()

	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("enqueueJob did not return after manager closed")
	}
}

func TestTryEnqueueInterfaceCallbackEnqueuesWhenQueueHasCapacity(t *testing.T) {
	ifQ := make(chan func(), 1)

	if ok := tryEnqueueInterfaceCallback(context.Background(), ifQ, func() {}); !ok {
		t.Fatal("tryEnqueueInterfaceCallback() = false, want true with available queue capacity")
	}
	if len(ifQ) != 1 {
		t.Fatalf("queue length = %d, want 1", len(ifQ))
	}
}

func TestTryEnqueueInterfaceCallbackDropsWhenQueueFull(t *testing.T) {
	ifQ := make(chan func(), 1)
	ifQ <- func() {}

	returned := make(chan struct{})
	go func() {
		defer close(returned)
		if ok := tryEnqueueInterfaceCallback(context.Background(), ifQ, func() {}); ok {
			t.Error("tryEnqueueInterfaceCallback() = true, want false when queue is full")
		}
	}()

	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("tryEnqueueInterfaceCallback blocked on a full queue")
	}
}
