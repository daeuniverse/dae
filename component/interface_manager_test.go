/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package component

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func newTestInterfaceManager() *InterfaceManager {
	closed, closeFunc := context.WithCancel(context.Background())
	log := logrus.New()
	log.SetOutput(testingWriter{})
	return &InterfaceManager{
		log:        log,
		callbacks:  make([]callbackSet, 0),
		closed:     closed,
		close:      closeFunc,
		upLinks:    make(map[string]bool),
		operStates: make(map[string]netlink.LinkOperState),
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

// TestInterfaceManagerRebindsOnOperStateUpTransition verifies that the binding
// callback is retriggered when a known link flaps down and comes back up. The
// kernel removes the ingress qdisc and TC filters on link down, so without
// this re-bind the dataplane would silently lose traffic steering after a flap.
func TestInterfaceManagerRebindsOnOperStateUpTransition(t *testing.T) {
	mgr := newTestInterfaceManager()

	var total atomic.Int32
	calls := make(chan string, 8)
	go func() {
		for range calls {
			total.Add(1)
		}
	}()

	mgr.callbacks = append(mgr.callbacks, callbackSet{
		pattern: "*",
		newCallback: func(link netlink.Link) {
			calls <- link.Attrs().Name
		},
	})

	ch := make(chan netlink.LinkUpdate)
	done := make(chan struct{})
	go mgr.monitor(ch, done)
	defer func() { _ = mgr.Close() }()

	const ifName = "eth0"
	// The monitor debounces callbacks by 200ms; wait for the margin to elapse
	// so any pending callback has been dispatched before we assert.
	settle := func() { time.Sleep(300 * time.Millisecond) }
	send := func(state netlink.LinkOperState) {
		ch <- netlink.LinkUpdate{
			Header: unix.NlMsghdr{Type: unix.RTM_NEWLINK},
			Link:   &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: ifName, OperState: state}},
		}
	}

	// 1. First appearance (OperUp) must bind.
	send(netlink.OperUp)
	settle()
	if v := total.Load(); v != 1 {
		t.Fatalf("after first appearance: got %d bind callback(s), want 1", v)
	}

	// 2. A repeated OperUp (no state change) must NOT re-bind.
	send(netlink.OperUp)
	settle()
	if v := total.Load(); v != 1 {
		t.Fatalf("after repeated OperUp: got %d bind callback(s), want 1 (no extra rebind)", v)
	}

	// 3. Going down (OperDown) must NOT re-bind.
	send(netlink.OperDown)
	settle()
	if v := total.Load(); v != 1 {
		t.Fatalf("after OperDown: got %d bind callback(s), want 1 (no rebind on down)", v)
	}

	// 4. Coming back up (OperDown -> OperUp) MUST re-bind.
	send(netlink.OperUp)
	settle()
	if v := total.Load(); v != 2 {
		t.Fatalf("after flap back to OperUp: got %d bind callback(s), want 2 (rebind on up transition)", v)
	}
}
