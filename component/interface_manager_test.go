/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package component

import (
	"context"
	"sync"
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

func testLinkUpdate(msgType uint16, ifName string) netlink.LinkUpdate {
	update := netlink.LinkUpdate{}
	update.Header.Type = msgType
	update.Link = &netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: ifName}}
	return update
}

func TestInterfaceManagerMonitorStopsOnClosedUpdateChannel(t *testing.T) {
	mgr := newTestInterfaceManager()
	ch := make(chan netlink.LinkUpdate)
	done := make(chan struct{})
	close(ch)

	go mgr.monitor(ch, done, true)

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("monitor did not stop after link update channel closed")
	}
}

// An interface can match more than one registration, for example when it is
// named by both lan_interface and wan_interface. Every matching callback has to
// run: dropping one silently leaves that side of the datapath unattached, and
// upLinks then suppresses any later retry for the same interface.
func TestInterfaceManagerRunsEveryMatchingCallback(t *testing.T) {
	mgr := newTestInterfaceManager()
	t.Cleanup(mgr.close)

	var mu sync.Mutex
	var ran []string
	record := func(name string) func(netlink.Link) {
		return func(netlink.Link) {
			mu.Lock()
			ran = append(ran, name)
			mu.Unlock()
		}
	}
	mgr.callbacks = []callbackSet{
		{pattern: "eth0", newCallback: record("lan")},
		{pattern: "eth*", newCallback: record("wan")},
		{pattern: "wg0", newCallback: record("unrelated")},
	}

	ch := make(chan netlink.LinkUpdate)
	done := make(chan struct{})
	go mgr.monitor(ch, done, true)

	ch <- testLinkUpdate(unix.RTM_NEWLINK, "eth0")

	deadline := time.After(2 * time.Second)
	for {
		mu.Lock()
		got := len(ran)
		mu.Unlock()
		if got == 2 {
			break
		}
		select {
		case <-deadline:
			mu.Lock()
			defer mu.Unlock()
			t.Fatalf("callbacks run = %v, want both lan and wan", ran)
		case <-time.After(5 * time.Millisecond):
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if ran[0] != "lan" || ran[1] != "wan" {
		t.Fatalf("callbacks run = %v, want [lan wan] in registration order", ran)
	}
}

// upLinks is the single source of truth for a link's up/down state, so a
// repeated RTM_DELLINK for an interface that is already down must not run the
// delete callbacks a second time.
func TestInterfaceManagerIgnoresRepeatedDelLink(t *testing.T) {
	mgr := newTestInterfaceManager()
	t.Cleanup(mgr.close)

	deleted := make(chan struct{}, 4)
	mgr.callbacks = []callbackSet{{
		pattern:     "eth0",
		delCallback: func(netlink.Link) { deleted <- struct{}{} },
	}}
	mgr.upLinks["eth0"] = true

	ch := make(chan netlink.LinkUpdate)
	done := make(chan struct{})
	go mgr.monitor(ch, done, true)

	ch <- testLinkUpdate(unix.RTM_DELLINK, "eth0")
	ch <- testLinkUpdate(unix.RTM_DELLINK, "eth0")

	select {
	case <-deleted:
	case <-time.After(2 * time.Second):
		t.Fatal("delete callback did not run for the first RTM_DELLINK")
	}
	select {
	case <-deleted:
		t.Fatal("delete callback ran again for an interface that was already down")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestInterfaceManagerEnqueueCallbacksWaitsWhenFull(t *testing.T) {
	mgr := newTestInterfaceManager()
	jobChan := make(chan func(), 1)
	jobChan <- func() {}

	returned := make(chan struct{})
	go func() {
		defer close(returned)
		mgr.enqueueCallbacks(jobChan, nil, []func(netlink.Link){func(netlink.Link) {}})
	}()

	select {
	case <-returned:
		t.Fatal("enqueueCallbacks returned while the queue was full")
	case <-time.After(50 * time.Millisecond):
	}

	<-jobChan
	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("enqueueCallbacks did not return after queue space became available")
	}
}

func TestInterfaceManagerEnqueueCallbacksReturnsWhenClosed(t *testing.T) {
	mgr := newTestInterfaceManager()
	jobChan := make(chan func(), 1)
	jobChan <- func() {}

	returned := make(chan struct{})
	go func() {
		defer close(returned)
		mgr.enqueueCallbacks(jobChan, nil, []func(netlink.Link){func(netlink.Link) {}})
	}()

	mgr.close()

	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("enqueueCallbacks did not return after manager closed")
	}
}
