/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"fmt"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"
)

// freeLoopbackPort reserves a loopback port and releases it, so a test can
// bind that port explicitly right after.
func freeLoopbackPort(t *testing.T) uint16 {
	t.Helper()
	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Skipf("loopback listen unavailable: %v", err)
	}
	port := uint16(l.Addr().(*net.TCPAddr).Port)
	if err := l.Close(); err != nil {
		t.Fatalf("release probe listener: %v", err)
	}
	return port
}

func pprofURL(port uint16) string {
	return "http://localhost:" + strconv.Itoa(int(port)) + "/debug/pprof/"
}

// TestPprofServerStartsAndStops pins the contract the reload path depends on:
// the listener exists as soon as startPprofServer returns, and stopPprofServer
// releases both the server slot and the port.
func TestPprofServerStartsAndStops(t *testing.T) {
	port := freeLoopbackPort(t)

	server, err := startPprofServer(port)
	if err != nil {
		t.Fatalf("startPprofServer: %v", err)
	}
	resp, err := http.Get(pprofURL(port))
	if err != nil {
		t.Fatalf("pprof not reachable right after start: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("pprof status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	_ = resp.Body.Close()

	stopPprofServer(&server)
	if server != nil {
		t.Fatal("stopPprofServer left a non-nil server in the slot")
	}

	// The port must be free again, otherwise a reload to the same port would
	// fail with a bind error the next time around.
	reclaim, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", port))
	if err != nil {
		t.Fatalf("port %d still bound after stopPprofServer: %v", port, err)
	}
	_ = reclaim.Close()
}

// TestPprofServerReportsBindFailure covers the defect that made a reloaded
// pprof_port silently unreachable: the bind error used to be dropped inside a
// bare goroutine.
func TestPprofServerReportsBindFailure(t *testing.T) {
	port := freeLoopbackPort(t)
	holder, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", port))
	if err != nil {
		t.Skipf("could not hold port %d: %v", port, err)
	}
	defer func() { _ = holder.Close() }()

	server, err := startPprofServer(port)
	if err == nil {
		stopPprofServer(&server)
		t.Fatal("startPprofServer succeeded on an occupied port")
	}
	if server != nil {
		t.Fatal("startPprofServer returned a server alongside an error")
	}
}

// TestRefreshPprofServer covers the reload entry point: it starts a listener
// for a non-zero port and shuts it down again when the port becomes zero.
func TestRefreshPprofServer(t *testing.T) {
	port := freeLoopbackPort(t)
	m := &reloadManager{}
	var slot *http.Server

	if err := m.refreshPprofServer(&slot, port); err != nil {
		t.Fatalf("refreshPprofServer(%d): %v", port, err)
	}
	if slot == nil {
		t.Fatal("refreshPprofServer did not record a server")
	}
	// Give Serve a moment to accept before probing.
	deadline := time.Now().Add(2 * time.Second)
	for {
		if resp, err := http.Get(pprofURL(port)); err == nil {
			_ = resp.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("pprof did not become reachable after refresh")
		}
		time.Sleep(10 * time.Millisecond)
	}

	if err := m.refreshPprofServer(&slot, 0); err != nil {
		t.Fatalf("refreshPprofServer(0): %v", err)
	}
	if slot != nil {
		t.Fatal("refreshPprofServer(0) did not clear the slot")
	}
}
