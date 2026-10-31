/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"errors"
	"os"
	"testing"
)

func TestReloadManagerRuntimeStatus(t *testing.T) {
	status := newRuntimeStatus()
	status.setState(runtimeStateRunning)
	manager := newReloadManager(make(chan reloadRequest, 1), make(chan struct{}, 1), make(chan os.Signal, 1))
	manager.setRuntimeStatus(status)

	manager.beginRuntimeReload(reloadRequest{isSuspend: true})
	if got := status.getState(); got != string(runtimeStateReloading) {
		t.Fatalf("state after begin suspend = %q", got)
	}
	manager.finishRuntimeReload(true)
	if got := status.getState(); got != string(runtimeStateSuspended) {
		t.Fatalf("state after suspend = %q", got)
	}
	snapshot := status.snapshot()
	if snapshot.LastReload == nil || snapshot.LastReload.Status != "succeeded" {
		t.Fatalf("last reload = %#v", snapshot.LastReload)
	}

	manager.beginRuntimeReload(reloadRequest{})
	manager.setReloadError(errors.New("boom"))
	manager.finishRuntimeReload(false)
	if got := status.getState(); got != string(runtimeStateSuspended) {
		t.Fatalf("failed resume should restore suspended, got %q", got)
	}
	snapshot = status.snapshot()
	if snapshot.LastReload == nil || snapshot.LastReload.Status != "failed" || snapshot.LastReload.Error == "" {
		t.Fatalf("failed last reload = %#v", snapshot.LastReload)
	}
}

func TestReloadManagerRuntimeStatusIgnoresUnstartedFinish(t *testing.T) {
	status := newRuntimeStatus()
	status.setState(runtimeStateRunning)
	manager := newReloadManager(make(chan reloadRequest, 1), make(chan struct{}, 1), make(chan os.Signal, 1))
	manager.setRuntimeStatus(status)

	manager.finishRuntimeReload(false)
	if got := status.getState(); got != string(runtimeStateRunning) {
		t.Fatalf("unstarted finish changed state to %q", got)
	}
	if status.snapshot().LastReload != nil {
		t.Fatal("unstarted finish must not record a reload")
	}
}
