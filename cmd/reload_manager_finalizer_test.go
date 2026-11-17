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

// The finaliser of one reload must complete that reload before the busy flags
// drop. Once reloadPending is released the next request can begin and replace
// the current operation, and a late finaliser would complete the wrong one.
func TestReloadFinalisersCompleteOperationBeforeReleasingFlags(t *testing.T) {
	for name, finish := range map[string]func(*reloadManager){
		"success":        func(m *reloadManager) { m.finishReloadSuccess() },
		"failure":        func(m *reloadManager) { m.finishReloadFailure() },
		"failed attempt": func(m *reloadManager) { m.failReloadAttempt(errors.New("boom")) },
	} {
		t.Run(name, func(t *testing.T) {
			m := newReloadManager(make(chan reloadRequest, 1), make(chan struct{}, 1), make(chan os.Signal, 1))
			m.setRuntimeStatus(newRuntimeStatus())
			var pendingAtCompletion, notified bool
			m.setReloadObserver(func(_ string, started, _ bool, _ error) {
				if started {
					return
				}
				notified = true
				pendingAtCompletion = m.reloadPending.Load()
			})
			m.reloadPending.Store(true)
			m.beginRuntimeReload(reloadRequest{apiOperationID: "op-1"})
			finish(m)

			if !notified {
				t.Fatal("operation was not completed")
			}
			if !pendingAtCompletion {
				t.Fatal("reloadPending was released before the operation completed")
			}
			if m.reloadPending.Load() {
				t.Fatal("reloadPending still set after the finaliser")
			}
		})
	}
}
