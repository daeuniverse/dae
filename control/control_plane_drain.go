/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import "sync"

var closedDrainIdleCh = func() <-chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}()

// controlPlaneDrainTracker tracks generation-owned sessions that should be
// allowed to drain during reload. It is intentionally coarse-grained:
// one ticket per accepted TCP connection or live UDP endpoint.
type controlPlaneDrainTracker struct {
	mu     sync.Mutex
	active int
	idleCh chan struct{}
}

func newControlPlaneDrainTracker() *controlPlaneDrainTracker {
	ch := make(chan struct{})
	close(ch)
	return &controlPlaneDrainTracker{idleCh: ch}
}

func (t *controlPlaneDrainTracker) Acquire() func() {
	if t == nil {
		return func() {}
	}

	t.mu.Lock()
	if t.active == 0 {
		t.idleCh = make(chan struct{})
	}
	t.active++
	t.mu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			t.mu.Lock()
			defer t.mu.Unlock()
			if t.active == 0 {
				return
			}
			t.active--
			if t.active == 0 {
				close(t.idleCh)
			}
		})
	}
}

func (t *controlPlaneDrainTracker) Count() int {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.active
}

func (t *controlPlaneDrainTracker) IdleCh() <-chan struct{} {
	if t == nil {
		return closedDrainIdleCh
	}
	t.mu.Lock()
	ch := t.idleCh
	t.mu.Unlock()
	return ch
}
