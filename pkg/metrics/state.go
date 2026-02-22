/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package metrics

import (
	"sync/atomic"

	"github.com/daeuniverse/dae/control"
)

// State keeps a pointer to the current control plane for collectors.
// During reload this pointer is atomically swapped to the new instance.
type State struct {
	cp atomic.Pointer[control.ControlPlane]
}

func NewState() *State {
	return &State{}
}

func (s *State) SetControlPlane(cp *control.ControlPlane) {
	s.cp.Store(cp)
}

func (s *State) GetControlPlane() *control.ControlPlane {
	return s.cp.Load()
}
