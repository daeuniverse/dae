/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/control"
)

// newTestRuntimeGeneration returns a minimal runtimeGeneration for runtime
// supervisor tests. Recovered from the pruned runtime_supervisor_test.go
// (Sprint 5 T1).
func newTestRuntimeGeneration() *runtimeGeneration {
	return &runtimeGeneration{
		controlPlane: &control.ControlPlane{},
		listener:     &control.Listener{},
		cancel:       func() {},
		conf:         &config.Config{},
	}
}
