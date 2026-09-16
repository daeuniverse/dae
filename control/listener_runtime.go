/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"os"
	"sync"
)

// controlPlaneListenerRuntime groups listener socket publishing state used to
// hand listener file descriptors across reload generations.
type controlPlaneListenerRuntime struct {
	listenerPublishMu sync.Mutex
	listenerFiles     []*os.File
}
