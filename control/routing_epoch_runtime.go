/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"sync"
	"sync/atomic"
)

// controlPlaneRoutingEpochRuntime groups the routing epoch peer linkage used by
// staged reload handoffs. Methods live in routing_epoch.go and
// routing_epoch_execution.go.
type controlPlaneRoutingEpochRuntime struct {
	routingEpochPeerMu    sync.RWMutex
	routingEpochPeer      *ControlPlane
	routingEpochSlot      atomic.Uint32
	routingEpochSlotKnown atomic.Bool
	// routingEpochExecutionClosed prevents a retiring generation from
	// accepting work delegated by its staged reload peer.
	routingEpochExecutionClosed atomic.Bool
}
