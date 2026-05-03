/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"testing"
	"time"
)

const (
	udpReplySLOHandlerDelay = 1 * time.Millisecond
	udpReplySLOProducerGap  = 100 * time.Microsecond

	// Moderate burst: must fit within the current hy2 receive queue plus dae's
	// bounded reply buffer without any loss at either boundary.
	udpReplySLOModerateBurstPackets = 1800

	// Prebuffered burst: overflow is deterministic because dae is not allowed to
	// drain until after all packets have already been queued into hy2.
	udpReplySLOPrebufferedBurstPackets = 2400

	// Sustained overload: exceeds the combined current hy2 queue budget and dae
	// reply buffer budget even after some draining during the burst.
	udpReplySLOSustainedOverloadPackets = 3200
)

// SLO: With the current hy2 receive queue depth, dae must absorb a moderate
// burst without dropping inside dae or pushing loss back to hy2.
func TestUdpReplyPathSLO_ModerateBurstAbsorbsWithoutLoss(t *testing.T) {
	result := runHy2BoundarySimulationWithQueueSize(
		t,
		hy2BoundaryModeBackpressure,
		udpReplySLOModerateBurstPackets,
		udpReplySLOProducerGap,
		udpReplySLOHandlerDelay,
		false,
		hy2CurrentReceiveQueueSize,
	)

	logHy2BoundarySimulationResult(t, result)

	if result.hy2Dropped != 0 {
		t.Fatalf("moderate burst hy2_dropped=%d, want 0", result.hy2Dropped)
	}
	if result.daeDropped != 0 {
		t.Fatalf("moderate burst dae_dropped=%d, want 0", result.daeDropped)
	}
	if result.handled != udpReplySLOModerateBurstPackets {
		t.Fatalf("moderate burst handled=%d, want %d", result.handled, udpReplySLOModerateBurstPackets)
	}
}

// SLO: If dae gets no CPU before the burst arrives, any loss must be fully
// attributable to the hy2 receive queue boundary; dae itself must not add
// a second layer of reply drops.
func TestUdpReplyPathSLO_PrebufferedOverflowIsAttributedToHy2Boundary(t *testing.T) {
	result := runHy2BoundarySimulationWithQueueSize(
		t,
		hy2BoundaryModeBackpressure,
		udpReplySLOPrebufferedBurstPackets,
		0,
		udpReplySLOHandlerDelay,
		true,
		hy2CurrentReceiveQueueSize,
	)

	logHy2BoundarySimulationResult(t, result)

	expectedHy2Dropped := udpReplySLOPrebufferedBurstPackets - hy2CurrentReceiveQueueSize
	if expectedHy2Dropped < 0 {
		expectedHy2Dropped = 0
	}
	if result.hy2Dropped != expectedHy2Dropped {
		t.Fatalf("prebuffered burst hy2_dropped=%d, want %d", result.hy2Dropped, expectedHy2Dropped)
	}
	if result.daeDropped != 0 {
		t.Fatalf("prebuffered burst dae_dropped=%d, want 0", result.daeDropped)
	}
	if result.handled != udpReplySLOPrebufferedBurstPackets-result.hy2Dropped {
		t.Fatalf(
			"prebuffered burst handled=%d, want %d",
			result.handled,
			udpReplySLOPrebufferedBurstPackets-result.hy2Dropped,
		)
	}
}

// SLO: Under sustained overload, dae may backpressure the read loop and hy2
// may eventually drop when its queue fills, but dae itself must still avoid
// introducing reply-path drops.
func TestUdpReplyPathSLO_SustainedOverloadDoesNotDropInsideDae(t *testing.T) {
	result := runHy2BoundarySimulationWithQueueSize(
		t,
		hy2BoundaryModeBackpressure,
		udpReplySLOSustainedOverloadPackets,
		udpReplySLOProducerGap,
		udpReplySLOHandlerDelay,
		false,
		hy2CurrentReceiveQueueSize,
	)

	logHy2BoundarySimulationResult(t, result)

	if result.hy2Dropped == 0 {
		t.Fatalf("sustained overload hy2_dropped=%d, want > 0", result.hy2Dropped)
	}
	if result.daeDropped != 0 {
		t.Fatalf("sustained overload dae_dropped=%d, want 0", result.daeDropped)
	}
	if result.handled != udpReplySLOSustainedOverloadPackets-result.hy2Dropped {
		t.Fatalf(
			"sustained overload handled=%d, want %d",
			result.handled,
			udpReplySLOSustainedOverloadPackets-result.hy2Dropped,
		)
	}
}
