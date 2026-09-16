/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

// controlPlaneUDPRuntime groups the UDP data-plane subsystems owned by a
// ControlPlane generation: endpoint admission, ingress admission, the
// direct-dispatch bound, and the QUIC DCID negative cache.
type controlPlaneUDPRuntime struct {
	udpEndpointAdmission udpEndpointAdmissionGate
	udpIngressAdmission  routingEpochIngressGate
	// udpDirectDispatchSem bounds the goroutines spawned by the
	// direct-dispatch strategy (DNS/SIP/RTP/STUN), which bypasses the bounded
	// per-flow queue to keep latency low. Without a cap, a UDP flood aimed at
	// any exception port converts directly into unbounded goroutine and
	// buffer growth. The bound is deliberately generous so legitimate
	// low-latency traffic is never clipped; on saturation the packet is
	// dropped like ordinary UDP loss and the client retransmits.
	udpDirectDispatchSem chan struct{}
	failedQuicDcidCache  *failedQuicDcidCache
}
