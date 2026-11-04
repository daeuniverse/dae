/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net/netip"
	"sync"
	"time"
)

// rejectFlowTTL bounds how long a flow stays in the reject set after its first
// ICMP injection. It must be at least as long as a QUIC connection's
// handshake/retry window so a single rejected flow does not keep re-triggering
// the userspace handoff within the same connection attempt.
const rejectFlowTTL = 30 * time.Second

// rejectFlows records (client, dst) pairs for which we have already injected an
// ICMP port-unreachable. Subsequent packets of the same flow are dropped in
// userspace without re-running the routing lookup or re-injecting ICMP, capping
// the control-plane cost of a hammered reject destination at O(flows) instead of
// O(packets). The data-plane SHOT marking that would let the kernel drop these
// packets without any handoff is tracked as a follow-up (see PR discussion).
//
// This state is platform-agnostic (no raw sockets), so it lives in a file
// without a build tag and is shared by both the Linux and non-Linux builds.
var rejectFlows sync.Map // string(client->dst) -> time.Time (injection time)

func rejectFlowKey(client, dst netip.AddrPort) string {
	return client.String() + "->" + dst.String()
}

// markRejectFlow records that an ICMP port-unreachable has been injected for
// this flow, so later packets of the same flow can be dropped cheaply.
func markRejectFlow(client, dst netip.AddrPort) {
	rejectFlows.Store(rejectFlowKey(client, dst), time.Now())
}

// isRejectFlow reports whether this flow has already been rejected within
// rejectFlowTTL. Expired entries are deleted lazily on access.
func isRejectFlow(client, dst netip.AddrPort) bool {
	if v, ok := rejectFlows.Load(rejectFlowKey(client, dst)); ok {
		if time.Since(v.(time.Time)) <= rejectFlowTTL {
			return true
		}
		rejectFlows.Delete(rejectFlowKey(client, dst))
	}
	return false
}

// rejectFlowSweeper periodically evicts stale entries from rejectFlows so the
// map does not grow without bound under sustained rejection pressure.
func rejectFlowSweeper() {
	ticker := time.NewTicker(rejectFlowTTL)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		rejectFlows.Range(func(k, v any) bool {
			if now.Sub(v.(time.Time)) > rejectFlowTTL {
				rejectFlows.Delete(k)
			}
			return true
		})
	}
}

func init() {
	go rejectFlowSweeper()
}
