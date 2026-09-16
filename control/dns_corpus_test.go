/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2laya.org>
 */

package control

import (
	"testing"
)

// TestPhase0DnsCorpus_LegacyBaseline runs the Phase 0 DNS corpus against the
// current DnsController implementation. Each fixture builds a fresh
// controller, installs its forwarder factory, and replays the cases.
//
// This test pins the legacy baseline. Future phases (DNS projection split,
// three-valued response routing, etc.) MUST keep these tests passing, since
// they encode user-visible behaviour the refactor cannot regress.
//
// See docs/en/semantic-architecture-refactor-plan.md Phase 0 acceptance
// clause 2: DNS UDP/TCP, stale cache, reject-before-cache, QUIC sniffing,
// full-cone and symmetric UDP flows, and reload-with-live-flows have replay
// coverage. The current corpus covers UDP cache-miss and reject-before-cache;
// the remaining sub-corpora are tracked in progress.md.
func TestPhase0DnsCorpus_LegacyBaseline(t *testing.T) {
	for _, fixture := range DnsCorpusFixtures() {
		t.Run(fixture.Name, func(t *testing.T) {
			ReplayDns(t, fixture)
		})
	}
}
