package control

import (
	"context"
	"net/netip"
	"testing"

	"github.com/daeuniverse/dae/component/routing"
)

// TestRetainedUDPEndpointEpochGate verifies the per-source epoch tally lets
// retainedUDPEndpoint skip its O(flows) scan when the current epoch owns
// every flow (the steady state between reloads), while stale-epoch flows are
// still found after the snapshot is rebuilt.
func TestRetainedUDPEndpointEpochGate(t *testing.T) {
	m := NewSessionManager(context.Background())
	defer func() { _ = m.Close() }()

	src := netip.MustParseAddrPort("10.0.0.1:4444")
	dst := netip.MustParseAddrPort("8.8.8.8:53")
	currentEpoch := routing.PolicyEpoch(11)
	staleEpoch := routing.PolicyEpoch(7)

	newFlow := func(epoch routing.PolicyEpoch, keyDst netip.AddrPort) *UDPFlowRuntime {
		ue := &UdpEndpoint{}
		ue.poolKey = UdpEndpointKey{Src: src, Dst: keyDst}
		return &UDPFlowRuntime{
			manager:  m,
			endpoint: ue,
			binding:  UdpFlowBinding{Route: UdpRouteBinding{PolicyEpoch: epoch}},
		}
	}

	// Two flows under the current epoch: the gate must answer without a
	// candidate and keep doing so as flows come and go.
	m.generationsMu.Lock()
	m.appendUDPFlowSourceLocked(src, newFlow(currentEpoch, dst))
	m.appendUDPFlowSourceLocked(src, newFlow(currentEpoch, netip.AddrPort{}))
	m.generationsMu.Unlock()
	if _, ok := m.retainedUDPEndpoint(src, dst, &bpfRoutingResult{}, currentEpoch); ok {
		t.Fatalf("retainedUDPEndpoint found a candidate while every flow is current-epoch")
	}

	// A reload adopts a stale-epoch flow for the same source: the gate must
	// open and the scan must return its endpoint.
	stale := newFlow(staleEpoch, dst)
	m.generationsMu.Lock()
	m.appendUDPFlowSourceLocked(src, stale)
	m.generationsMu.Unlock()
	ue, ok := m.retainedUDPEndpoint(src, dst, &bpfRoutingResult{}, currentEpoch)
	if !ok || ue != stale.endpoint {
		t.Fatalf("retainedUDPEndpoint = (%p, %v), want the stale-epoch endpoint %p", ue, ok, stale.endpoint)
	}

	// Once the stale flow retires, the rebuilt snapshot closes the gate again.
	m.generationsMu.Lock()
	m.removeUDPFlowSourceLocked(src, stale)
	m.generationsMu.Unlock()
	if _, ok := m.retainedUDPEndpoint(src, dst, &bpfRoutingResult{}, currentEpoch); ok {
		t.Fatalf("retainedUDPEndpoint found a candidate after the stale flow retired")
	}
}
