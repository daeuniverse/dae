package control

import "testing"

func TestTCPRelayPrefetchOffloadSkipReason_AllowsAllFlows(t *testing.T) {
	// Server-first flow restriction removed: eBPF offload is now allowed
	// regardless of client payload state.
	if got := tcpRelayPrefetchOffloadSkipReason(true, false); got != "" {
		t.Fatalf("expected no skip reason for server-first flow, got %q", got)
	}
	if got := tcpRelayPrefetchOffloadSkipReason(true, true); got != "" {
		t.Fatalf("expected no skip reason when client payload is ready, got %q", got)
	}
	if got := tcpRelayPrefetchOffloadSkipReason(false, false); got != "" {
		t.Fatalf("expected no skip reason when sniff prefetch was not attempted, got %q", got)
	}
}
