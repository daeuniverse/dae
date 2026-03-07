package control

import "testing"

func TestTCPRelayPrefetchOffloadSkipReason_SkipsServerFirstFlow(t *testing.T) {
	if got := tcpRelayPrefetchOffloadSkipReason(true, false); got != "server-first/no-early-client-payload flow" {
		t.Fatalf("unexpected skip reason: %q", got)
	}
}

func TestTCPRelayPrefetchOffloadSkipReason_AllowsClientPayloadFlow(t *testing.T) {
	if got := tcpRelayPrefetchOffloadSkipReason(true, true); got != "" {
		t.Fatalf("expected no skip reason when client payload is ready, got %q", got)
	}
	if got := tcpRelayPrefetchOffloadSkipReason(false, false); got != "" {
		t.Fatalf("expected no skip reason when sniff prefetch was not attempted, got %q", got)
	}
}
