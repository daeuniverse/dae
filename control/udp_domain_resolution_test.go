package control

import (
	"errors"
	"fmt"
	"testing"

	"github.com/daeuniverse/outbound/protocol"
)

// TestApplyUpstreamReadErrorPolicySkipsUnresolvedDatagram pins that a datagram
// whose peer-supplied source address could not be resolved does not retire the
// endpoint. Under full-cone NAT one endpoint carries every destination of the
// client, so retiring it because a single source address did not resolve would
// break all of them.
func TestApplyUpstreamReadErrorPolicySkipsUnresolvedDatagram(t *testing.T) {
	ue := &UdpEndpoint{}
	retired := false
	// Transports wrap the sentinel (juicity prefixes "ReadFrom AddrPort:"), so
	// the policy has to match through the wrapping.
	err := fmt.Errorf("ReadFrom AddrPort: %w",
		fmt.Errorf("%w: unresolvable.invalid: %w", protocol.ErrDomainResolution, errors.New("no answer")))
	if ue.applyUpstreamReadErrorPolicy(err, func() { retired = true }) {
		t.Fatal("an unresolved datagram source should skip, not terminate the UDP read loop")
	}
	if retired {
		t.Fatal("endpoint retired because one datagram's source address did not resolve")
	}
}

// TestApplyUpstreamReadErrorPolicyStillRetiresUnknownErrors is the counterweight:
// the new soft class must not have widened into "read errors no longer retire".
func TestApplyUpstreamReadErrorPolicyStillRetiresUnknownErrors(t *testing.T) {
	ue := &UdpEndpoint{}
	retired := false
	if !ue.applyUpstreamReadErrorPolicy(errors.New("unexpected transport failure"), func() { retired = true }) {
		t.Fatal("an unknown read error should still terminate the UDP read loop")
	}
	if !retired {
		t.Fatal("endpoint was not retired on an unknown read error")
	}
}
