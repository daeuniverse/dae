package control

import (
	"io"
	"testing"
)

func TestApplyUpstreamReadErrorPolicySkipsShortBuffer(t *testing.T) {
	ue := &UdpEndpoint{}
	retired := false
	if ue.applyUpstreamReadErrorPolicy(io.ErrShortBuffer, func() { retired = true }) {
		t.Fatal("io.ErrShortBuffer should skip, not terminate the UDP read loop")
	}
	if retired {
		t.Fatal("endpoint retired on a skippable short-buffer datagram")
	}
}
