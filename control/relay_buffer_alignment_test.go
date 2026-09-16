package control

import "testing"

// TestRelayBufferAlignmentWithAnytlsFrame locks the cross-repo buffer
// contract: the relay read buffer must be an integer multiple of the anytls
// frame payload size of the pinned outbound fork (32768 at the time of
// writing). The literal mirrors the fork's maxFramePayloadSize on purpose —
// when the pin advances past a frame-size change, update this constant and
// relayCopyBufferSize together, or every 32 KiB read splits into a full
// frame plus a one-byte tail frame.
func TestRelayBufferAlignmentWithAnytlsFrame(t *testing.T) {
	const anytlsMaxFramePayloadSize = 32768
	if relayCopyBufferSize%anytlsMaxFramePayloadSize != 0 {
		t.Fatalf("relayCopyBufferSize=%d is not a multiple of the anytls frame payload size %d; reads would split into a full frame plus a tail frame",
			relayCopyBufferSize, anytlsMaxFramePayloadSize)
	}
}
