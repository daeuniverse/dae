/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

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
