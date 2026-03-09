/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net"
	"testing"
	"time"
)

func TestUdpIngressBatchReader_ReadsLoopbackPackets(t *testing.T) {
	recv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer recv.Close()

	send, err := net.DialUDP("udp4", nil, recv.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial udp: %v", err)
	}
	defer send.Close()

	reader := newUdpIngressBatchReader(recv, 4)
	defer reader.Close()

	payloads := []string{"first-packet", "second-packet"}
	for _, payload := range payloads {
		if _, err := send.Write([]byte(payload)); err != nil {
			t.Fatalf("send payload %q: %v", payload, err)
		}
	}

	if err := recv.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}

	seen := make(map[string]int)
	for len(seen) < len(payloads) {
		n, err := reader.ReadBatch()
		if err != nil {
			t.Fatalf("read batch: %v", err)
		}
		for i := 0; i < n; i++ {
			pktBuf, src, oob, ok := reader.Take(i)
			if !ok {
				continue
			}
			seen[string(pktBuf)]++
			if !src.IsValid() {
				pktBuf.Put()
				t.Fatal("expected valid source address")
			}
			if len(oob) != 0 {
				pktBuf.Put()
				t.Fatalf("expected empty OOB on plain loopback UDP, got %d bytes", len(oob))
			}
			pktBuf.Put()
		}
	}

	for _, payload := range payloads {
		if seen[payload] != 1 {
			t.Fatalf("expected payload %q exactly once, got %d", payload, seen[payload])
		}
	}
}