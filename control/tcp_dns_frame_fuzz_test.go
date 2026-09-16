/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"bufio"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// FuzzReadDnsMsgFromBufio drives the TCP DNS fast-path frame parser with
// hostile frames. It mirrors both slicing contexts that occur in production:
//
//   - probe frames: payload is a bufio.Peek sub-slice with surplus capacity;
//   - large frames (consumeLarge): payload is an exact-sized make([]byte, n),
//     so a zero-length sub-slice at the message end has zero capacity. That is
//     the only context where a downstream `b[2:]` can panic with
//     "slice bounds out of range [2:0]".
//
// A successful Unpack is additionally round-tripped through Pack, matching
// what tcpDnsResponseWriter.WriteMsg does with parsed messages.
func FuzzReadDnsMsgFromBufio(f *testing.F) {
	// Seed 1: minimal well-formed query header (12 bytes).
	f.Add([]byte{
		0x4a, 0x2b, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	})
	// Seed 2: query with a root question and an OPT RR (EDNS) with options.
	f.Add([]byte{
		0x4a, 0x2b, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x00,       // root name
		0x00, 0x01, // A
		0x00, 0x01, // IN
		0x00,                   // root name (OPT)
		0x00, 0x29, 0x10, 0x00, // OPT, class 4096
		0x00, 0x00, 0x00, 0x00, // TTL
		0x00, 0x00, // rdlength 0
	})
	// Seed 3: truncated garbage.
	f.Add([]byte{0xff, 0x00})
	// Seed 4: response-shaped header.
	f.Add([]byte{
		0x4a, 0x2b, 0x81, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	})

	f.Fuzz(func(t *testing.T, payload []byte) {
		if len(payload) > 65535 {
			return
		}
		frame := make([]byte, 2+len(payload))
		binary.BigEndian.PutUint16(frame, uint16(len(payload)))
		copy(frame[2:], payload)

		for _, consumeLarge := range []bool{false, true} {
			serverConn, clientConn := net.Pipe()
			writeDone := make(chan struct{})
			go func() {
				defer close(writeDone)
				_, _ = clientConn.Write(frame)
				_ = clientConn.Close()
			}()

			reader := bufio.NewReader(serverConn)
			msg, _, err := readDnsMsgFromBufio(reader, 250*time.Millisecond, serverConn, consumeLarge)
			if err == nil && msg != nil {
				// Mirror tcpDnsResponseWriter.WriteMsg: repack the
				// parsed message.
				if _, err := msg.Pack(); err != nil {
					t.Logf("Pack() error = %v", err)
				}
			}
			_ = serverConn.Close()
			select {
			case <-writeDone:
			case <-time.After(5 * time.Second):
				t.Fatalf("frame writer hung (consumeLarge=%v)", consumeLarge)
			}
		}
	})
}
