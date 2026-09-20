//go:build linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// A server-first greeting and subsequent short replies must arrive while the
// connection remains open, without waiting for another write or TCP's cork timer.
func TestSplicePipeToSocketFlushesShortWrites(t *testing.T) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	client, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	server, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Close() }()
	raw, err := server.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	pipe, err := newRelaySplicePipe()
	if err != nil {
		t.Fatal(err)
	}
	defer pipe.close()
	for _, payload := range [][]byte{[]byte("greeting"), []byte("reply one"), []byte("reply two")} {
		if n, err := unix.Write(pipe.writeFD, payload); err != nil || n != len(payload) {
			t.Fatalf("pipe write: n=%d err=%v", n, err)
		}
		if err := client.SetReadDeadline(time.Now().Add(150 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		if n, err := splicePipeToSocket(raw, pipe.readFD, len(payload)); err != nil || n != len(payload) {
			t.Fatalf("splice: n=%d err=%v", n, err)
		}
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(client, got); err != nil {
			t.Fatalf("short write was not flushed before the cork timer: %v", err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("received %q, want %q", got, payload)
		}
	}
}
