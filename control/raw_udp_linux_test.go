//go:build linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net"
	"net/netip"
	"os"
	"strconv"
	"testing"
	"time"
)

func TestSendUDPv6RawDirect(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("raw IPv6 socket test requires root")
	}

	clientConn, err := net.ListenPacket("udp6", "[::1]:0")
	if err != nil {
		t.Fatalf("listen client UDP6 socket: %v", err)
	}
	defer clientConn.Close()

	clientAddr, ok := clientConn.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("unexpected client local addr type: %T", clientConn.LocalAddr())
	}

	const conflictPort = 5357
	conflictConn, err := net.ListenPacket("udp6", "[::]:"+strconv.Itoa(conflictPort))
	if err != nil {
		t.Fatalf("listen wildcard UDP6 conflict socket: %v", err)
	}
	defer conflictConn.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 64)
		_ = clientConn.SetDeadline(time.Now().Add(2 * time.Second))
		n, addr, readErr := clientConn.ReadFrom(buf)
		if readErr != nil {
			t.Errorf("read fallback packet: %v", readErr)
			return
		}
		if got := string(buf[:n]); got != "hello" {
			t.Errorf("unexpected payload: %q", got)
		}
		if addr.String() != "[2001:4860:4860::8844]:"+strconv.Itoa(conflictPort) {
			t.Errorf("unexpected source addr: %v", addr)
		}
	}()

	from := netip.MustParseAddrPort("[2001:4860:4860::8844]:" + strconv.Itoa(conflictPort))
	realTo := netip.MustParseAddrPort(clientAddr.String())
	if err := sendUDPv6RawDirect([]byte("hello"), from, realTo); err != nil {
		t.Fatalf("sendUDPv6RawDirect: %v", err)
	}

	<-done
}
