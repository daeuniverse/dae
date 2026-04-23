//go:build linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

func TestSendUDPv4RawDirect(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("raw IPv4 socket test requires root")
	}

	clientConn, err := net.ListenPacket("udp4", "10.255.255.254:0")
	if err != nil {
		t.Fatalf("listen client UDP4 socket: %v", err)
	}
	defer func() { _ = clientConn.Close() }()

	clientAddr, ok := clientConn.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("unexpected client local addr type: %T", clientConn.LocalAddr())
	}

	const conflictPort = 5357
	conflictConn, err := net.ListenPacket("udp4", "0.0.0.0:"+strconv.Itoa(conflictPort))
	if err != nil {
		t.Fatalf("listen wildcard UDP4 conflict socket: %v", err)
	}
	defer func() { _ = conflictConn.Close() }()

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
		if addr.String() != "1.1.1.1:"+strconv.Itoa(conflictPort) {
			t.Errorf("unexpected source addr: %v", addr)
		}
	}()

	from := netip.MustParseAddrPort("1.1.1.1:" + strconv.Itoa(conflictPort))
	realTo := netip.MustParseAddrPort(clientAddr.String())
	if err := sendUDPv4RawDirect([]byte("hello"), from, realTo); err != nil {
		t.Fatalf("sendUDPv4RawDirect: %v", err)
	}

	<-done
}

func TestSendUDPv6RawDirect(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("raw IPv6 socket test requires root")
	}

	clientConn, err := net.ListenPacket("udp6", "[::1]:0")
	if err != nil {
		t.Fatalf("listen client UDP6 socket: %v", err)
	}
	defer func() { _ = clientConn.Close() }()

	clientAddr, ok := clientConn.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("unexpected client local addr type: %T", clientConn.LocalAddr())
	}

	const conflictPort = 5357
	conflictConn, err := net.ListenPacket("udp6", "[::]:"+strconv.Itoa(conflictPort))
	if err != nil {
		t.Fatalf("listen wildcard UDP6 conflict socket: %v", err)
	}
	defer func() { _ = conflictConn.Close() }()

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

func TestSendPktFallsBackToRawIPv4AfterAnyfromNegativeCache(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("raw IPv4 socket test requires root")
	}

	DefaultAnyfromPool.Reset()
	defer DefaultAnyfromPool.Reset()

	clientConn, err := net.ListenPacket("udp4", "10.255.255.254:0")
	if err != nil {
		t.Fatalf("listen client UDP4 socket: %v", err)
	}
	defer func() { _ = clientConn.Close() }()

	clientAddr, ok := clientConn.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("unexpected client local addr type: %T", clientConn.LocalAddr())
	}

	conflictConn, err := net.ListenPacket("udp4", "0.0.0.0:53")
	if err != nil {
		t.Skipf("listen wildcard UDP4 conflict socket on :53: %v", err)
	}
	defer func() { _ = conflictConn.Close() }()

	logger := logrus.New()
	logger.SetOutput(io.Discard)
	from := netip.MustParseAddrPort("1.1.1.1:53")
	realTo := netip.MustParseAddrPort(clientAddr.String())

	readPacket := func(want string) {
		t.Helper()
		buf := make([]byte, 64)
		_ = clientConn.SetDeadline(time.Now().Add(2 * time.Second))
		n, addr, readErr := clientConn.ReadFrom(buf)
		if readErr != nil {
			t.Fatalf("read fallback packet: %v", readErr)
		}
		if got := string(buf[:n]); got != want {
			t.Fatalf("unexpected payload: %q, want %q", got, want)
		}
		if addr.String() != from.String() {
			t.Fatalf("unexpected source addr: %v, want %v", addr, from)
		}
	}

	if err := sendPkt(logger, []byte("first"), from, realTo, nil); err != nil {
		t.Fatalf("first sendPkt: %v", err)
	}
	readPacket("first")

	if _, _, err := DefaultAnyfromPool.GetOrCreate(from, AnyfromTimeout); err == nil || err != ErrAnyfromBindFailed {
		t.Fatalf("GetOrCreate err = %v, want %v", err, ErrAnyfromBindFailed)
	}

	if err := sendPkt(logger, []byte("second"), from, realTo, nil); err != nil {
		t.Fatalf("second sendPkt with negative cache: %v", err)
	}
	readPacket("second")
}
