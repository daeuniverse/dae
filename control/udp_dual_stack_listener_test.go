/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common"
)

func TestUdpDualStackListenAddr(t *testing.T) {
	if got, want := udpDualStackListenAddr(12345), "[::]:12345"; got != want {
		t.Fatalf("unexpected dual-stack listen addr: got %q want %q", got, want)
	}
}

func TestUdpIngressSupportsBatch(t *testing.T) {
	ipv4Conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatalf("listen udp4: %v", err)
	}
	defer ipv4Conn.Close()

	if !udpIngressSupportsBatch(ipv4Conn) {
		t.Fatal("expected IPv4 UDP listener to keep batch ingress enabled")
	}

	if !supportsIPv6() {
		return
	}

	dialStack := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return enableUDPDualStackSocket(c)
		},
	}
	pc, err := dialStack.ListenPacket(context.Background(), "udp6", udpDualStackListenAddr(0))
	if err != nil {
		t.Fatalf("listen udp6 dual-stack: %v", err)
	}
	defer pc.Close()

	udpConn, ok := pc.(*net.UDPConn)
	if !ok {
		t.Fatalf("unexpected packet conn type %T", pc)
	}
	if udpIngressSupportsBatch(udpConn) {
		t.Fatal("expected dual-stack IPv6 UDP listener to disable IPv4-only batch ingress")
	}
}

func TestDualStackUDPListenerReceivesIPv4AndIPv6(t *testing.T) {
	if !supportsIPv6() {
		t.Skip("IPv6 not available on this system")
	}

	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return enableUDPDualStackSocket(c)
		},
	}
	pc, err := lc.ListenPacket(context.Background(), "udp6", udpDualStackListenAddr(0))
	if err != nil {
		t.Fatalf("listen dual-stack udp6: %v", err)
	}
	defer pc.Close()

	udpConn := pc.(*net.UDPConn)
	listenAddr := udpConn.LocalAddr().(*net.UDPAddr).AddrPort().Port()

	ipv4Sender, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(listenAddr)})
	if err != nil {
		t.Fatalf("dial udp4 sender: %v", err)
	}
	defer ipv4Sender.Close()

	ipv6Sender, err := net.DialUDP("udp6", nil, &net.UDPAddr{IP: net.IPv6loopback, Port: int(listenAddr)})
	if err != nil {
		t.Fatalf("dial udp6 sender: %v", err)
	}
	defer ipv6Sender.Close()

	if _, err := ipv4Sender.Write([]byte("ipv4")); err != nil {
		t.Fatalf("send ipv4 payload: %v", err)
	}
	if _, err := ipv6Sender.Write([]byte("ipv6")); err != nil {
		t.Fatalf("send ipv6 payload: %v", err)
	}

	if err := udpConn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}

	seenPayloads := make(map[string]netip.Addr)
	for len(seenPayloads) < 2 {
		buf := make([]byte, 64)
		n, _, _, src, err := udpConn.ReadMsgUDPAddrPort(buf, nil)
		if err != nil {
			t.Fatalf("read dual-stack listener: %v", err)
		}
		seenPayloads[string(buf[:n])] = common.ConvergeAddrPort(src).Addr()
	}

	if got := seenPayloads["ipv4"]; got != netip.MustParseAddr("127.0.0.1") {
		t.Fatalf("unexpected IPv4 sender addr: got %v", got)
	}
	if got := seenPayloads["ipv6"]; got != netip.IPv6Loopback() {
		t.Fatalf("unexpected IPv6 sender addr: got %v", got)
	}
}
