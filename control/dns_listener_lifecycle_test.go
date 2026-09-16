/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"io"
	"net"
	"testing"

	"github.com/sirupsen/logrus"
)

func newDNSListenerTestLogger() *logrus.Logger {
	log := logrus.New()
	log.SetOutput(io.Discard)
	return log
}

func TestDNSListenerStartReportsUDPBindFailure(t *testing.T) {
	blocker, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("bind blocker: %v", err)
	}
	defer func() { _ = blocker.Close() }()

	listener, err := NewDNSListener(newDNSListenerTestLogger(), blocker.LocalAddr().String(), nil)
	if err != nil {
		t.Fatalf("NewDNSListener: %v", err)
	}
	if err = listener.Start(); err == nil {
		_ = listener.Stop()
		t.Fatal("Start succeeded despite occupied UDP address")
	}
}

func TestDNSListenerImmediateStop(t *testing.T) {
	for i := range 50 {
		listener, err := NewDNSListener(newDNSListenerTestLogger(), "127.0.0.1:0", nil)
		if err != nil {
			t.Fatalf("NewDNSListener iteration %d: %v", i, err)
		}
		if err = listener.Start(); err != nil {
			t.Fatalf("Start iteration %d: %v", i, err)
		}
		if err = listener.Stop(); err != nil {
			t.Fatalf("Stop iteration %d: %v", i, err)
		}
	}
}

func TestDNSListenerTCPBindFailureRollsBackUDP(t *testing.T) {
	tcpBlocker, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("bind TCP blocker: %v", err)
	}
	defer func() { _ = tcpBlocker.Close() }()

	addr := tcpBlocker.Addr().String()
	listener, err := NewDNSListener(newDNSListenerTestLogger(), "tcp+udp://"+addr, nil)
	if err != nil {
		t.Fatalf("NewDNSListener: %v", err)
	}
	if err = listener.Start(); err == nil {
		_ = listener.Stop()
		t.Fatal("Start succeeded despite occupied TCP address")
	}

	udpProbe, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatalf("UDP listener was not rolled back: %v", err)
	}
	_ = udpProbe.Close()
}
