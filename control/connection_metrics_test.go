/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import "testing"

func TestControlPlaneConnectionTotalsSnapshot(t *testing.T) {
	cp := &ControlPlane{}

	cp.AddTcpConnectionTotal("tcp4", "HK")
	cp.AddTcpConnectionTotal("tcp4", "HK")
	cp.AddTcpConnectionTotal("tcp6", "US")
	cp.AddUdpConnectionTotal("udp4", "HK")
	cp.AddUdpConnectionTotal("udp4", "HK")
	cp.AddUdpConnectionTotal("udp6", "US")
	cp.AddUdpConnectionTotal("", "ignored")
	cp.AddTcpConnectionTotal("tcp4", "")

	tcpSnapshot := cp.TcpConnectionTotalsSnapshot()
	if got := tcpSnapshot[ConnMetricKey{Protocol: "tcp4", Group: "HK"}]; got != 2 {
		t.Fatalf("unexpected tcp4/HK count: got=%d want=2", got)
	}
	if got := tcpSnapshot[ConnMetricKey{Protocol: "tcp6", Group: "US"}]; got != 1 {
		t.Fatalf("unexpected tcp6/US count: got=%d want=1", got)
	}
	if len(tcpSnapshot) != 2 {
		t.Fatalf("unexpected tcp snapshot size: got=%d want=2", len(tcpSnapshot))
	}

	udpSnapshot := cp.UdpConnectionTotalsSnapshot()
	if got := udpSnapshot[ConnMetricKey{Protocol: "udp4", Group: "HK"}]; got != 2 {
		t.Fatalf("unexpected udp4/HK count: got=%d want=2", got)
	}
	if got := udpSnapshot[ConnMetricKey{Protocol: "udp6", Group: "US"}]; got != 1 {
		t.Fatalf("unexpected udp6/US count: got=%d want=1", got)
	}
	if len(udpSnapshot) != 2 {
		t.Fatalf("unexpected udp snapshot size: got=%d want=2", len(udpSnapshot))
	}
}
