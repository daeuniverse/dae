/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"io"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/netutils"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// These tests pin the observe-only upstream source validation of: the
// datagram source reported by the transport is compared with the endpoint dae
// dialed, mismatches are counted and rate-limit logged, and nothing is dropped
// until every transport is known to report a truthful source.

func resetDnsUDPSourceMismatchState() {
	dnsUDPResponseSourceMismatchCount.Store(0)
	lastDnsUDPResponseSourceMismatchAt.Store(0)
}

func TestReadUDPConnFromReportsPacketSource(t *testing.T) {
	target := netip.MustParseAddrPort("198.51.100.53:53")
	conn := &scriptedPacketConn{
		reads:   make(chan scriptedPacketRead, 1),
		closeCh: make(chan struct{}),
	}
	conn.reads <- scriptedPacketRead{data: []byte{1, 2, 3, 4}, from: target}
	t.Cleanup(func() { _ = conn.Close() })

	buf := make([]byte, 16)
	n, from, err := netutils.ReadUDPConnFrom(conn, buf)
	if err != nil {
		t.Fatalf("ReadUDPConnFrom: %v", err)
	}
	if n != 4 {
		t.Fatalf("read length = %d, want 4", n)
	}
	if from != target {
		t.Fatalf("reported source = %v, want %v", from, target)
	}

	// The thin wrapper keeps its old signature and still returns the payload.
	conn.reads <- scriptedPacketRead{data: []byte{9}, from: target}
	n, err = netutils.ReadUDPConn(conn, buf)
	if err != nil {
		t.Fatalf("ReadUDPConn: %v", err)
	}
	if n != 1 {
		t.Fatalf("ReadUDPConn length = %d, want 1", n)
	}
}

func TestReadUDPConnFromReportsUnknownSourceForStreamTransport(t *testing.T) {
	conn := &streamOnlyConn{}
	buf := make([]byte, 8)
	n, from, err := netutils.ReadUDPConnFrom(conn, buf)
	if err != nil {
		t.Fatalf("ReadUDPConnFrom: %v", err)
	}
	if n != 2 {
		t.Fatalf("read length = %d, want 2", n)
	}
	if from.IsValid() {
		t.Fatalf("a stream transport must report an invalid (unknown) source, got %v", from)
	}
}

// streamOnlyConn implements netproxy.Conn but not netproxy.PacketConn.
type streamOnlyConn struct{}

func (c *streamOnlyConn) Read(p []byte) (int, error) {
	copy(p, []byte{7, 8})
	return 2, nil
}
func (c *streamOnlyConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *streamOnlyConn) Close() error                { return nil }
func (c *streamOnlyConn) SetDeadline(time.Time) error { return nil }
func (c *streamOnlyConn) SetReadDeadline(time.Time) error {
	return nil
}
func (c *streamOnlyConn) SetWriteDeadline(time.Time) error { return nil }

func TestUDPResponseSourceMismatchOnlyFlagsRealSources(t *testing.T) {
	target := netip.MustParseAddrPort("198.51.100.53:53")
	if udpResponseSourceMismatch(target, target) {
		t.Fatal("an identical source must not be flagged")
	}
	if !udpResponseSourceMismatch(netip.MustParseAddrPort("203.0.113.9:53"), target) {
		t.Fatal("a different source must be flagged")
	}
	if udpResponseSourceMismatch(netip.AddrPort{}, target) {
		t.Fatal("an unknown source must not be flagged as a mismatch")
	}
	if udpResponseSourceMismatch(target, netip.AddrPort{}) {
		t.Fatal("an unknown dialed target must not be flagged as a mismatch")
	}
}

// TestNoteUDPResponseSourceMismatchCountsAndRateLimits keeps the observe-only
// signal visible without letting a permanently mismatching transport flood the
// log.
func TestNoteUDPResponseSourceMismatchCountsAndRateLimits(t *testing.T) {
	resetDnsUDPSourceMismatchState()
	t.Cleanup(resetDnsUDPSourceMismatchState)

	logger := logrus.New()
	logger.SetOutput(io.Discard)
	target := netip.MustParseAddrPort("198.51.100.53:53")
	from := netip.MustParseAddrPort("203.0.113.9:53")

	for range 3 {
		noteDnsUDPResponseSourceMismatch(logger, target, from)
	}
	if got := dnsUDPResponseSourceMismatchCount.Load(); got != 3 {
		t.Fatalf("mismatch counter = %d, want 3", got)
	}
	if first, second := lastDnsUDPResponseSourceMismatchAt.Load(), time.Now().UnixNano(); first == 0 || first > second {
		t.Fatalf("rate-limit timestamp = %d, want a timestamp in the past", first)
	}

	// A datagram whose source matches must not be counted at all: the check is
	// performed by the caller before this reporter runs.
	if udpResponseSourceMismatch(from, from) {
		t.Fatal("sanity: identical endpoints are not a mismatch")
	}
}

// TestDoUDPObservesSourceMismatchWithoutDropping pins the end-to-end behaviour
// at the UDP forwarder: a reply whose reported source differs from the dialed
// endpoint is still delivered to the controller and counted.
func TestDoUDPObservesSourceMismatchWithoutDropping(t *testing.T) {
	resetDnsUDPSourceMismatchState()
	t.Cleanup(resetDnsUDPSourceMismatchState)

	dialed := netip.MustParseAddrPort("198.51.100.53:53")
	other := netip.MustParseAddrPort("203.0.113.9:53")
	reply := dnsAResponseMsg("source.test.", "203.0.113.10")
	reply.Id = 0x7101
	wire, err := reply.Pack()
	if err != nil {
		t.Fatalf("pack reply: %v", err)
	}

	conn := &scriptedPacketConn{
		reads:   make(chan scriptedPacketRead, 1),
		closeCh: make(chan struct{}),
	}
	conn.reads <- scriptedPacketRead{data: wire, from: other}

	logger := logrus.New()
	logger.SetOutput(io.Discard)
	dial := &DoUDP{
		dialArgument: dialArgument{
			l4proto:    consts.L4ProtoStr_UDP,
			ipversion:  consts.IpVersionStr_4,
			bestDialer: newTestEndpointDialer(conn),
			bestTarget: dialed,
		},
		log: logger,
	}
	t.Cleanup(func() { _ = dial.Close() })

	query := new(dnsmessage.Msg)
	query.SetQuestion("source.test.", dnsmessage.TypeA)
	query.Id = 0x7101
	queryWire, err := query.Pack()
	if err != nil {
		t.Fatalf("pack query: %v", err)
	}

	msg, err := dial.ForwardDNS(t.Context(), queryWire)
	if err != nil {
		t.Fatalf("ForwardDNS: %v", err)
	}
	if msg == nil || msg.Id != 0x7101 {
		t.Fatalf("ForwardDNS returned %#v, want the reply (observe-only mode must not drop it)", msg)
	}
	if got := dnsUDPResponseSourceMismatchCount.Load(); got != 1 {
		t.Fatalf("mismatch counter = %d, want 1", got)
	}
}
