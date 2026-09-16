/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package daedns

import (
	"context"
	"io"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// quietLogger returns a logger whose output is discarded so the observe-only
// warnings do not pollute test output.
func quietLogger() *logrus.Logger {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	return logger
}

// fakePacketConn is a netproxy.PacketConn that replays canned datagrams. It is
// enough to drive queryUDP because WriteUDPConn/ReadUDPConn only need the
// PacketConn surface.
type fakePacketConn struct {
	datagrams [][]byte
	from      netip.AddrPort
	readErr   error
}

func (c *fakePacketConn) Read(p []byte) (int, error) { return 0, c.readErr }

func (c *fakePacketConn) Write(p []byte) (int, error) { return len(p), nil }

func (c *fakePacketConn) ReadFrom(p []byte) (int, netip.AddrPort, error) {
	if len(c.datagrams) == 0 {
		return 0, netip.AddrPort{}, c.readErr
	}
	next := c.datagrams[0]
	c.datagrams = c.datagrams[1:]
	if len(next) > len(p) {
		return 0, netip.AddrPort{}, c.readErr
	}
	return copy(p, next), c.from, nil
}

func (c *fakePacketConn) WriteTo(p []byte, _ string) (int, error) { return len(p), nil }
func (c *fakePacketConn) Close() error                            { return nil }
func (c *fakePacketConn) SetDeadline(time.Time) error             { return nil }
func (c *fakePacketConn) SetReadDeadline(time.Time) error         { return nil }
func (c *fakePacketConn) SetWriteDeadline(time.Time) error        { return nil }

type fakeDialer struct {
	conn netproxy.Conn
}

func (d *fakeDialer) DialContext(context.Context, string, string) (netproxy.Conn, error) {
	return d.conn, nil
}

// TestDNSQuestionEchoMatches pins the RFC 5452 second factor: the echoed
// question, not only the 16-bit transaction ID.
func TestDNSQuestionEchoMatches(t *testing.T) {
	req := dnsmessage.Question{Name: "echo.test.", Qtype: dnsmessage.TypeA, Qclass: dnsmessage.ClassINET}

	reply := func(name string, qtype uint16) *dnsmessage.Msg {
		msg := new(dnsmessage.Msg)
		msg.SetQuestion(name, qtype)
		msg.Response = true
		return msg
	}

	if !dnsQuestionEchoMatches(req, reply("echo.test.", dnsmessage.TypeA)) {
		t.Fatal("an identical question must match")
	}
	if !dnsQuestionEchoMatches(req, reply("ECHO.TEST.", dnsmessage.TypeA)) {
		t.Fatal("question comparison must be case-insensitive")
	}
	if dnsQuestionEchoMatches(req, reply("other.test.", dnsmessage.TypeA)) {
		t.Fatal("a different name must not match")
	}
	if dnsQuestionEchoMatches(req, reply("echo.test.", dnsmessage.TypeAAAA)) {
		t.Fatal("a different qtype must not match")
	}
	if dnsQuestionEchoMatches(req, reply("echo.test.", dnsmessage.TypeA)) == false {
		t.Fatal("sanity")
	}
	empty := new(dnsmessage.Msg)
	empty.Response = true
	if dnsQuestionEchoMatches(req, empty) {
		t.Fatal("a reply without a question section must not match")
	}
}

// TestQueryUDPCountsQuestionEchoMismatchWithoutRejecting pins the observe-only
// behaviour: a reply whose ID matches but whose question does not echo the
// request is counted, and still returned so no working upstream regresses
// before the stricter condition has been validated in the field.
func TestQueryUDPCountsQuestionEchoMismatchWithoutRejecting(t *testing.T) {
	target := netip.MustParseAddrPort("192.0.2.53:53")
	query := new(dnsmessage.Msg)
	query.SetQuestion("asked.test.", dnsmessage.TypeA)
	query.Id = 0x1234
	wire, err := query.Pack()
	if err != nil {
		t.Fatalf("pack query: %v", err)
	}

	spoof := new(dnsmessage.Msg)
	spoof.SetQuestion("other.test.", dnsmessage.TypeA)
	spoof.Id = 0x1234 // same transaction ID: the question is the only signal
	spoof.Response = true
	spoofWire, err := spoof.Pack()
	if err != nil {
		t.Fatalf("pack spoofed reply: %v", err)
	}

	conn := &fakePacketConn{datagrams: [][]byte{spoofWire}, from: target}
	router := &Router{directDialer: &fakeDialer{conn: conn}, log: quietLogger()}

	msg, err := router.queryUDP(context.Background(), target, wire)
	if err != nil {
		t.Fatalf("queryUDP: %v", err)
	}
	if msg == nil {
		t.Fatal("observe-only mode must still accept the reply")
	}
	if got := router.udpQuestionEchoMismatches.Load(); got != 1 {
		t.Fatalf("question echo mismatches = %d, want 1", got)
	}
	if got := router.udpStaleResponses.Load(); got != 0 {
		t.Fatalf("stale response count = %d, want 0 (the ID matched)", got)
	}
}

// TestQueryUDPCountsStaleTransactionIDs keeps the previously silent ID-mismatch
// drop visible.
func TestQueryUDPCountsStaleTransactionIDs(t *testing.T) {
	target := netip.MustParseAddrPort("192.0.2.53:53")
	query := new(dnsmessage.Msg)
	query.SetQuestion("asked.test.", dnsmessage.TypeA)
	query.Id = 0x1234
	wire, err := query.Pack()
	if err != nil {
		t.Fatalf("pack query: %v", err)
	}

	stale := new(dnsmessage.Msg)
	stale.SetQuestion("asked.test.", dnsmessage.TypeA)
	stale.Id = 0x9999
	stale.Response = true
	staleWire, err := stale.Pack()
	if err != nil {
		t.Fatalf("pack stale reply: %v", err)
	}

	fresh := new(dnsmessage.Msg)
	fresh.SetQuestion("asked.test.", dnsmessage.TypeA)
	fresh.Id = 0x1234
	fresh.Response = true
	freshWire, err := fresh.Pack()
	if err != nil {
		t.Fatalf("pack fresh reply: %v", err)
	}

	conn := &fakePacketConn{datagrams: [][]byte{staleWire, freshWire}, from: target}
	router := &Router{directDialer: &fakeDialer{conn: conn}, log: quietLogger()}

	msg, err := router.queryUDP(context.Background(), target, wire)
	if err != nil {
		t.Fatalf("queryUDP: %v", err)
	}
	if msg == nil || msg.Id != 0x1234 {
		t.Fatalf("queryUDP returned %#v, want the matching reply", msg)
	}
	if got := router.udpStaleResponses.Load(); got != 1 {
		t.Fatalf("stale response count = %d, want 1", got)
	}
	if got := router.udpQuestionEchoMismatches.Load(); got != 0 {
		t.Fatalf("question echo mismatches = %d, want 0", got)
	}
}
