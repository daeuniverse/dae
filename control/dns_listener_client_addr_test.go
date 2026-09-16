/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net"
	"strings"
	"testing"
	"time"

	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// These tests pin the log contract of a request whose client address cannot be
// turned into an IP:port. The address comes from the client, so a broken or
// hostile peer must not be able to drive one error line per request; the
// SERVFAIL answer itself, the drop count and the per-request debug detail must
// all survive the pace.

// addrLessResponseWriter is a dnsmessage.ResponseWriter whose RemoteAddr is
// whatever the test sets. It records every message written to the client.
type addrLessResponseWriter struct {
	remote net.Addr
	writes []*dnsmessage.Msg
}

func (w *addrLessResponseWriter) LocalAddr() net.Addr  { return &net.UDPAddr{} }
func (w *addrLessResponseWriter) RemoteAddr() net.Addr { return w.remote }
func (w *addrLessResponseWriter) WriteMsg(m *dnsmessage.Msg) error {
	w.writes = append(w.writes, m)
	return nil
}
func (w *addrLessResponseWriter) Write(p []byte) (int, error) { return len(p), nil }
func (w *addrLessResponseWriter) Close() error                { return nil }
func (w *addrLessResponseWriter) TsigStatus() error           { return nil }
func (w *addrLessResponseWriter) TsigTimersOnly(bool)         {}
func (w *addrLessResponseWriter) Hijack()                     {}

// badAddr is a net.Addr whose String() has no host:port form.
type badAddr struct{}

func (badAddr) Network() string { return "udp" }
func (badAddr) String() string  { return "not-an-address" }

func newTestDNSQuery() *dnsmessage.Msg {
	m := new(dnsmessage.Msg)
	m.SetQuestion("example.com.", dnsmessage.TypeA)
	return m
}

func TestUnusableClientAddrIsPacedButStillAnswered(t *testing.T) {
	logger, out := newLogCapture(logrus.WarnLevel)
	h := &dnsHandler{log: logger}

	const requests = 4
	for i := range requests {
		w := &addrLessResponseWriter{remote: badAddr{}}
		h.answerUnusableClientAddr(w, newTestDNSQuery(), "split host and port", nil)
		if len(w.writes) != 1 {
			t.Fatalf("request %d: wrote %d messages, want the SERVFAIL answer", i, len(w.writes))
		}
		if rcode := w.writes[0].Rcode; rcode != dnsmessage.RcodeServerFailure {
			t.Fatalf("request %d: rcode = %v, want SERVFAIL", i, rcode)
		}
	}

	lines := out.lines()
	if len(lines) != 1 {
		t.Fatalf("%d unusable client addresses produced %d lines, want 1: %v", requests, len(lines), lines)
	}
	for _, want := range []string{"unusable client address", "split host and port"} {
		if !strings.Contains(lines[0], want) {
			t.Fatalf("paced line %q is missing %q", lines[0], want)
		}
	}
	if got := h.badClientAddrAlert.observations.Load(); got != requests {
		t.Fatalf("dropped requests = %d, want %d: a paced report must still count every request", got, requests)
	}

	// Let the pace elapse: the next report carries the number of requests it
	// covers, so the suppressed ones are never lost.
	rewindPace(&h.badClientAddrAlert, time.Now(), dnsListenerBadClientAddrLogInterval)
	h.answerUnusableClientAddr(&addrLessResponseWriter{remote: badAddr{}}, newTestDNSQuery(), "split host and port", nil)
	lines = out.lines()
	if len(lines) != 2 {
		t.Fatalf("lines after the pace = %d, want 2: %v", len(lines), lines)
	}
	if !strings.Contains(lines[1], "dropped=5") {
		t.Fatalf("paced line %q does not carry the accumulated drop count", lines[1])
	}
}

func TestUnusableClientAddrKeepsPerRequestDetailAtDebug(t *testing.T) {
	logger, out := newLogCapture(logrus.DebugLevel)
	h := &dnsHandler{log: logger}

	h.answerUnusableClientAddr(&addrLessResponseWriter{remote: badAddr{}}, newTestDNSQuery(), "split host and port", nil)
	h.answerUnusableClientAddr(&addrLessResponseWriter{remote: badAddr{}}, newTestDNSQuery(), "parse IP", nil)

	lines := out.lines()
	debugs, warns := 0, 0
	for _, line := range lines {
		switch {
		case strings.Contains(line, "level=debug"):
			debugs++
		case strings.Contains(line, "level=warning"):
			warns++
		}
	}
	if debugs != 2 {
		t.Fatalf("debug lines = %d, want one per request: %v", debugs, lines)
	}
	if warns != 1 {
		t.Fatalf("warning lines = %d, want 1: %v", warns, lines)
	}
}

func TestNilRemoteAddrIsReportedWithItsOwnReason(t *testing.T) {
	logger, out := newLogCapture(logrus.WarnLevel)
	h := &dnsHandler{log: logger}

	w := &addrLessResponseWriter{}
	h.answerUnusableClientAddr(w, newTestDNSQuery(), "nil RemoteAddr", nil)

	if len(w.writes) != 1 || w.writes[0].Rcode != dnsmessage.RcodeServerFailure {
		t.Fatalf("a nil RemoteAddr must still be answered with SERVFAIL, got %+v", w.writes)
	}
	lines := out.lines()
	if len(lines) != 1 || !strings.Contains(lines[0], "nil RemoteAddr") {
		t.Fatalf("lines = %v, want one line naming the nil RemoteAddr", lines)
	}
}

// TestUnusableClientAddrIsNoLongerReportedAtErrorLevel is the level contract:
// the failure is caused by the client, it is answered (SERVFAIL) and the
// daemon keeps serving, so it must not sit at error level where it competes
// with daemon-side failures. It must also not disappear from the default
// level: warn and above stay visible at the default info level.
func TestUnusableClientAddrIsNoLongerReportedAtErrorLevel(t *testing.T) {
	logger, out := newLogCapture(logrus.InfoLevel)
	h := &dnsHandler{log: logger}

	h.answerUnusableClientAddr(&addrLessResponseWriter{remote: badAddr{}}, newTestDNSQuery(), "split host and port", nil)

	lines := out.lines()
	if len(lines) != 1 {
		t.Fatalf("lines = %v, want one visible line at the default level", lines)
	}
	if strings.Contains(lines[0], "level=error") {
		t.Fatalf("line %q is still at error level", lines[0])
	}
	if !strings.Contains(lines[0], "level=warning") {
		t.Fatalf("line %q is not at warning level", lines[0])
	}
}
