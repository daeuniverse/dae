/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package daedns

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	dnsmessage "github.com/miekg/dns"
	"github.com/olicesx/quic-go"
)

// stubAResponseMsg builds a single-A-record response for the DoQ stubs.
func stubAResponseMsg(name, ip string) *dnsmessage.Msg {
	msg := new(dnsmessage.Msg)
	msg.SetReply(new(dnsmessage.Msg))
	msg.SetQuestion(dnsmessage.CanonicalName(name), dnsmessage.TypeA)
	msg.Answer = []dnsmessage.RR{
		&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{
				Name:   dnsmessage.CanonicalName(name),
				Rrtype: dnsmessage.TypeA,
				Class:  dnsmessage.ClassINET,
				Ttl:    60,
			},
			A: net.ParseIP(ip).To4(),
		},
	}
	return msg
}

// stubQuicStream is a quic.Stream that records the order of the operations the
// DoQ exchange performs, so a test can assert that the send half was finished
// before the response is read (RFC 9250 §4.2).
type stubQuicStream struct {
	mu sync.Mutex

	writes     [][]byte
	closed     bool
	reads      int
	readAfter  bool // a Read happened while the send half was still open
	closeCalls int

	response []byte
	closeErr error
	readErr  error
	writeErr error
}

func (s *stubQuicStream) StreamID() quic.StreamID { return 0 }

func (s *stubQuicStream) Read(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reads++
	if !s.closed {
		s.readAfter = true
	}
	if s.readErr != nil {
		return 0, s.readErr
	}
	if s.response == nil {
		return 0, io.EOF
	}
	n := copy(p, s.response)
	s.response = s.response[n:]
	return n, nil
}

func (s *stubQuicStream) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.writeErr != nil {
		return 0, s.writeErr
	}
	s.writes = append(s.writes, append([]byte(nil), p...))
	return len(p), nil
}

func (s *stubQuicStream) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closeCalls++
	if s.closeErr != nil {
		return s.closeErr
	}
	s.closed = true
	return nil
}

func (s *stubQuicStream) CancelWrite(quic.StreamErrorCode) {}
func (s *stubQuicStream) CancelRead(quic.StreamErrorCode)  {}
func (s *stubQuicStream) SetDeadline(time.Time) error      { return nil }
func (s *stubQuicStream) SetReadDeadline(time.Time) error  { return nil }
func (s *stubQuicStream) SetWriteDeadline(time.Time) error { return nil }
func (s *stubQuicStream) Context() context.Context         { return context.Background() }

func stubFramedResponse(t *testing.T, msg *dnsmessage.Msg) []byte {
	t.Helper()
	wire, err := msg.Pack()
	if err != nil {
		t.Fatalf("pack stub DoQ response: %v", err)
	}
	framed := make([]byte, 2+len(wire))
	binary.BigEndian.PutUint16(framed[:2], uint16(len(wire)))
	copy(framed[2:], wire)
	return framed
}

// TestDoQExchangeSendsFinBeforeReading pins the DoQ client contract: the query
// is written, the send half is closed (FIN), and only then is the response
// read. A compliant server may legitimately never answer a query whose send
// half is still open, so reading first would hang until the exchange timeout.
func TestDoQExchangeSendsFinBeforeReading(t *testing.T) {
	response := stubAResponseMsg("doq.test.", "203.0.113.5")
	stream := &stubQuicStream{response: stubFramedResponse(t, response)}

	query := dnsQueryWire(t, "doq.test.", dnsmessage.TypeA)
	msg, err := exchangeDoQQuery(stream, query)
	if err != nil {
		t.Fatalf("exchangeDoQQuery: %v", err)
	}
	if msg == nil || len(msg.Answer) != 1 {
		t.Fatalf("exchangeDoQQuery returned %#v, want the stubbed answer", msg)
	}
	if stream.readAfter {
		t.Fatal("the response was read before the send half was closed (FIN); RFC 9250 §4.2 requires FIN first")
	}
	if stream.closeCalls != 1 {
		t.Fatalf("stream.Close calls = %d, want exactly 1 (the FIN)", stream.closeCalls)
	}
	if len(stream.writes) != 1 {
		t.Fatalf("stream writes = %d, want 1", len(stream.writes))
	}
	if len(stream.writes[0]) != 2+len(query) {
		t.Fatalf("framed query length = %d, want %d", len(stream.writes[0]), 2+len(query))
	}
	if got := stream.writes[0][2:]; !bytes.Equal(got, query) {
		t.Fatalf("framed query payload = %x, want %x", got, query)
	}
}

// TestDoQExchangeReportsFailedFin covers the failure path: when the FIN cannot
// be delivered the exchange fails instead of parking on a response that cannot
// arrive, and the deferred close still fires because no FIN was sent.
func TestDoQExchangeReportsFailedFin(t *testing.T) {
	finErr := fmt.Errorf("stub: send half already cancelled")
	stream := &stubQuicStream{closeErr: finErr, response: nil}

	_, err := exchangeDoQQuery(stream, dnsQueryWire(t, "doq.test.", dnsmessage.TypeA))
	if err == nil {
		t.Fatal("exchangeDoQQuery must fail when the FIN cannot be delivered")
	}
	if stream.reads != 0 {
		t.Fatalf("stream reads = %d, want 0 when the FIN failed", stream.reads)
	}
	// One explicit Close (failed) plus the deferred cleanup Close.
	if stream.closeCalls != 2 {
		t.Fatalf("stream.Close calls = %d, want 2 (explicit failure plus deferred cleanup)", stream.closeCalls)
	}
}

// TestDoQExchangeReportsWriteFailure covers a query that never reached the
// server: the FIN must not be sent, and the deferred close still releases the
// stream.
func TestDoQExchangeReportsWriteFailure(t *testing.T) {
	writeErr := fmt.Errorf("stub: write failed")
	stream := &stubQuicStream{writeErr: writeErr}

	_, err := exchangeDoQQuery(stream, dnsQueryWire(t, "doq.test.", dnsmessage.TypeA))
	if err == nil {
		t.Fatal("exchangeDoQQuery must fail when the query cannot be written")
	}
	// Only the deferred cleanup closes the stream: the explicit FIN must not
	// have been attempted after a failed write.
	if stream.closeCalls != 1 {
		t.Fatalf("stream.Close calls = %d, want 1 (deferred cleanup)", stream.closeCalls)
	}
	if stream.reads != 0 {
		t.Fatalf("stream reads = %d, want 0 after a failed write", stream.reads)
	}
}

func dnsQueryWire(t *testing.T, name string, qtype uint16) []byte {
	t.Helper()
	msg := new(dnsmessage.Msg)
	msg.SetQuestion(dnsmessage.CanonicalName(name), qtype)
	wire, err := msg.Pack()
	if err != nil {
		t.Fatalf("pack stub DoQ query: %v", err)
	}
	return wire
}
