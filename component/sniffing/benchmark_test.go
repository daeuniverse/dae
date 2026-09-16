/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package sniffing

import (
	"bytes"
	"net"
	"testing"
	"time"
)

// deadlineConn wraps a *bytes.Reader as a net.Conn whose deadline setters are
// no-ops returning nil.
//
// H8 (first application): a bare bytes.Reader is only an io.Reader, so
// NewStreamSniffer's r.(net.Conn) assertion fails and the sniffer falls back to
// the legacy async read path (readStreamOnceAsync, ~13 allocs). Production TCP
// sockets satisfy net.Conn and route through the deadline-sync path
// (readStreamOnceWithReadDeadline, ~5 allocs). Wrapping the bench payload in a
// deadlineConn makes the assertion succeed and SetReadDeadline return nil, so
// the bench measures the production-representative deadline-sync path instead
// of the async-biased one (see L14). The deadline is not actually enforced —
// the payload is fully available up front, mirroring data that has already
// arrived on a real socket before the sniff deadline.
type deadlineConn struct {
	r *bytes.Reader
}

func (c *deadlineConn) Read(p []byte) (int, error)      { return c.r.Read(p) }
func (c *deadlineConn) Write(p []byte) (int, error)     { return len(p), nil }
func (c *deadlineConn) Close() error                    { return nil }
func (c *deadlineConn) LocalAddr() net.Addr             { return nil }
func (c *deadlineConn) RemoteAddr() net.Addr            { return nil }
func (c *deadlineConn) SetDeadline(time.Time) error     { return nil }
func (c *deadlineConn) SetReadDeadline(time.Time) error { return nil }
func (c *deadlineConn) SetWriteDeadline(time.Time) error {
	return nil
}

// newDeadlineConn wraps a fresh bytes.Reader over payload as a deadline-supporting
// net.Conn for SniffTcp benchmarks.
func newDeadlineConn(payload []byte) *deadlineConn {
	return &deadlineConn{r: bytes.NewReader(payload)}
}

func BenchmarkSniffer_SniffTcp_TLS(b *testing.B) {
	// H8: newDeadlineConn exposes SetReadDeadline so SniffTcp routes through the
	// production deadline-sync read path (not the legacy async path a bare
	// bytes.Reader forces).
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sniffer := NewStreamSniffer(newDeadlineConn(tlsStreamGoogle), 300*time.Millisecond)
		d, err := sniffer.SniffTcp()
		if err != nil {
			b.Fatalf("sniff failed: %v", err)
		}
		if d != "www.google.com" {
			b.Fatalf("domain = %q, want %q", d, "www.google.com")
		}
		// Close exercises the full construct->sniff->close lifecycle so the
		// pool reuse path (production behavior) is measured, not just the
		// allocation path.
		_ = sniffer.Close()
	}
}

func BenchmarkSniffer_SniffTcp_HTTP(b *testing.B) {
	payload := []byte("GET / HTTP/1.1\r\nHost: benchmark.example.com\r\nUser-Agent: test\r\n\r\n")
	// H8: deadlineConn SetReadDeadline routes this through deadline-sync read.
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sniffer := NewStreamSniffer(newDeadlineConn(payload), 300*time.Millisecond)
		d, err := sniffer.SniffTcp()
		if err != nil {
			b.Fatalf("sniff failed: %v", err)
		}
		if d != "benchmark.example.com" {
			b.Fatalf("domain = %q, want %q", d, "benchmark.example.com")
		}
		_ = sniffer.Close()
	}
}

func BenchmarkSniffer_SniffUdp_QUIC(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sniffer := NewPacketSniffer(QuicStream3, 300*time.Millisecond)
		d, err := sniffer.SniffQuic()
		if err != nil {
			b.Fatalf("sniff failed: %v", err)
		}
		if d == "" {
			b.Fatal("empty domain")
		}
		_ = sniffer.Close()
	}
}

func BenchmarkSniffer_SniffUdp_QUICMultiPacket(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sniffer := NewPacketSniffer(QuicStream2_1, 300*time.Millisecond)
		_, err := sniffer.SniffQuic()
		if err != nil && sniffer.NeedMore() {
			sniffer.AppendData(QuicStream2_2)
			_, err = sniffer.SniffQuic()
		}
		if err != nil {
			b.Fatalf("sniff failed: %v", err)
		}
		_ = sniffer.Close()
	}
}

func BenchmarkSniffHTTPHostHeader_Extended(b *testing.B) {
	payload := []byte(
		"GET /path HTTP/1.1\r\n" +
			"User-Agent: benchmark-agent\r\n" +
			"Accept: */*\r\n" +
			"X-Forwarded-For: 10.0.0.1\r\n" +
			"Host: benchmark.example.com:443\r\n" +
			"Connection: keep-alive\r\n\r\n",
	)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = sniffHTTPHostHeader(payload)
	}
}

func BenchmarkSniffHTTPHostHeader_NoHost(b *testing.B) {
	payload := []byte(
		"GET /path HTTP/1.1\r\n" +
			"User-Agent: benchmark-agent\r\n" +
			"Accept: */*\r\n\r\n",
	)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = sniffHTTPHostHeader(payload)
	}
}

func BenchmarkIsLikelyQuicInitialPacket(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		IsLikelyQuicInitialPacket(QuicStream3)
	}
}

func BenchmarkSniffer_SniffTcp_NotApplicable(b *testing.B) {
	payload := []byte("this is not TLS or HTTP traffic, just random binary data that should fail quickly")
	// H8: deadlineConn SetReadDeadline routes this through deadline-sync read.
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sniffer := NewStreamSniffer(newDeadlineConn(payload), 50*time.Millisecond)
		_, _ = sniffer.SniffTcp()
		_ = sniffer.Close()
	}
}

// Allocation budgets, measured before and after the review.
//
// Measured baseline on the review machine (go1.26, amd64, -benchtime 2000x):
//
//	BenchmarkSniffer_SniffUdp_QUIC   5909 ns/op  5427 B/op  60 allocs/op
//	BenchmarkIsLikelyQuicInitialPacket 0.28 ns/op   0 B/op   0 allocs/op
//
// proposed moving the HKDF/AES construction off the per-packet path by
// reusing a cipher suite per destination connection ID. That change was NOT
// made: QUIC Initial keys are per (version, DCID) and the sniffer only ever
// sees a flow's first packets, so the win is bounded to a handful of packets
// per flow, while the change itself carries a silent-misclassification failure
// mode (a stale or wrong cached suite decrypts to a wrong domain, which then
// picks a different outbound) and would require the pooled key buffers to stay
// owned by the cache instead of being returned by Keys.Close. The numbers below
// are therefore a regression gate on the current shape: any future
// optimization must lower them, and any unrelated change that raises them fails
// here instead of silently costing allocations on a per-flow path.
func TestSniffAllocationBudget(t *testing.T) {
	if raceEnabled {
		t.Skip("allocation budgets describe production builds; the race detector instruments allocations (see race_off_test.go)")
	}
	quicAllocs := testing.AllocsPerRun(20, func() {
		sniffer := NewPacketSniffer(QuicStream3, 300*time.Millisecond)
		if _, err := sniffer.SniffQuic(); err != nil {
			t.Fatalf("SniffQuic: %v", err)
		}
		_ = sniffer.Close()
	})
	if quicAllocs > 60 {
		t.Fatalf("SniffQuic allocations = %v/op, budget 60 (baseline)", quicAllocs)
	}

	tlsAllocs := testing.AllocsPerRun(20, func() {
		sniffer := NewStreamSniffer(newDeadlineConn(tlsStreamGoogle), 300*time.Millisecond)
		if _, err := sniffer.SniffTcp(); err != nil {
			t.Fatalf("SniffTcp: %v", err)
		}
		_ = sniffer.Close()
	})
	if tlsAllocs > 8 {
		t.Fatalf("SniffTcp(TLS) allocations = %v/op, budget 8", tlsAllocs)
	}
}
