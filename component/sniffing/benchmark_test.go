/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package sniffing

import (
	"bytes"
	"testing"
	"time"
)

func BenchmarkSniffer_SniffTcp_TLS(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sniffer := NewStreamSniffer(bytes.NewReader(tlsStreamGoogle), 300*time.Millisecond)
		d, err := sniffer.SniffTcp()
		if err != nil {
			b.Fatalf("sniff failed: %v", err)
		}
		if d != "www.google.com" {
			b.Fatalf("domain = %q, want %q", d, "www.google.com")
		}
	}
}

func BenchmarkSniffer_SniffTcp_HTTP(b *testing.B) {
	payload := []byte("GET / HTTP/1.1\r\nHost: benchmark.example.com\r\nUser-Agent: test\r\n\r\n")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sniffer := NewStreamSniffer(bytes.NewReader(payload), 300*time.Millisecond)
		d, err := sniffer.SniffTcp()
		if err != nil {
			b.Fatalf("sniff failed: %v", err)
		}
		if d != "benchmark.example.com" {
			b.Fatalf("domain = %q, want %q", d, "benchmark.example.com")
		}
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
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sniffer := NewStreamSniffer(bytes.NewReader(payload), 50*time.Millisecond)
		_, _ = sniffer.SniffTcp()
	}
}
