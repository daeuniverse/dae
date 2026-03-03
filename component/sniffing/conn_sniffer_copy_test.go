//go:build linux
// +build linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package sniffing

import (
	"bytes"
	"io"
	"net"
	"syscall"
	"testing"
)

// TestConnSnifferWriteToBufferFlush verifies that WriteTo first flushes the
// pre-buffered sniff data, then streams the remainder of the connection.
// NOTE: relay uses io.Copy after flushing the sniff buffer.
func TestConnSnifferWriteToBufferFlush(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	conn2, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn2.Close()

	conn1, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn1.Close()

	// Simulate pre-buffered sniff data (e.g. TLS ClientHello).
	sniffer := NewConnSniffer(conn1, 0)
	sniffer.Sniffer.buf.Reset()
	sniffer.Sniffer.buf.Write([]byte("BUFFERED_DATA"))

	var _ io.WriterTo = sniffer // interface must be satisfied

	testData := make([]byte, 100*1024)
	for i := range testData {
		testData[i] = byte(i % 256)
	}
	go func() {
		conn2.Write(testData)
		conn2.Close()
	}()

	var buf bytes.Buffer
	n, err := sniffer.WriteTo(&buf)
	if err != nil {
		t.Fatalf("WriteTo error: %v", err)
	}

	expected := int64(len("BUFFERED_DATA") + len(testData))
	if n != expected {
		t.Errorf("expected %d bytes, got %d", expected, n)
	}
	if !bytes.HasPrefix(buf.Bytes(), []byte("BUFFERED_DATA")) {
		t.Error("buffered data should come first")
	}
	if !bytes.Equal(buf.Bytes()[len("BUFFERED_DATA"):], testData) {
		t.Error("remaining data mismatch")
	}
}

// TestConnSnifferReadFromForwardsData verifies that ReadFrom forwards all bytes
// to the underlying connection.
func TestConnSnifferReadFromForwardsData(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	done := make(chan []byte, 1)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			done <- nil
			return
		}
		defer conn.Close()
		data, _ := io.ReadAll(conn)
		done <- data
	}()

	conn1, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn1.Close()

	sniffer := NewConnSniffer(conn1, 0)

	var _ io.ReaderFrom = sniffer // interface must be satisfied

	testData := make([]byte, 50*1024)
	for i := range testData {
		testData[i] = byte(i % 256)
	}
	n, err := sniffer.ReadFrom(bytes.NewReader(testData))
	if err != nil {
		t.Fatalf("ReadFrom error: %v", err)
	}
	if n != int64(len(testData)) {
		t.Errorf("expected %d bytes, got %d", len(testData), n)
	}
	conn1.Close()

	received := <-done
	if !bytes.Equal(received, testData) {
		t.Error("data mismatch after ReadFrom")
	}
}

// TestConnSnifferSyscallConnNotExposed verifies that ConnSniffer does NOT
// expose SyscallConn directly. This ensures callers (e.g. netproxy.ReadFrom)
// take the io.Copy branch, which triggers our WriteTo/ReadFrom implementations.
func TestConnSnifferSyscallConnNotExposed(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	sniffer := NewConnSniffer(conn, 0)

	type syscallConn interface {
		SyscallConn() (syscall.RawConn, error)
	}
	if _, ok := interface{}(sniffer).(syscallConn); ok {
		t.Error("ConnSniffer must NOT directly expose SyscallConn")
	}
	if _, ok := sniffer.Conn.(syscallConn); !ok {
		t.Error("underlying TCP connection should support SyscallConn")
	}
}

// BenchmarkWriteToBufferFlush benchmarks the WriteTo hot path (buffer flush + relay).
func BenchmarkWriteToBufferFlush(b *testing.B) {
	for i := 0; i < b.N; i++ {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			b.Fatal(err)
		}
		c2, _ := net.Dial("tcp", l.Addr().String())
		c1, _ := l.Accept()

		sniffer := NewConnSniffer(c1, 0)
		sniffer.Sniffer.buf.Write([]byte("BUFFERED"))

		data := make([]byte, 1024*1024)
		go func() {
			c2.Write(data)
			c2.Close()
		}()

		var buf bytes.Buffer
		sniffer.WriteTo(&buf)

		c1.Close()
		c2.Close()
		l.Close()
	}
}

// TestConnSnifferWriteToViaCopy verifies the io.Copy integration: when data is
// copied from a ConnSniffer via io.Copy, pre-buffered bytes come first.
func TestConnSnifferWriteToViaCopy(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	conn2, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn2.Close()

	conn1, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn1.Close()

	sniffer := NewConnSniffer(conn1, 0)
	sniffer.Sniffer.buf.Reset()
	sniffer.Sniffer.buf.Write([]byte("HELLO"))

	testData := make([]byte, 10*1024)
	for i := range testData {
		testData[i] = byte(i % 256)
	}
	go func() {
		conn2.Write(testData)
		conn2.Close()
	}()

	var buf bytes.Buffer
	n, err := io.Copy(&buf, sniffer)
	if err != nil {
		t.Fatalf("io.Copy error: %v", err)
	}

	expected := int64(len("HELLO") + len(testData))
	if n != expected {
		t.Errorf("expected %d bytes, got %d", expected, n)
	}
	if !bytes.HasPrefix(buf.Bytes(), []byte("HELLO")) {
		t.Error("buffered data should come first")
	}
}
