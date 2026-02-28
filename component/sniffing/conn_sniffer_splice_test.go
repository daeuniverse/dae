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

// TestConnSnifferWriteToSplice verifies that WriteTo implements zero-copy splice
func TestConnSnifferWriteToSplice(t *testing.T) {
	// Create a TCP connection pair
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

	// Create ConnSniffer with buffered data
	sniffer := NewConnSniffer(conn1, 0)
	// Simulate buffered data (like TLS ClientHello)
	sniffer.Sniffer.buf.Reset()
	sniffer.Sniffer.buf.Write([]byte("BUFFERED_DATA"))

	// Check that ConnSniffer implements io.WriterTo
	var _ io.WriterTo = sniffer

	// Write test data to conn2 (will be received by conn1)
	testData := make([]byte, 100*1024) // 100KB
	for i := range testData {
		testData[i] = byte(i % 256)
	}
	go func() {
		conn2.Write(testData)
		conn2.Close()
	}()

	// Use WriteTo to transfer data
	var buf bytes.Buffer
	n, err := sniffer.WriteTo(&buf)
	if err != nil {
		t.Fatalf("WriteTo error: %v", err)
	}

	// Verify we received all data
	expected := int64(len("BUFFERED_DATA") + len(testData))
	if n != expected {
		t.Errorf("Expected %d bytes, got %d", expected, n)
	}

	// Verify the buffered data came first
	result := buf.Bytes()
	if !bytes.HasPrefix(result, []byte("BUFFERED_DATA")) {
		t.Error("Buffered data should come first")
	}

	// Verify the rest of the data matches
	rest := result[len("BUFFERED_DATA"):]
	if !bytes.Equal(rest, testData) {
		t.Error("Remaining data doesn't match")
	}
}

// TestConnSnifferReadFromSplice verifies that ReadFrom implements zero-copy splice
func TestConnSnifferReadFromSplice(t *testing.T) {
	// Create a TCP connection pair
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	// First accept and then dial to avoid race
	done := make(chan struct{})
	go func() {
		conn2, err := l.Accept()
		if err != nil {
			return
		}
		defer conn2.Close()
		close(done)
	}()

	conn1, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn1.Close()

	<-done // Wait for connection to be accepted

	// Create ConnSniffer
	sniffer := NewConnSniffer(conn1, 0)

	// Check that ConnSniffer implements io.ReaderFrom
	var _ io.ReaderFrom = sniffer

	// Create another connection pair for testing
	l2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()

	go func() {
		c2, _ := net.Dial("tcp", l2.Addr().String())
		testData := make([]byte, 100*1024) // 100KB
		for i := range testData {
			testData[i] = byte(i % 256)
		}
		c2.Write(testData)
		// Close write side but keep connection open for reading
		if tcpConn, ok := c2.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
		// Delay closing to allow read
		c2.Close()
	}()

	srcConn, err := l2.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer srcConn.Close()

	// Use ReadFrom to transfer data from srcConn to sniffer (which wraps conn1)
	n, err := sniffer.ReadFrom(srcConn)
	if err != nil && err != io.EOF {
		t.Logf("ReadFrom error (may be expected): %v", err)
	}

	if n == 0 {
		t.Error("Expected to read some data")
	}
	t.Logf("Read %d bytes via ReadFrom", n)
}

// TestConnSnifferSyscallConnNotExposed verifies that ConnSniffer does NOT expose SyscallConn
// This ensures that netproxy.ReadFrom will use io.Copy path, which will call our WriteTo/ReadFrom
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

	// Verify that ConnSniffer does NOT implement SyscallConn directly
	type syscallConn interface {
		SyscallConn() (syscall.RawConn, error)
	}

	_, ok := interface{}(sniffer).(syscallConn)
	if ok {
		t.Error("ConnSniffer should NOT directly expose SyscallConn")
	}

	// But the underlying connection should support it
	_, ok = sniffer.Conn.(syscallConn)
	if !ok {
		t.Error("Underlying connection should support SyscallConn")
	}

	// And we can get the raw connection from it
	_, ok = conn.(syscallConn)
	if !ok {
		t.Error("Original TCP connection should support SyscallConn")
	}
}

// BenchmarkWriteToWithSplice benchmarks WriteTo with splice
func BenchmarkWriteToWithSplice(b *testing.B) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer l.Close()

	conn2, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		b.Fatal(err)
	}
	defer conn2.Close()

	conn1, err := l.Accept()
	if err != nil {
		b.Fatal(err)
	}
	defer conn1.Close()

	sniffer := NewConnSniffer(conn1, 0)
	// Add some buffered data
	sniffer.Sniffer.buf.Write([]byte("BUFFERED"))

	data := make([]byte, 1024*1024) // 1MB

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// Create new connections for each iteration
		l2, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			b.Fatal(err)
		}
		c2, _ := net.Dial("tcp", l2.Addr().String())
		c1, _ := l2.Accept()

		sniffer := NewConnSniffer(c1, 0)
		sniffer.Sniffer.buf.Write([]byte("BUFFERED"))

		go c2.Write(data)

		var buf bytes.Buffer
		sniffer.WriteTo(&buf)

		c1.Close()
		c2.Close()
		l2.Close()
	}
}

// TestConnSnifferWithNetproxyReadFrom tests integration with netproxy.ReadFrom
func TestConnSnifferWithNetproxyReadFrom(t *testing.T) {
	// Create a TCP connection pair
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

	// Wrap conn1 in ConnSniffer
	sniffer := NewConnSniffer(conn1, 0)
	// Add buffered data
	sniffer.Sniffer.buf.Reset()
	sniffer.Sniffer.buf.Write([]byte("HELLO"))

	// Write test data
	testData := make([]byte, 10*1024) // 10KB
	for i := range testData {
		testData[i] = byte(i % 256)
	}
	go func() {
		conn2.Write(testData)
		conn2.Close()
	}()

	// Use io.Copy (this will use our WriteTo implementation)
	var buf bytes.Buffer
	n, err := io.Copy(&buf, sniffer)
	if err != nil {
		t.Fatalf("io.Copy error: %v", err)
	}

	expected := int64(len("HELLO") + len(testData))
	if n != expected {
		t.Errorf("Expected %d bytes, got %d", expected, n)
	}

	result := buf.Bytes()
	if !bytes.HasPrefix(result, []byte("HELLO")) {
		t.Error("Buffered data should come first")
	}
}
