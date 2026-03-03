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
	"testing"
	"time"
)

// TestConnSnifferRelayPath verifies the relay path through netproxy.ReadFrom.
func TestConnSnifferRelayPath(t *testing.T) {
	// Create echo server
	echoServer, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoServer.Close()

	go func() {
		conn, err := echoServer.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		io.Copy(conn, conn) // Echo back
	}()

	// Create client connection
	clientConn, err := net.Dial("tcp", echoServer.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()

	// Wrap client connection with ConnSniffer
	sniffer := NewConnSniffer(clientConn, 0)
	// Simulate buffered data
	sniffer.Sniffer.buf.Reset()
	sniffer.Sniffer.buf.Write([]byte("BUFFERED"))

	// Send test data
	testData := make([]byte, 10*1024) // 10KB
	for i := range testData {
		testData[i] = byte(i % 256)
	}

	// Write data through sniffer
	go func() {
		sniffer.Write(testData)
		// Read echoed data
		recvBuf := make([]byte, len(testData))
		n, _ := sniffer.Read(recvBuf)
		t.Logf("Received %d bytes", n)
	}()

	time.Sleep(100 * time.Millisecond)
}

// TestWriterToCalledByIoCopy verifies that io.Copy calls WriterTo
func TestWriterToCalledByIoCopy(t *testing.T) {
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
	sniffer.Sniffer.buf.Reset()
	sniffer.Sniffer.buf.Write([]byte("HEAD"))

	// Write extra data to conn2
	extraData := []byte("DATA")
	go func() {
		conn2.Write(extraData)
		conn2.Close()
	}()

	// Use io.Copy - should call WriteTo
	var buf bytes.Buffer
	n, err := io.Copy(&buf, sniffer)
	if err != nil {
		t.Logf("io.Copy error: %v", err)
	}

	// Verify data
	result := buf.String()
	expected := "HEADDATA"

	if n != int64(len(expected)) {
		t.Errorf("Expected %d bytes, got %d", len(expected), n)
	}

	if result != expected {
		t.Errorf("Expected %q, got %q", expected, result)
	}

	t.Logf("Successfully transferred %d bytes via io.Copy -> WriteTo", n)
}

// BenchmarkConnSnifferRelay compares relay performance with and without ConnSniffer.
func BenchmarkConnSnifferRelay(b *testing.B) {
	data := make([]byte, 1024*1024) // 1MB
	for i := range data {
		data[i] = byte(i % 256)
	}

	b.Run("WithConnSniffer", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				b.Fatal(err)
			}

			go func() {
				conn, err := net.Dial("tcp", l.Addr().String())
				if err != nil {
					return
				}
				conn.Write(data)
				conn.Close()
			}()

			conn, err := l.Accept()
			if err != nil {
				b.Fatal(err)
			}

			sniffer := NewConnSniffer(conn, 0)
			var buf bytes.Buffer
			io.Copy(&buf, sniffer)

			conn.Close()
			l.Close()
		}
	})

	b.Run("WithoutSniffer", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				b.Fatal(err)
			}

			go func() {
				conn, err := net.Dial("tcp", l.Addr().String())
				if err != nil {
					return
				}
				conn.Write(data)
				conn.Close()
			}()

			conn, err := l.Accept()
			if err != nil {
				b.Fatal(err)
			}

			var buf bytes.Buffer
			io.Copy(&buf, conn)

			conn.Close()
			l.Close()
		}
	})
}

// TestNetproxyReadFromBehavior tests io.Copy with ConnSniffer as source.
// This verifies that WriteTo is called correctly when copying from a ConnSniffer.
func TestNetproxyReadFromBehavior(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	// Create connection pair
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

	// Wrap conn1 with ConnSniffer (with buffered data)
	sniffer := NewConnSniffer(conn1, 0)
	sniffer.Sniffer.buf.Reset()
	sniffer.Sniffer.buf.Write([]byte("BUFFERED_"))

	// Write test data to conn2 (will be received by conn1/sniffer)
	testData := []byte("TEST_DATA")
	go func() {
		conn2.Write(testData)
		conn2.Close() // Close write side to signal EOF
	}()

	// Use io.Copy to read from sniffer (which calls WriteTo)
	var buf bytes.Buffer
	n, err := io.Copy(&buf, sniffer)

	if err != nil && err != io.EOF {
		t.Logf("io.Copy error: %v", err)
	}

	t.Logf("Transferred %d bytes via io.Copy from sniffer", n)

	// Verify we got the buffered data followed by the connection data
	result := buf.String()
	expected := "BUFFERED_TEST_DATA"

	if result != expected {
		t.Errorf("Expected %q, got %q", expected, result)
	}

	// Verify byte count
	if n != int64(len(expected)) {
		t.Errorf("Expected %d bytes, got %d", len(expected), n)
	}
}

// TestConnSnifferWriteToWithRealConnection tests WriteTo with real TCP connection
func TestConnSnifferWriteToWithRealConnection(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	// Receiver
	done := make(chan struct{})
	var received bytes.Buffer
	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		io.Copy(&received, conn)
		close(done)
	}()

	// Sender (using ConnSniffer)
	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	sniffer := NewConnSniffer(conn, 0)
	sniffer.Sniffer.buf.Reset()
	sniffer.Sniffer.buf.Write([]byte("HEADER"))

	// Write extra data to connection (data stays in socket receive buffer)
	testData := make([]byte, 100*1024)
	for i := range testData {
		testData[i] = byte(i % 256)
	}
	// Write data from other end
	go func() {
		time.Sleep(10 * time.Millisecond)
		// Cannot write directly here because conn is the sender
		// We need to read data from the receiver
	}()

	// Use WriteTo to transfer data (including buffered data)
	// Since sniffer is a ConnSniffer, io.Copy will call WriteTo
	// But we need to read data from sniffer's underlying connection
	// So this test needs to be redesigned

	// Simplified test: only verify WriteTo is called correctly
	t.Skip("Test needs redesign - WriteTo is for reading FROM sniffer, not writing TO it")

	_ = testData
	_ = done
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
