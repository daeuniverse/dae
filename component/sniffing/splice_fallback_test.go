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

// mockConn implements net.Conn for testing.
// It intentionally does not implement SyscallConn so that WriteTo/ReadFrom
// takes the io.Copy code path rather than any syscall shortcut.
type mockConn struct {
	net.Conn // nil — only the methods below are used
	data     []byte
	read     int
	delay    time.Duration
}

func (m *mockConn) Read(b []byte) (n int, err error) {
	if m.delay > 0 {
		time.Sleep(m.delay)
	}
	if m.read >= len(m.data) {
		return 0, io.EOF
	}
	n = copy(b, m.data[m.read:])
	m.read += n
	return n, nil
}

func (m *mockConn) Write(b []byte) (n int, err error)    { return len(b), nil }
func (m *mockConn) Close() error                         { return nil }
func (m *mockConn) RemoteAddr() net.Addr                 { return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345} }
func (m *mockConn) LocalAddr() net.Addr                  { return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080} }
func (m *mockConn) SetDeadline(_ time.Time) error        { return nil }
func (m *mockConn) SetReadDeadline(_ time.Time) error    { return nil }
func (m *mockConn) SetWriteDeadline(_ time.Time) error   { return nil }

// TestWriteToDataIntegrity verifies that WriteTo transfers all bytes correctly
// when the underlying connection does not support SyscallConn (the io.Copy path).
// splice(2) is never attempted socket→socket; this test documents that fact.
func TestWriteToDataIntegrity(t *testing.T) {
	data := bytes.Repeat([]byte("test data for relay\n"), 100)
	mock := &mockConn{data: data}

	sniffer := NewConnSniffer(mock, 1*time.Second)

	var buf bytes.Buffer
	n, err := io.Copy(&buf, sniffer)

	if err != nil && err != io.EOF {
		t.Errorf("unexpected error: %v", err)
	}
	if int(n) != len(data) {
		t.Errorf("expected %d bytes, got %d", len(data), n)
	}
	if !bytes.Equal(buf.Bytes(), data) {
		t.Error("data corruption detected")
	}
}

// TestWriteToFlushesPrebufferedData verifies that data already buffered during
// protocol sniffing is flushed to the writer before the stream continues.
func TestWriteToFlushesPrebufferedData(t *testing.T) {
	streamData := []byte("STREAM_PAYLOAD")
	mock := &mockConn{data: streamData}
	sniffer := NewConnSniffer(mock, 1*time.Second)

	// Simulate bytes already consumed into the sniff buffer (e.g. TLS ClientHello).
	prebuf := []byte("PRE_BUFFERED")
	sniffer.Sniffer.buf.Write(prebuf)

	var buf bytes.Buffer
	n, err := io.Copy(&buf, sniffer)
	if err != nil && err != io.EOF {
		t.Errorf("unexpected error: %v", err)
	}

	expected := append(prebuf, streamData...)
	if int(n) != len(expected) {
		t.Errorf("expected %d bytes, got %d", len(expected), n)
	}
	if !bytes.Equal(buf.Bytes(), expected) {
		t.Errorf("data mismatch: got %q, want %q", buf.Bytes(), expected)
	}
}

// TestReadFromForwardsAllBytes verifies that ReadFrom delivers every byte to
// the underlying connection.
func TestReadFromForwardsAllBytes(t *testing.T) {
	var written []byte
	wMock := &writeCaptureMock{}
	sniffer := NewConnSniffer(wMock, 1*time.Second)

	payload := bytes.Repeat([]byte("payload"), 200)
	n, err := sniffer.ReadFrom(bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("ReadFrom error: %v", err)
	}
	written = wMock.written
	if int(n) != len(payload) {
		t.Errorf("expected %d bytes written, got %d", len(payload), n)
	}
	if !bytes.Equal(written, payload) {
		t.Error("data mismatch in ReadFrom output")
	}
}

// TestSniffTcpWithFtpPayloadPreservesData verifies that non-TLS/HTTP payloads
// (e.g. FTP control channel banners/commands) are not recognized as domains
// but are still fully preserved for relay after sniffing.
func TestSniffTcpWithFtpPayloadPreservesData(t *testing.T) {
	ftpPayload := []byte("220 FTP Service Ready\r\nUSER anonymous\r\nPASS guest@example.com\r\n")
	mock := &mockConn{data: ftpPayload}
	sniffer := NewConnSniffer(mock, 200*time.Millisecond)

	domain, err := sniffer.SniffTcp()
	if err != nil && !IsSniffingError(err) {
		t.Fatalf("unexpected sniff error: %v", err)
	}
	if domain != "" {
		t.Fatalf("expected empty domain for FTP payload, got %q", domain)
	}

	var buf bytes.Buffer
	n, copyErr := io.Copy(&buf, sniffer)
	if copyErr != nil && copyErr != io.EOF {
		t.Fatalf("unexpected relay error: %v", copyErr)
	}
	if int(n) != len(ftpPayload) {
		t.Fatalf("expected %d bytes, got %d", len(ftpPayload), n)
	}
	if !bytes.Equal(buf.Bytes(), ftpPayload) {
		t.Fatalf("payload mismatch: got %q, want %q", buf.Bytes(), ftpPayload)
	}
}

// writeCaptureMock is a net.Conn whose Write method captures all written bytes.
type writeCaptureMock struct {
	net.Conn
	written []byte
}

func (w *writeCaptureMock) Write(b []byte) (int, error) {
	w.written = append(w.written, b...)
	return len(b), nil
}
func (w *writeCaptureMock) Close() error                        { return nil }
func (w *writeCaptureMock) RemoteAddr() net.Addr                { return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9999} }
func (w *writeCaptureMock) LocalAddr() net.Addr                 { return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080} }
func (w *writeCaptureMock) SetDeadline(_ time.Time) error       { return nil }
func (w *writeCaptureMock) SetReadDeadline(_ time.Time) error   { return nil }
func (w *writeCaptureMock) SetWriteDeadline(_ time.Time) error  { return nil }
