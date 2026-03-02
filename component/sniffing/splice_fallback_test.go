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

// mockConn implements net.Conn for testing splice-unavailable fallback path.
// It intentionally does not implement SyscallConn.
type mockConn struct {
	net.Conn
	data  []byte
	read  int
	delay time.Duration
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

func (m *mockConn) Write(b []byte) (n int, err error) {
	return len(b), nil
}

func (m *mockConn) Close() error {
	return nil
}

func (m *mockConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 21}
}

// TestSpliceUnavailableFallbackTransparency tests that splice-unavailable path doesn't break connection.
func TestSpliceUnavailableFallbackTransparency(t *testing.T) {
	// Create a mock connection with data
	data := bytes.Repeat([]byte("test data for splice fallback\n"), 100)
	mock := &mockConn{data: data}

	// Create sniffer
	sniffer := NewConnSniffer(mock, 1*time.Second)

	// Write to buffer
	var buf bytes.Buffer
	n, err := io.Copy(&buf, sniffer)

	// Verify data was transferred completely when splice is unavailable.
	if err != nil && err != io.EOF {
		t.Errorf("unexpected error: %v", err)
	}

	if int(n) != len(data) {
		t.Errorf("expected %d bytes, got %d", len(data), n)
	}

	// Verify data integrity
	if !bytes.Equal(buf.Bytes(), data) {
		t.Error("data corruption detected")
	}
}

// TestSpliceFailedFlagState tests spliceFailed flag access without forcing splice path.
func TestSpliceFailedFlagState(t *testing.T) {
	mock := &mockConn{data: []byte("test")}
	sniffer := NewConnSniffer(mock, 1*time.Second)

	// Initially splice should not be marked as failed
	if sniffer.spliceFailed.Load() {
		t.Error("splice should not be marked as failed initially")
	}

	// Perform one copy through the splice-unavailable path.
	var buf bytes.Buffer
	io.Copy(&buf, sniffer)

	// This test intentionally does not force a splice failure; it only verifies
	// flag state can be read safely after data transfer.
	_ = sniffer.spliceFailed.Load()
}
