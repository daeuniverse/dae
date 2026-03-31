/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@daeuniverse.org>
 */

package shadowsocks

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/protocol"
)

// mockConn implements netproxy.Conn for testing
type mockConn struct {
	readBuf  bytes.Buffer
	writeBuf bytes.Buffer
}

func fillRandomB(b *testing.B, p []byte) {
	b.Helper()
	_, err := rand.Read(p)
	if err != nil {
		b.Fatalf("rand.Read failed: %v", err)
	}
}

func (m *mockConn) Read(b []byte) (n int, err error) {
	return m.readBuf.Read(b)
}

func (m *mockConn) Write(b []byte) (n int, err error) {
	return m.writeBuf.Write(b)
}

func (m *mockConn) Close() error                       { return nil }
func (m *mockConn) LocalAddr() net.Addr                { return nil }
func (m *mockConn) RemoteAddr() net.Addr               { return nil }
func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

// BenchmarkTCPEncryptFirstWrite benchmarks the first write (with cipher creation)
func BenchmarkTCPEncryptFirstWrite(b *testing.B) {
	conf := ciphers.AeadCiphersConf["aes-256-gcm"]
	masterKey := make([]byte, conf.KeyLen)
	fillRandomB(b, masterKey)

	plaintext := make([]byte, 1024)

	metadata := protocol.Metadata{
		Cipher:   "aes-256-gcm",
		IsClient: true,
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		mock := &mockConn{}
		conn, err := NewTCPConn(mock, metadata, masterKey, nil)
		if err != nil {
			b.Fatal(err)
		}

		_, err = conn.Write(plaintext)
		if err != nil {
			b.Fatal(err)
		}

		_ = conn.Close()
	}
}

// BenchmarkTCPEncryptSubsequentWrites benchmarks subsequent writes (cipher reused)
func BenchmarkTCPEncryptSubsequentWrites(b *testing.B) {
	conf := ciphers.AeadCiphersConf["aes-256-gcm"]
	masterKey := make([]byte, conf.KeyLen)
	fillRandomB(b, masterKey)

	plaintext := make([]byte, 1024)

	metadata := protocol.Metadata{
		Cipher:   "aes-256-gcm",
		IsClient: true,
	}

	mock := &mockConn{}
	conn, err := NewTCPConn(mock, metadata, masterKey, nil)
	if err != nil {
		b.Fatal(err)
	}

	// First write to initialize cipher
	_, err = conn.Write(plaintext)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err = conn.Write(plaintext)
		if err != nil {
			b.Fatal(err)
		}
	}

	_ = conn.Close()
}

// BenchmarkTCPDecryptFirstRead benchmarks the first read (with cipher creation)
func BenchmarkTCPDecryptFirstRead(b *testing.B) {
	conf := ciphers.AeadCiphersConf["aes-256-gcm"]
	masterKey := make([]byte, conf.KeyLen)
	fillRandomB(b, masterKey)

	plaintext := make([]byte, 1024)

	metadataClient := protocol.Metadata{
		Cipher:   "aes-256-gcm",
		IsClient: true,
	}

	metadataServer := protocol.Metadata{
		Cipher:   "aes-256-gcm",
		IsClient: false,
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Create client and write encrypted data
		mockClient := &mockConn{}
		client, err := NewTCPConn(mockClient, metadataClient, masterKey, nil)
		if err != nil {
			b.Fatal(err)
		}

		_, err = client.Write(plaintext)
		if err != nil {
			b.Fatal(err)
		}

		// Create server and read encrypted data
		mockServer := &mockConn{readBuf: mockClient.writeBuf}
		server, err := NewTCPConn(mockServer, metadataServer, masterKey, nil)
		if err != nil {
			b.Fatal(err)
		}

		decrypted := make([]byte, len(plaintext))
		_, err = io.ReadFull(server, decrypted)
		if err != nil {
			b.Fatal(err)
		}

		_ = client.Close()
		_ = server.Close()
	}
}

// BenchmarkTCPDecryptSubsequentReads benchmarks subsequent reads (cipher reused)
func BenchmarkTCPDecryptSubsequentReads(b *testing.B) {
	conf := ciphers.AeadCiphersConf["aes-256-gcm"]
	masterKey := make([]byte, conf.KeyLen)
	fillRandomB(b, masterKey)

	plaintext := make([]byte, 1024)

	metadataClient := protocol.Metadata{
		Cipher:   "aes-256-gcm",
		IsClient: true,
	}

	metadataServer := protocol.Metadata{
		Cipher:   "aes-256-gcm",
		IsClient: false,
	}

	// Setup client and write multiple chunks
	mockClient := &mockConn{}
	client, err := NewTCPConn(mockClient, metadataClient, masterKey, nil)
	if err != nil {
		b.Fatal(err)
	}

	// Write 100 chunks
	for i := 0; i < 100; i++ {
		_, err = client.Write(plaintext)
		if err != nil {
			b.Fatal(err)
		}
	}

	// Setup server
	mockServer := &mockConn{readBuf: mockClient.writeBuf}
	server, err := NewTCPConn(mockServer, metadataServer, masterKey, nil)
	if err != nil {
		b.Fatal(err)
	}

	// First read to initialize cipher
	decrypted := make([]byte, len(plaintext))
	_, err = io.ReadFull(server, decrypted)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err = io.ReadFull(server, decrypted)
		if err != nil {
			b.Fatal(err)
		}
	}

	_ = client.Close()
	_ = server.Close()
}

// BenchmarkTCPSmallChunks benchmarks encryption of small chunks (< 16KB)
func BenchmarkTCPSmallChunks_64B(b *testing.B)  { benchmarkTCPChunkSize(b, 64) }
func BenchmarkTCPSmallChunks_512B(b *testing.B) { benchmarkTCPChunkSize(b, 512) }
func BenchmarkTCPSmallChunks_1KB(b *testing.B)  { benchmarkTCPChunkSize(b, 1024) }
func BenchmarkTCPSmallChunks_4KB(b *testing.B)  { benchmarkTCPChunkSize(b, 4096) }
func BenchmarkTCPSmallChunks_16KB(b *testing.B) { benchmarkTCPChunkSize(b, 16384) }

func benchmarkTCPChunkSize(b *testing.B, size int) {
	conf := ciphers.AeadCiphersConf["aes-256-gcm"]
	masterKey := make([]byte, conf.KeyLen)
	fillRandomB(b, masterKey)

	plaintext := make([]byte, size)

	metadata := protocol.Metadata{
		Cipher:   "aes-256-gcm",
		IsClient: true,
	}

	mock := &mockConn{}
	conn, err := NewTCPConn(mock, metadata, masterKey, nil)
	if err != nil {
		b.Fatal(err)
	}

	// First write to initialize cipher
	_, err = conn.Write(plaintext)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err = conn.Write(plaintext)
		if err != nil {
			b.Fatal(err)
		}
	}

	_ = conn.Close()
}

// BenchmarkTCPLargeStream benchmarks encryption of large stream
func BenchmarkTCPLargeStream(b *testing.B) {
	conf := ciphers.AeadCiphersConf["aes-256-gcm"]
	masterKey := make([]byte, conf.KeyLen)
	fillRandomB(b, masterKey)

	// 1MB stream
	totalSize := 1024 * 1024
	chunkSize := 16384
	chunks := totalSize / chunkSize

	plaintext := make([]byte, chunkSize)

	metadata := protocol.Metadata{
		Cipher:   "aes-256-gcm",
		IsClient: true,
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		mock := &mockConn{}
		conn, err := NewTCPConn(mock, metadata, masterKey, nil)
		if err != nil {
			b.Fatal(err)
		}

		for j := 0; j < chunks; j++ {
			_, err = conn.Write(plaintext)
			if err != nil {
				b.Fatal(err)
			}
		}

		_ = conn.Close()
	}
}

// BenchmarkTCPMutexOverhead benchmarks the mutex overhead
func BenchmarkTCPMutexOverhead(b *testing.B) {
	conf := ciphers.AeadCiphersConf["aes-256-gcm"]
	masterKey := make([]byte, conf.KeyLen)
	fillRandomB(b, masterKey)

	plaintext := make([]byte, 1024)

	metadata := protocol.Metadata{
		Cipher:   "aes-256-gcm",
		IsClient: true,
	}

	mock := &mockConn{}
	conn, err := NewTCPConn(mock, metadata, masterKey, nil)
	if err != nil {
		b.Fatal(err)
	}

	// Initialize cipher
	_, err = conn.Write(plaintext)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// This will acquire writeMutex
		_, err = conn.Write(plaintext)
		if err != nil {
			b.Fatal(err)
		}
	}

	_ = conn.Close()
}

// BenchmarkTCPPoolOverhead benchmarks the pool allocation overhead
func BenchmarkTCPPoolOverhead(b *testing.B) {
	conf := ciphers.AeadCiphersConf["aes-256-gcm"]
	masterKey := make([]byte, conf.KeyLen)
	fillRandomB(b, masterKey)

	plaintext := make([]byte, 1024)

	metadata := protocol.Metadata{
		Cipher:   "aes-256-gcm",
		IsClient: true,
	}

	mock := &mockConn{}
	conn, err := NewTCPConn(mock, metadata, masterKey, nil)
	if err != nil {
		b.Fatal(err)
	}

	// Initialize cipher
	_, err = conn.Write(plaintext)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Each write allocates from pool
		_, err = conn.Write(plaintext)
		if err != nil {
			b.Fatal(err)
		}
	}

	_ = conn.Close()
}

// Compare first vs subsequent operations
func BenchmarkTCPFirstVsSubsequent(b *testing.B) {
	b.Run("FirstWrite", func(b *testing.B) {
		conf := ciphers.AeadCiphersConf["aes-256-gcm"]
		masterKey := make([]byte, conf.KeyLen)
		plaintext := make([]byte, 1024)

		metadata := protocol.Metadata{
			Cipher:   "aes-256-gcm",
			IsClient: true,
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			mock := &mockConn{}
			conn, _ := NewTCPConn(mock, metadata, masterKey, nil)
			_, _ = conn.Write(plaintext)
			_ = conn.Close()
		}
	})

	b.Run("SubsequentWrite", func(b *testing.B) {
		conf := ciphers.AeadCiphersConf["aes-256-gcm"]
		masterKey := make([]byte, conf.KeyLen)
		plaintext := make([]byte, 1024)

		metadata := protocol.Metadata{
			Cipher:   "aes-256-gcm",
			IsClient: true,
		}

		mock := &mockConn{}
		conn, _ := NewTCPConn(mock, metadata, masterKey, nil)
		_, _ = conn.Write(plaintext) // Initialize

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = conn.Write(plaintext)
		}
		_ = conn.Close()
	})
}
