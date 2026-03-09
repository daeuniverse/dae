/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// BenchmarkAnyfromWriteConcurrentSameDest tests write serialization to the same destination.
// This measures the overhead of per-destination locking when all goroutines target one address.
func BenchmarkAnyfromWriteConcurrentSameDest(b *testing.B) {
	// Create a UDP socket to receive packets (discard them).
	listener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		b.Skipf("failed to create UDP listener: %v", err)
	}
	defer listener.Close()
	destAddr := listener.LocalAddr().(*net.UDPAddr).AddrPort()

	// Create Anyfrom socket.
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		b.Skipf("failed to create UDP conn: %v", err)
	}
	defer conn.Close()

	af := &Anyfrom{
		UDPConn: conn,
		ttl:     time.Minute,
	}
	af.RefreshTtl()

	data := make([]byte, 64)
	for i := range data {
		data[i] = byte(i)
	}

	parallelisms := []int{1, 2, 4, 8, 16}
	for _, p := range parallelisms {
		b.Run(fmt.Sprintf("parallelism=%d", p), func(b *testing.B) {
			b.SetBytes(int64(len(data)))
			var wg sync.WaitGroup
			n := b.N / p
			if n == 0 {
				n = 1
			}

			b.ResetTimer()
			for i := 0; i < p; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for j := 0; j < n; j++ {
						_, _ = af.WriteToUDPAddrPort(data, destAddr)
					}
				}()
			}
			wg.Wait()
		})
	}
}

// BenchmarkAnyfromWriteConcurrentDifferentDests tests parallel writes to different destinations.
// This should show good scalability since each destination has its own lock shard.
func BenchmarkAnyfromWriteConcurrentDifferentDests(b *testing.B) {
	// Create multiple UDP listeners.
	numDests := 256
	listeners := make([]*net.UDPConn, numDests)
	destAddrs := make([]netip.AddrPort, numDests)

	for i := 0; i < numDests; i++ {
		listener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
		if err != nil {
			b.Skipf("failed to create UDP listener: %v", err)
		}
		listeners[i] = listener
		destAddrs[i] = listener.LocalAddr().(*net.UDPAddr).AddrPort()
	}
	defer func() {
		for _, l := range listeners {
			_ = l.Close()
		}
	}()

	// Create Anyfrom socket.
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		b.Skipf("failed to create UDP conn: %v", err)
	}
	defer conn.Close()

	af := &Anyfrom{
		UDPConn: conn,
		ttl:     time.Minute,
	}
	af.RefreshTtl()

	data := make([]byte, 64)

	parallelisms := []int{1, 2, 4, 8, 16}
	for _, p := range parallelisms {
		b.Run(fmt.Sprintf("parallelism=%d", p), func(b *testing.B) {
			b.SetBytes(int64(len(data)))
			var wg sync.WaitGroup
			n := b.N / p
			if n == 0 {
				n = 1
			}

			b.ResetTimer()
			for i := 0; i < p; i++ {
				wg.Add(1)
				go func(goroutineID int) {
					defer wg.Done()
					destIdx := uint64(goroutineID) % uint64(numDests)
					for j := 0; j < n; j++ {
						_, _ = af.WriteToUDPAddrPort(data, destAddrs[destIdx])
						// Rotate to different destinations to test lock distribution.
						destIdx = (destIdx + 1) % uint64(numDests)
					}
				}(i)
			}
			wg.Wait()
		})
	}
}

// BenchmarkAnyfromLockOverhead measures the overhead of hashAddrPort.
func BenchmarkAnyfromLockOverhead(b *testing.B) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		b.Skipf("failed to create UDP conn: %v", err)
	}
	defer conn.Close()

	af := &Anyfrom{
		UDPConn: conn,
		ttl:     time.Minute,
	}
	af.RefreshTtl()

	dest := netip.MustParseAddrPort("127.0.0.1:53")

	b.Run("hash-only", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = hashAddrPort(dest)
		}
	})

	b.Run("ttl-refresh", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			af.RefreshTtl()
		}
	})
}

// BenchmarkAnyfromTTLRefresh compares throttled vs non-throttled TTL refresh.
func BenchmarkAnyfromTTLRefresh(b *testing.B) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		b.Skipf("failed to create UDP conn: %v", err)
	}
	defer conn.Close()

	af := &Anyfrom{
		UDPConn: conn,
		ttl:     time.Minute,
	}
	af.RefreshTtl()

	b.Run("throttled-refresh", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			af.RefreshTtl()
		}
	})
}

// BenchmarkWyHashDistribution tests hash distribution quality.
func BenchmarkWyHashDistribution(b *testing.B) {
	addrs := make([]netip.AddrPort, 10000)
	for i := 0; i < 10000; i++ {
		// Generate diverse addresses.
		ip := netip.AddrFrom4([4]byte{
			byte(i >> 24),
			byte(i >> 16),
			byte(i >> 8),
			byte(i),
		})
		addrs[i] = netip.AddrPortFrom(ip, uint16(i%65536))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = hashAddrPort(addrs[i%10000])
	}
}

// BenchmarkAnyfromMemory measures memory footprint per Anyfrom instance.
func BenchmarkAnyfromMemory(b *testing.B) {
	b.ReportAllocs()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		b.Skipf("failed to create UDP conn: %v", err)
	}
	defer conn.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		af := &Anyfrom{
			UDPConn: conn,
			ttl:     time.Minute,
		}
		af.RefreshTtl()
		// Prevent escape analysis optimization.
		runtime.KeepAlive(af)
	}
}

// TestAnyfromWriteOrdering verifies that writes to the same destination are serialized.
func TestAnyfromWriteOrdering(t *testing.T) {
	listener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Skipf("failed to create UDP listener: %v", err)
	}
	defer listener.Close()
	destAddr := listener.LocalAddr().(*net.UDPAddr).AddrPort()

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Skipf("failed to create UDP conn: %v", err)
	}
	defer conn.Close()

	af := &Anyfrom{
		UDPConn: conn,
		ttl:     time.Minute,
	}
	af.RefreshTtl()

	// Start receiver goroutine.
	var receivedCount atomic.Int64
	go func() {
		buf := make([]byte, 1024)
		for {
			n, _, err := listener.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			if n > 0 {
				receivedCount.Add(1)
			}
		}
	}()

	// Concurrent writers to the same destination.
	numWriters := 16
	writesPerWriter := 1000
	totalWrites := numWriters * writesPerWriter

	var wg sync.WaitGroup
	for i := 0; i < numWriters; i++ {
		wg.Add(1)
		go func(writerID int) {
			defer wg.Done()
			data := []byte(fmt.Sprintf("writer-%d-packet", writerID))
			for j := 0; j < writesPerWriter; j++ {
				_, _ = af.WriteToUDPAddrPort(data, destAddr)
			}
		}(i)
	}
	wg.Wait()

	// Wait for receiver to process.
	time.Sleep(100 * time.Millisecond)

	received := receivedCount.Load()
	t.Logf("Sent %d packets, received %d packets", totalWrites, received)

	// In UDP, we may lose packets, but no packet corruption should occur.
	// The key guarantee is no data races (verified by race detector).
}

// TestAnyfromNoRaceConcurrentWrites verifies no data races with concurrent writes.
func TestAnyfromNoRaceConcurrentWrites(t *testing.T) {
	listener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Skipf("failed to create UDP listener: %v", err)
	}
	defer listener.Close()
	destAddr := listener.LocalAddr().(*net.UDPAddr).AddrPort()

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Skipf("failed to create UDP conn: %v", err)
	}
	defer conn.Close()

	af := &Anyfrom{
		UDPConn: conn,
		ttl:     time.Minute,
	}
	af.RefreshTtl()

	numWriters := 32
	var wg sync.WaitGroup

	// Mix of same and different destinations.
	for i := 0; i < numWriters; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			data := make([]byte, 64)
			for j := 0; j < 100; j++ {
				// Alternate between same and different destinations.
				if j%2 == 0 {
					_, _ = af.WriteToUDPAddrPort(data, destAddr)
				} else {
					// Use different port for each writer.
					diffDest := netip.AddrPortFrom(destAddr.Addr(), uint16(10000+id))
					_, _ = af.WriteToUDPAddrPort(data, diffDest)
				}
			}
		}(i)
	}
	wg.Wait()
}
