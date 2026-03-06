/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@daeuniverse.org>
 */

package control

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/daeuniverse/outbound/netproxy"
	"golang.org/x/sys/unix"
)

// Test different buffer sizes with realistic MTU-constrained data
func BenchmarkRelayBufferSize_Small(b *testing.B) {
	// Small packets: 500 bytes (API requests)
	benchRelayWithSize(b, 500, "500B")
}

func BenchmarkRelayBufferSize_MTU(b *testing.B) {
	// MTU-sized packets: 1460 bytes
	benchRelayWithSize(b, 1460, "1460B")
}

func BenchmarkRelayBufferSize_Medium(b *testing.B) {
	// Medium: 16KB (11 MTU packets)
	benchRelayWithSize(b, 16<<10, "16KB")
}

func BenchmarkRelayBufferSize_Large(b *testing.B) {
	// Large: 64KB (44 MTU packets)
	benchRelayWithSize(b, 64<<10, "64KB")
}

func BenchmarkRelayBufferSize_VeryLarge(b *testing.B) {
	// Very large: 1MB (698 MTU packets)
	benchRelayWithSize(b, 1<<20, "1MB")
}

func benchRelayWithSize(b *testing.B, size int, name string) {
	b.Run("32KB-buffer/"+name, func(b *testing.B) {
		benchRelayBufferSize(b, size, 32<<10)
	})
	b.Run("64KB-buffer/"+name, func(b *testing.B) {
		benchRelayBufferSize(b, size, 64<<10)
	})
	b.Run("128KB-buffer/"+name, func(b *testing.B) {
		benchRelayBufferSize(b, size, 128<<10)
	})
	b.Run("256KB-buffer/"+name, func(b *testing.B) {
		benchRelayBufferSize(b, size, 256<<10)
	})
}

func benchRelayBufferSize(b *testing.B, payloadSize int, bufferSize int) {
	payload := bytes.Repeat([]byte{0x7f}, payloadSize)

	b.ResetTimer()
	b.SetBytes(int64(payloadSize))
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		srcWriter, srcRelay := unixConnPair(b)
		dstRelay, dstReader := unixConnPair(b)

		var wg sync.WaitGroup
		wg.Add(2)

		// Writer goroutine
		go func() {
			defer wg.Done()
			srcWriter.Write(payload)
			srcWriter.CloseWrite()
		}()

		// Reader goroutine
		go func() {
			defer wg.Done()
			io.Copy(io.Discard, dstReader)
		}()

		// Relay with specific buffer size
		buf := make([]byte, bufferSize)
		io.CopyBuffer(netproxy.Conn(dstRelay), netproxy.Conn(srcRelay), buf)
		dstRelay.CloseWrite()

		wg.Wait()
		closeUnixPair(srcWriter, srcRelay)
		closeUnixPair(dstRelay, dstReader)
	}
}

// Benchmark readv/writev (vectorised I/O)
func BenchmarkRelayVectorised(b *testing.B) {
	sizes := []int{500, 1460, 16 << 10, 64 << 10, 1 << 20}
	for _, size := range sizes {
		size := size
		b.Run(fmt.Sprintf("Vectorised/%dB", size), func(b *testing.B) {
			benchRelayVectorised(b, size)
		})
		b.Run(fmt.Sprintf("Standard/%dB", size), func(b *testing.B) {
			benchRelayStandard(b, size)
		})
	}
}

func benchRelayVectorised(b *testing.B, payloadSize int) {
	payload := bytes.Repeat([]byte{0x7f}, payloadSize)

	b.ResetTimer()
	b.SetBytes(int64(payloadSize))
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		srcWriter, srcRelay := unixConnPair(b)
		dstRelay, dstReader := unixConnPair(b)

		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			srcWriter.Write(payload)
			srcWriter.CloseWrite()
		}()

		go func() {
			defer wg.Done()
			io.Copy(io.Discard, dstReader)
		}()

		// Vectorised relay
		relayVectorised(dstRelay, srcRelay)
		dstRelay.CloseWrite()

		wg.Wait()
		closeUnixPair(srcWriter, srcRelay)
		closeUnixPair(dstRelay, dstReader)
	}
}

func benchRelayStandard(b *testing.B, payloadSize int) {
	payload := bytes.Repeat([]byte{0x7f}, payloadSize)

	b.ResetTimer()
	b.SetBytes(int64(payloadSize))
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		srcWriter, srcRelay := unixConnPair(b)
		dstRelay, dstReader := unixConnPair(b)

		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			srcWriter.Write(payload)
			srcWriter.CloseWrite()
		}()

		go func() {
			defer wg.Done()
			io.Copy(io.Discard, dstReader)
		}()

		// Standard relay
		io.Copy(dstRelay, srcRelay)
		dstRelay.CloseWrite()

		wg.Wait()
		closeUnixPair(srcWriter, srcRelay)
		closeUnixPair(dstRelay, dstReader)
	}
}

func closeUnixPair(conns ...*net.UnixConn) {
	for _, conn := range conns {
		if conn != nil {
			_ = conn.Close()
		}
	}
}

// Vectorised I/O implementation
func relayVectorised(dst, src *net.UnixConn) (int64, error) {
	// Use multiple buffers to batch reads
	bufs := make([][]byte, 8)
	for i := range bufs {
		bufs[i] = make([]byte, 32<<10) // 32KB each
	}

	var total int64
	for {
		// Try to read into multiple buffers at once
		n, err := readvAll(src, bufs)
		if n == 0 {
			if err == io.EOF {
				return total, nil
			}
			return total, err
		}

		// Write all the data we read
		written := int64(0)
		for i := 0; i < len(bufs) && written < n; i++ {
			bufLen := int64(len(bufs[i]))
			if written+bufLen > n {
				bufLen = n - written
			}
			if bufLen > 0 {
				nw, err := dst.Write(bufs[i][:bufLen])
				written += int64(nw)
				if err != nil {
					return total + written, err
				}
			}
		}
		total += n

		if err == io.EOF {
			return total, nil
		}
		if err != nil {
			return total, err
		}
	}
}

func readvAll(conn *net.UnixConn, bufs [][]byte) (int64, error) {
	// Use syscall to read into multiple buffers
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}

	var total int64
	var readErr error

	err = raw.Read(func(fd uintptr) bool {
		// Prepare iovec structure
		iovs := make([]unix.Iovec, len(bufs))
		for i, buf := range bufs {
			iovs[i] = unix.Iovec{
				Base: &buf[0],
				Len:  uint64(len(buf)),
			}
		}

		n, _, errno := unix.Syscall(
			unix.SYS_READV,
			fd,
			uintptr(unsafe.Pointer(&iovs[0])),
			uintptr(len(iovs)),
		)

		if errno != 0 {
			readErr = errno
			return true
		}

		total = int64(n)
		return true
	})

	if err != nil {
		return 0, err
	}
	return total, readErr
}

// Benchmark continuous stream (realistic scenario)
func BenchmarkRelayContinuousStream(b *testing.B) {
	// Simulate 10 seconds of 5 Mbps video stream
	// 5 Mbps = 625 KB/s = ~428 MTU packets/s
	duration := 10 * time.Second
	bitrate := 5 << 20 // 5 Mbps
	totalBytes := int(float64(bitrate) * duration.Seconds() / 8)

	b.Run("32KB-buffer", func(b *testing.B) {
		benchContinuousStream(b, totalBytes, 32<<10)
	})
	b.Run("64KB-buffer", func(b *testing.B) {
		benchContinuousStream(b, totalBytes, 64<<10)
	})
	b.Run("128KB-buffer", func(b *testing.B) {
		benchContinuousStream(b, totalBytes, 128<<10)
	})
}

func benchContinuousStream(b *testing.B, totalBytes int, bufferSize int) {
	srcWriter, srcRelay := unixConnPair(b)
	dstRelay, dstReader := unixConnPair(b)

	chunkSize := 1460
	chunks := totalBytes / chunkSize

	b.ResetTimer()
	b.SetBytes(int64(totalBytes))
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			chunk := bytes.Repeat([]byte{0x7f}, chunkSize)
			for j := 0; j < chunks; j++ {
				srcWriter.Write(chunk)
				time.Sleep(2 * time.Microsecond)
			}
			srcWriter.CloseWrite()
		}()

		go func() {
			defer wg.Done()
			io.Copy(io.Discard, dstReader)
		}()

		buf := make([]byte, bufferSize)
		io.CopyBuffer(netproxy.Conn(dstRelay), netproxy.Conn(srcRelay), buf)
		dstRelay.CloseWrite()

		wg.Wait()

		closeUnixPair(srcWriter, srcRelay)
		closeUnixPair(dstRelay, dstReader)

		srcWriter, srcRelay = unixConnPair(b)
		dstRelay, dstReader = unixConnPair(b)
	}

	closeUnixPair(srcWriter, srcRelay)
	closeUnixPair(dstRelay, dstReader)
}

// Benchmark with context (dae's real implementation)
func BenchmarkRelayWithEngine(b *testing.B) {
	sizes := []int{500, 1460, 16 << 10, 64 << 10}
	for _, size := range sizes {
		size := size
		b.Run(fmt.Sprintf("DefaultEngine/%dB", size), func(b *testing.B) {
			benchRelayWithEngine(b, size, defaultRelayCopyEngine{})
		})
	}
}

func benchRelayWithEngine(b *testing.B, payloadSize int, engine relayCopyEngine) {
	srcWriter, srcRelay := unixConnPair(b)
	dstRelay, dstReader := unixConnPair(b)

	payload := bytes.Repeat([]byte{0x7f}, payloadSize)

	b.ResetTimer()
	b.SetBytes(int64(payloadSize))
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			srcWriter.Write(payload)
			srcWriter.CloseWrite()
		}()

		go func() {
			defer wg.Done()
			io.Copy(io.Discard, dstReader)
		}()

		ctx := context.Background()
		engine.Copy(ctx, netproxy.Conn(dstRelay), netproxy.Conn(srcRelay))
		dstRelay.CloseWrite()

		wg.Wait()

		closeUnixPair(srcWriter, srcRelay)
		closeUnixPair(dstRelay, dstReader)

		srcWriter, srcRelay = unixConnPair(b)
		dstRelay, dstReader = unixConnPair(b)
	}

	closeUnixPair(srcWriter, srcRelay)
	closeUnixPair(dstRelay, dstReader)
}

// unixConnPair is defined in tcp_copy_linux_test.go
