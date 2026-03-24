//go:build linux
// +build linux

package sniffing

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"sync"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

type relayMode string

const (
	relayIOCopy     relayMode = "io.Copy"
	relayPipeSplice relayMode = "pipe+splice"
)

func splicePipeN(dst, src interface {
	SyscallConn() (syscall.RawConn, error)
}, total int64) (int64, error) {
	rawSrc, err := src.SyscallConn()
	if err != nil {
		return 0, err
	}
	rawDst, err := dst.SyscallConn()
	if err != nil {
		return 0, err
	}

	var srcFD, dstFD int
	if err := rawSrc.Control(func(fd uintptr) { srcFD = int(fd) }); err != nil {
		return 0, err
	}
	if err := rawDst.Control(func(fd uintptr) { dstFD = int(fd) }); err != nil {
		return 0, err
	}

	pipeFD := make([]int, 2)
	if err := unix.Pipe2(pipeFD, unix.O_CLOEXEC); err != nil {
		return 0, err
	}
	defer func() { _ = unix.Close(pipeFD[0]) }()
	defer func() { _ = unix.Close(pipeFD[1]) }()

	const chunk = 1 << 20
	var copied int64
	for copied < total {
		want := int(total - copied)
		if want > chunk {
			want = chunk
		}

		var in int64
		for {
			in, err = unix.Splice(srcFD, nil, pipeFD[1], nil, want, unix.SPLICE_F_MOVE)
			if err == unix.EINTR {
				continue
			}
			if err == unix.EAGAIN {
				runtime.Gosched()
				continue
			}
			if err != nil {
				return copied, err
			}
			break
		}
		if in == 0 {
			break
		}

		remaining := int(in)
		for remaining > 0 {
			var out int64
			for {
				out, err = unix.Splice(pipeFD[0], nil, dstFD, nil, remaining, unix.SPLICE_F_MOVE)
				if err == unix.EINTR {
					continue
				}
				if err == unix.EAGAIN {
					runtime.Gosched()
					continue
				}
				if err != nil {
					return copied, err
				}
				break
			}
			remaining -= int(out)
		}
		copied += in
	}
	return copied, nil
}

func connFD(c interface {
	SyscallConn() (syscall.RawConn, error)
}) (int, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, err
	}
	var fd int
	if err := raw.Control(func(u uintptr) { fd = int(u) }); err != nil {
		return 0, err
	}
	return fd, nil
}

func splicePipeToEOF(dst, src interface {
	SyscallConn() (syscall.RawConn, error)
}) (int64, error) {
	srcFD, err := connFD(src)
	if err != nil {
		return 0, err
	}
	dstFD, err := connFD(dst)
	if err != nil {
		return 0, err
	}

	pipeFD := make([]int, 2)
	if err := unix.Pipe2(pipeFD, unix.O_CLOEXEC); err != nil {
		return 0, err
	}
	defer func() { _ = unix.Close(pipeFD[0]) }()
	defer func() { _ = unix.Close(pipeFD[1]) }()

	const chunk = 1 << 20
	var copied int64
	for {
		var in int64
		for {
			in, err = unix.Splice(srcFD, nil, pipeFD[1], nil, chunk, unix.SPLICE_F_MOVE)
			if err == unix.EINTR {
				continue
			}
			if err == unix.EAGAIN {
				runtime.Gosched()
				continue
			}
			if err != nil {
				return copied, err
			}
			break
		}
		if in == 0 {
			return copied, nil
		}

		remaining := int(in)
		for remaining > 0 {
			var out int64
			for {
				out, err = unix.Splice(pipeFD[0], nil, dstFD, nil, remaining, unix.SPLICE_F_MOVE)
				if err == unix.EINTR {
					continue
				}
				if err == unix.EAGAIN {
					runtime.Gosched()
					continue
				}
				if err != nil {
					return copied, err
				}
				break
			}
			remaining -= int(out)
		}
		copied += in
	}
}

func makeUnixPair(tb testing.TB) (*net.UnixConn, *net.UnixConn) {
	tb.Helper()

	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		tb.Fatal(err)
	}

	f0 := os.NewFile(uintptr(fds[0]), "unixpair-0")
	f1 := os.NewFile(uintptr(fds[1]), "unixpair-1")
	defer func() { _ = f0.Close() }()
	defer func() { _ = f1.Close() }()

	c0raw, err := net.FileConn(f0)
	if err != nil {
		tb.Fatal(err)
	}
	c1raw, err := net.FileConn(f1)
	if err != nil {
		_ = c0raw.Close()
		tb.Fatal(err)
	}

	c0, ok := c0raw.(*net.UnixConn)
	if !ok {
		_ = c0raw.Close()
		_ = c1raw.Close()
		tb.Fatal("pair endpoint 0 is not UnixConn")
	}
	c1, ok := c1raw.(*net.UnixConn)
	if !ok {
		_ = c0raw.Close()
		_ = c1raw.Close()
		tb.Fatal("pair endpoint 1 is not UnixConn")
	}
	return c0, c1
}

func startRelay(tb testing.TB, mode relayMode) (*net.UnixConn, func()) {
	tb.Helper()

	client, relayClient := makeUnixPair(tb)
	relayServer, server := makeUnixPair(tb)

	relayFn := func(dst, src *net.UnixConn) (int64, error) {
		if mode == relayPipeSplice {
			return splicePipeToEOF(dst, src)
		}
		return io.Copy(dst, src)
	}

	var wg sync.WaitGroup
	wg.Add(3)

	go func() {
		defer wg.Done()
		_, _ = relayFn(relayServer, relayClient)
		_ = relayServer.CloseWrite()
	}()
	go func() {
		defer wg.Done()
		_, _ = relayFn(relayClient, relayServer)
		_ = relayClient.CloseWrite()
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(server, server)
	}()

	cleanup := func() {
		_ = client.Close()
		_ = relayClient.Close()
		_ = relayServer.Close()
		_ = server.Close()
		wg.Wait()
	}
	return client, cleanup
}

func runRelayBenchmark(b *testing.B, payloadSize int, relay func(dst *net.UnixConn, src *net.UnixConn) (int64, error)) {
	payload := make([]byte, payloadSize)
	for i := range payload {
		payload[i] = byte(i)
	}

	b.SetBytes(int64(payloadSize))
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		b.StopTimer()
		srcClient, srcRelay := makeUnixPair(b)
		dstClient, dstRelay := makeUnixPair(b)

		var wg sync.WaitGroup
		wg.Add(2)

		writerErr := make(chan error, 1)
		go func() {
			defer wg.Done()
			defer func() { _ = srcClient.Close() }()
			_, err := srcClient.Write(payload)
			if err == nil {
				err = srcClient.CloseWrite()
			}
			writerErr <- err
		}()

		sinkErr := make(chan error, 1)
		go func() {
			defer wg.Done()
			defer func() { _ = dstClient.Close() }()
			_, err := io.Copy(io.Discard, dstClient)
			sinkErr <- err
		}()

		b.StartTimer()
		n, err := relay(dstRelay, srcRelay)
		b.StopTimer()

		_ = dstRelay.CloseWrite()
		_ = srcRelay.Close()
		_ = dstRelay.Close()
		wg.Wait()

		if err != nil {
			b.Fatalf("relay failed: %v", err)
		}
		if n != int64(payloadSize) {
			b.Fatalf("relay bytes mismatch: got %d want %d", n, payloadSize)
		}
		if err := <-writerErr; err != nil {
			b.Fatalf("writer failed: %v", err)
		}
		if err := <-sinkErr; err != nil {
			b.Fatalf("sink failed: %v", err)
		}
	}
}

func BenchmarkTCPRelayCopyVsPipeSplice(b *testing.B) {
	sizes := []int{1 << 10, 4 << 10, 16 << 10, 64 << 10, 1 << 20, 8 << 20}
	for _, sz := range sizes {
		sz := sz
		b.Run(fmt.Sprintf("io.Copy/%d", sz), func(b *testing.B) {
			runRelayBenchmark(b, sz, func(dst, src *net.UnixConn) (int64, error) {
				return io.Copy(dst, src)
			})
		})
		b.Run(fmt.Sprintf("pipe+splice/%d", sz), func(b *testing.B) {
			runRelayBenchmark(b, sz, func(dst, src *net.UnixConn) (int64, error) {
				return splicePipeN(dst, src, int64(sz))
			})
		})
	}
}

func BenchmarkRelayPingPongLatency(b *testing.B) {
	sizes := []int{64, 256, 1024, 4096}
	for _, sz := range sizes {
		payload := bytes.Repeat([]byte{0x5a}, sz)
		reply := make([]byte, sz)
		for _, mode := range []relayMode{relayIOCopy, relayPipeSplice} {
			mode := mode
			b.Run(fmt.Sprintf("%s/%dB", mode, sz), func(b *testing.B) {
				client, cleanup := startRelay(b, mode)
				defer cleanup()

				b.ReportAllocs()
				b.SetBytes(int64(sz * 2))
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if _, err := client.Write(payload); err != nil {
						b.Fatalf("write failed: %v", err)
					}
					if _, err := io.ReadFull(client, reply); err != nil {
						b.Fatalf("read failed: %v", err)
					}
				}
				b.StopTimer()
			})
		}
	}
}
