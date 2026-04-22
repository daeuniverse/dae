//go:build linux

package control

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"sync"
	"testing"

	"github.com/daeuniverse/outbound/netproxy"
	"golang.org/x/sys/unix"
)

func tcpConnPair(tb testing.TB) (*net.TCPConn, *net.TCPConn) {
	tb.Helper()

	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		tb.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	accepted := make(chan *net.TCPConn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := ln.AcceptTCP()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn
	}()

	client, err := net.DialTCP("tcp", nil, ln.Addr().(*net.TCPAddr))
	if err != nil {
		tb.Fatal(err)
	}

	select {
	case err := <-acceptErr:
		_ = client.Close()
		tb.Fatal(err)
	case server := <-accepted:
		return client, server
	}
	panic("unreachable")
}

func unixConnPair(tb testing.TB) (*net.UnixConn, *net.UnixConn) {
	tb.Helper()

	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		tb.Fatal(err)
	}
	f0 := os.NewFile(uintptr(fds[0]), "pair-0")
	f1 := os.NewFile(uintptr(fds[1]), "pair-1")
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

func TestRelayAdaptiveCopy_SmallPayload(t *testing.T) {
	testRelayAdaptiveCopy(t, 1024)
}

func TestRelayAdaptiveCopy_LargePayload(t *testing.T) {
	testRelayAdaptiveCopy(t, 256*1024) // 256 KB: well above buffer size to exercise splice path
}

func TestRelayFastCopy_RecordsExactSpliceBytes(t *testing.T) {
	srcWriter, srcRelay := tcpConnPair(t)
	dstReader, dstRelay := tcpConnPair(t)
	defer func() { _ = srcWriter.Close() }()
	defer func() { _ = srcRelay.Close() }()
	defer func() { _ = dstReader.Close() }()
	defer func() { _ = dstRelay.Close() }()

	if !shouldUseRelayFastPath(srcRelay, dstRelay) {
		t.Fatal("expected loopback TCP pair to use relay fast path")
	}

	payload := bytes.Repeat([]byte{0x5a}, relaySpliceAccountingChunkSize*3+123)
	var received bytes.Buffer
	var callbackCalls int
	var callbackBytes int64

	var wg sync.WaitGroup
	wg.Add(2)

	readErrCh := make(chan error, 1)
	go func() {
		defer wg.Done()
		_, err := io.Copy(&received, dstReader)
		readErrCh <- err
	}()

	writeErrCh := make(chan error, 1)
	go func() {
		defer wg.Done()
		_, err := srcWriter.Write(payload)
		if err == nil {
			err = srcWriter.CloseWrite()
		}
		writeErrCh <- err
	}()

	n, err := defaultRelayCopyEngine{}.Copy(context.Background(), dstRelay, srcRelay, func(written int64) {
		callbackCalls++
		callbackBytes += written
	})
	if err != nil {
		t.Fatalf("copy failed: %v", err)
	}
	if n != int64(len(payload)) {
		t.Fatalf("bytes relayed mismatch: got %d want %d", n, len(payload))
	}
	if callbackBytes != n {
		t.Fatalf("recorded bytes mismatch: got %d want %d", callbackBytes, n)
	}
	if callbackCalls == 0 {
		t.Fatal("expected at least one accounting callback")
	}

	_ = dstRelay.CloseWrite()
	wg.Wait()

	if err := <-writeErrCh; err != nil {
		t.Fatalf("writer failed: %v", err)
	}
	if err := <-readErrCh; err != nil {
		t.Fatalf("reader failed: %v", err)
	}
	if !bytes.Equal(received.Bytes(), payload) {
		t.Fatalf("payload mismatch: got %d bytes, want %d bytes", received.Len(), len(payload))
	}
}

func testRelayAdaptiveCopy(t *testing.T, size int) {
	srcWriter, srcRelay := unixConnPair(t)
	dstRelay, dstReader := unixConnPair(t)
	defer func() { _ = srcWriter.Close() }()
	defer func() { _ = srcRelay.Close() }()
	defer func() { _ = dstRelay.Close() }()
	defer func() { _ = dstReader.Close() }()

	payload := bytes.Repeat([]byte{0x7f}, size)
	var received bytes.Buffer

	var wg sync.WaitGroup
	wg.Add(2)

	readErrCh := make(chan error, 1)
	go func() {
		defer wg.Done()
		_, err := io.Copy(&received, dstReader)
		readErrCh <- err
	}()

	writeErrCh := make(chan error, 1)
	go func() {
		defer wg.Done()
		_, err := srcWriter.Write(payload)
		if err == nil {
			err = srcWriter.CloseWrite()
		}
		writeErrCh <- err
	}()

	n, err := relayAdaptiveCopy(context.Background(), netproxy.Conn(dstRelay), netproxy.Conn(srcRelay))
	if err != nil {
		t.Fatalf("relayAdaptiveCopy failed: %v", err)
	}
	if n != int64(len(payload)) {
		t.Fatalf("bytes relayed mismatch: got %d want %d", n, len(payload))
	}

	_ = dstRelay.CloseWrite()
	wg.Wait()

	if err := <-writeErrCh; err != nil {
		t.Fatalf("writer failed: %v", err)
	}
	if err := <-readErrCh; err != nil {
		t.Fatalf("reader failed: %v", err)
	}

	if !bytes.Equal(received.Bytes(), payload) {
		t.Fatalf("payload mismatch: got %d bytes, want %d bytes", received.Len(), len(payload))
	}
}
