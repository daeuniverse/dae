//go:build linux
// +build linux

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

func unixConnPair(tb testing.TB) (*net.UnixConn, *net.UnixConn) {
	tb.Helper()

	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		tb.Fatal(err)
	}
	f0 := os.NewFile(uintptr(fds[0]), "pair-0")
	f1 := os.NewFile(uintptr(fds[1]), "pair-1")
	defer f0.Close()
	defer f1.Close()

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

func testRelayAdaptiveCopy(t *testing.T, size int) {
	srcWriter, srcRelay := unixConnPair(t)
	dstRelay, dstReader := unixConnPair(t)
	defer srcWriter.Close()
	defer srcRelay.Close()
	defer dstRelay.Close()
	defer dstReader.Close()

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
