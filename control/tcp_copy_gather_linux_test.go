//go:build linux
// +build linux

package control

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/sniffing"
	"github.com/daeuniverse/outbound/netproxy"
	bufferredconn "github.com/daeuniverse/outbound/pkg/bufferred_conn"
)

func TestDefaultRelayCopyEngine_UsesGatherWriteForPrefixedConn(t *testing.T) {
	srcLn, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer srcLn.Close()

	srcAccepted := make(chan *net.TCPConn, 1)
	srcErr := make(chan error, 1)
	go func() {
		conn, err := srcLn.AcceptTCP()
		if err != nil {
			srcErr <- err
			return
		}
		srcAccepted <- conn
	}()

	srcClient, err := net.DialTCP("tcp", nil, srcLn.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer srcClient.Close()

	var srcServer *net.TCPConn
	select {
	case err := <-srcErr:
		t.Fatal(err)
	case srcServer = <-srcAccepted:
	}
	defer srcServer.Close()

	dstLn, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer dstLn.Close()

	dstAccepted := make(chan *net.TCPConn, 1)
	dstErr := make(chan error, 1)
	go func() {
		conn, err := dstLn.AcceptTCP()
		if err != nil {
			dstErr <- err
			return
		}
		dstAccepted <- conn
	}()

	dstClient, err := net.DialTCP("tcp", nil, dstLn.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer dstClient.Close()

	var dstServer *net.TCPConn
	select {
	case err := <-dstErr:
		t.Fatal(err)
	case dstServer = <-dstAccepted:
	}
	defer dstServer.Close()

	payload := []byte("payload-body")
	prefix := []byte("prefetched-")
	go func() {
		_, _ = srcClient.Write(payload)
		_ = srcClient.CloseWrite()
	}()

	hookCalled := false
	relayGatherWriteTestHook = func(prefixLen, bodyLen int) {
		hookCalled = true
		if prefixLen != len(prefix) {
			t.Fatalf("unexpected prefix len: got %d want %d", prefixLen, len(prefix))
		}
	}
	defer func() { relayGatherWriteTestHook = nil }()

	n, err := (defaultRelayCopyEngine{}).Copy(context.Background(), dstServer, &prefixedConn{
		Conn:   srcServer,
		prefix: append([]byte(nil), prefix...),
	})
	if err != nil {
		t.Fatalf("copy failed: %v", err)
	}
	if n != int64(len(prefix)+len(payload)) {
		t.Fatalf("unexpected copied bytes: got %d want %d", n, len(prefix)+len(payload))
	}
	if !hookCalled {
		t.Fatal("expected gather-write path to be used")
	}

	_ = dstServer.CloseWrite()
	got, err := io.ReadAll(dstClient)
	if err != nil {
		t.Fatalf("read destination failed: %v", err)
	}
	want := append(append([]byte(nil), prefix...), payload...)
	if !bytes.Equal(got, want) {
		t.Fatalf("payload mismatch: got %q want %q", got, want)
	}
}

func TestRelayAdvanceSegments(t *testing.T) {
	segs := relayAdvanceSegments([][]byte{
		[]byte("abc"),
		[]byte("def"),
		[]byte("ghi"),
	}, 4)

	if len(segs) != 2 {
		t.Fatalf("unexpected segment count: got %d want 2", len(segs))
	}
	if string(segs[0]) != "ef" {
		t.Fatalf("unexpected first remaining segment: %q", segs[0])
	}
	if string(segs[1]) != "ghi" {
		t.Fatalf("unexpected second remaining segment: %q", segs[1])
	}
}

func TestDefaultRelayCopyEngine_UsesGatherWriteForUnderlyingWrappedDestination(t *testing.T) {
	srcLn, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer srcLn.Close()

	srcAccepted := make(chan *net.TCPConn, 1)
	srcErr := make(chan error, 1)
	go func() {
		conn, err := srcLn.AcceptTCP()
		if err != nil {
			srcErr <- err
			return
		}
		srcAccepted <- conn
	}()

	srcClient, err := net.DialTCP("tcp", nil, srcLn.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer srcClient.Close()

	var srcServer *net.TCPConn
	select {
	case err := <-srcErr:
		t.Fatal(err)
	case srcServer = <-srcAccepted:
	}
	defer srcServer.Close()

	dstLn, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer dstLn.Close()

	dstAccepted := make(chan *net.TCPConn, 1)
	dstErr := make(chan error, 1)
	go func() {
		conn, err := dstLn.AcceptTCP()
		if err != nil {
			dstErr <- err
			return
		}
		dstAccepted <- conn
	}()

	dstClient, err := net.DialTCP("tcp", nil, dstLn.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer dstClient.Close()

	var dstServer *net.TCPConn
	select {
	case err := <-dstErr:
		t.Fatal(err)
	case dstServer = <-dstAccepted:
	}
	defer dstServer.Close()

	payload := []byte("payload-body")
	prefix := []byte("prefetched-")
	go func() {
		_, _ = srcClient.Write(payload)
		_ = srcClient.CloseWrite()
	}()

	hookCalled := false
	relayGatherWriteTestHook = func(prefixLen, bodyLen int) {
		hookCalled = true
		if prefixLen != len(prefix) {
			t.Fatalf("unexpected prefix len: got %d want %d", prefixLen, len(prefix))
		}
	}
	defer func() { relayGatherWriteTestHook = nil }()

	n, err := (defaultRelayCopyEngine{}).Copy(
		context.Background(),
		underlyingTCPWrapper{Conn: dstServer, inner: dstServer},
		&prefixedConn{Conn: srcServer, prefix: append([]byte(nil), prefix...)},
	)
	if err != nil {
		t.Fatalf("copy failed: %v", err)
	}
	if n != int64(len(prefix)+len(payload)) {
		t.Fatalf("unexpected copied bytes: got %d want %d", n, len(prefix)+len(payload))
	}
	if !hookCalled {
		t.Fatal("expected gather-write path to use UnderlyingConn destination")
	}

	_ = dstServer.CloseWrite()
	got, err := io.ReadAll(dstClient)
	if err != nil {
		t.Fatalf("read destination failed: %v", err)
	}
	want := append(append([]byte(nil), prefix...), payload...)
	if !bytes.Equal(got, want) {
		t.Fatalf("payload mismatch: got %q want %q", got, want)
	}
}

func TestDefaultRelayCopyEngine_PrefersGatherWriteBeforeFastPathForConnSniffer(t *testing.T) {
	srcLn, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer srcLn.Close()

	srcAccepted := make(chan *net.TCPConn, 1)
	srcErr := make(chan error, 1)
	go func() {
		conn, err := srcLn.AcceptTCP()
		if err != nil {
			srcErr <- err
			return
		}
		srcAccepted <- conn
	}()

	srcClient, err := net.DialTCP("tcp", nil, srcLn.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer srcClient.Close()

	var srcServer *net.TCPConn
	select {
	case err := <-srcErr:
		t.Fatal(err)
	case srcServer = <-srcAccepted:
	}
	defer srcServer.Close()

	dstLn, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer dstLn.Close()

	dstAccepted := make(chan *net.TCPConn, 1)
	dstErr := make(chan error, 1)
	go func() {
		conn, err := dstLn.AcceptTCP()
		if err != nil {
			dstErr <- err
			return
		}
		dstAccepted <- conn
	}()

	dstClient, err := net.DialTCP("tcp", nil, dstLn.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer dstClient.Close()

	var dstServer *net.TCPConn
	select {
	case err := <-dstErr:
		t.Fatal(err)
	case dstServer = <-dstAccepted:
	}
	defer dstServer.Close()

	prefix := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	payload := []byte("payload-body")
	go func() {
		_, _ = srcClient.Write(prefix)
		_, _ = srcClient.Write(payload)
		_ = srcClient.CloseWrite()
	}()

	snifferConn := sniffing.NewConnSniffer(srcServer, 200*time.Millisecond)
	if _, err := snifferConn.SniffTcp(); err != nil && !sniffing.IsSniffingError(err) {
		t.Fatalf("sniff failed: %v", err)
	}
	defer snifferConn.Close()

	hookCalled := false
	relayGatherWriteTestHook = func(prefixLen, bodyLen int) {
		hookCalled = true
		if prefixLen == 0 {
			t.Fatal("expected prefetched bytes from ConnSniffer")
		}
	}
	defer func() { relayGatherWriteTestHook = nil }()

	n, err := (defaultRelayCopyEngine{}).Copy(context.Background(), dstServer, snifferConn)
	if err != nil {
		t.Fatalf("copy failed: %v", err)
	}
	if n != int64(len(prefix)+len(payload)) {
		t.Fatalf("unexpected copied bytes: got %d want %d", n, len(prefix)+len(payload))
	}
	if !hookCalled {
		t.Fatal("expected gather-write to run before fast path for ConnSniffer")
	}

	_ = dstServer.CloseWrite()
	got, err := io.ReadAll(dstClient)
	if err != nil {
		t.Fatalf("read destination failed: %v", err)
	}
	want := append(append([]byte(nil), prefix...), payload...)
	if !bytes.Equal(got, want) {
		t.Fatalf("payload mismatch: got %q want %q", got, want)
	}
}

func TestDefaultRelayCopyEngine_UsesGatherWriteForBufferedConnSource(t *testing.T) {
	srcLn, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer srcLn.Close()

	srcAccepted := make(chan *net.TCPConn, 1)
	srcErr := make(chan error, 1)
	go func() {
		conn, err := srcLn.AcceptTCP()
		if err != nil {
			srcErr <- err
			return
		}
		srcAccepted <- conn
	}()

	srcClient, err := net.DialTCP("tcp", nil, srcLn.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer srcClient.Close()

	var srcServer *net.TCPConn
	select {
	case err := <-srcErr:
		t.Fatal(err)
	case srcServer = <-srcAccepted:
	}
	defer srcServer.Close()

	dstLn, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer dstLn.Close()

	dstAccepted := make(chan *net.TCPConn, 1)
	dstErr := make(chan error, 1)
	go func() {
		conn, err := dstLn.AcceptTCP()
		if err != nil {
			dstErr <- err
			return
		}
		dstAccepted <- conn
	}()

	dstClient, err := net.DialTCP("tcp", nil, dstLn.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer dstClient.Close()

	var dstServer *net.TCPConn
	select {
	case err := <-dstErr:
		t.Fatal(err)
	case dstServer = <-dstAccepted:
	}
	defer dstServer.Close()

	prefix := []byte("prefetched-")
	payload := []byte("payload-body")
	go func() {
		_, _ = srcClient.Write(prefix)
		_, _ = srcClient.Write(payload)
		_ = srcClient.CloseWrite()
	}()

	buffered := bufferredconn.NewBufferedConnSize(srcServer, len(prefix)+len(payload))
	defer buffered.Close()
	if _, err := buffered.Peek(len(prefix)); err != nil {
		t.Fatalf("peek failed: %v", err)
	}

	hookCalled := false
	relayGatherWriteTestHook = func(prefixLen, bodyLen int) {
		hookCalled = true
		if prefixLen < len(prefix) {
			t.Fatalf("expected at least %d buffered bytes, got %d", len(prefix), prefixLen)
		}
	}
	defer func() { relayGatherWriteTestHook = nil }()

	n, err := (defaultRelayCopyEngine{}).Copy(context.Background(), netproxy.Conn(dstServer), buffered)
	if err != nil {
		t.Fatalf("copy failed: %v", err)
	}
	if n != int64(len(prefix)+len(payload)) {
		t.Fatalf("unexpected copied bytes: got %d want %d", n, len(prefix)+len(payload))
	}
	if !hookCalled {
		t.Fatal("expected gather-write path to use BufferedConn prefix")
	}

	_ = dstServer.CloseWrite()
	got, err := io.ReadAll(dstClient)
	if err != nil {
		t.Fatalf("read destination failed: %v", err)
	}
	want := append(append([]byte(nil), prefix...), payload...)
	if !bytes.Equal(got, want) {
		t.Fatalf("payload mismatch: got %q want %q", got, want)
	}
}
