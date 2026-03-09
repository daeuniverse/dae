//go:build linux
// +build linux

package control

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/sniffing"
	"github.com/daeuniverse/outbound/netproxy"
	bufferredconn "github.com/daeuniverse/outbound/pkg/bufferred_conn"
)

type trackedPrefixedWriterToConn struct {
	*prefixedConn
	writeToCalled bool
}

type multiSegmentRelaySource struct {
	net.Conn
	segments      [][]byte
	writeToCalled bool
}

type writerToOnlyRelaySource struct {
	net.Conn
	prefix        []byte
	off           int
	writeToCalled bool
}

type gatherWriteWrappedDstConn struct {
	netproxy.Conn
	writeCalls int
}

func (c *gatherWriteWrappedDstConn) Write(p []byte) (int, error) {
	c.writeCalls++
	return c.Conn.Write(p)
}

func (c *trackedPrefixedWriterToConn) UnderlyingConn() net.Conn {
	if c == nil || c.prefixedConn == nil {
		return nil
	}
	return c.prefixedConn.Conn
}

func (c *trackedPrefixedWriterToConn) WriteTo(w io.Writer) (int64, error) {
	c.writeToCalled = true
	return io.Copy(w, c.prefixedConn.Conn)
}

func (c *trackedPrefixedWriterToConn) CopyRelayRemainder(dst io.Writer, buf []byte) (int64, error) {
	c.writeToCalled = true
	return io.CopyBuffer(dst, c.prefixedConn.Conn, buf)
}

func (c *multiSegmentRelaySource) UnderlyingConn() net.Conn {
	if c == nil {
		return nil
	}
	return c.Conn
}

func (c *multiSegmentRelaySource) TakeRelaySegments() [][]byte {
	if c == nil || len(c.segments) == 0 {
		return nil
	}
	segs := c.segments
	c.segments = nil
	return segs
}

func (c *multiSegmentRelaySource) WriteTo(w io.Writer) (int64, error) {
	c.writeToCalled = true
	return io.Copy(w, c.Conn)
}

func (c *multiSegmentRelaySource) CopyRelayRemainder(dst io.Writer, buf []byte) (int64, error) {
	c.writeToCalled = true
	return io.CopyBuffer(dst, c.Conn, buf)
}

func (c *writerToOnlyRelaySource) UnderlyingConn() net.Conn {
	if c == nil {
		return nil
	}
	return c.Conn
}

func (c *writerToOnlyRelaySource) TakeRelaySegments() [][]byte {
	if c == nil || c.off >= len(c.prefix) {
		return nil
	}
	seg := c.prefix[c.off:]
	c.off = len(c.prefix)
	return [][]byte{seg}
}

func (c *writerToOnlyRelaySource) WriteTo(w io.Writer) (int64, error) {
	c.writeToCalled = true
	return io.Copy(w, c.Conn)
}

func withRelayGatherWriteTestHook(hook func(prefixLen, bodyLen int), fn func()) {
	relayGatherWriteTestHookMu.Lock()
	old := relayGatherWriteTestHook
	relayGatherWriteTestHook = hook
	relayGatherWriteTestHookMu.Unlock()

	defer func() {
		relayGatherWriteTestHookMu.Lock()
		relayGatherWriteTestHook = old
		relayGatherWriteTestHookMu.Unlock()
	}()

	fn()
}

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

	var hookCalled bool
	withRelayGatherWriteTestHook(func(prefixLen, bodyLen int) {
		hookCalled = true
		if prefixLen != len(prefix) {
			t.Fatalf("unexpected prefix len: got %d want %d", prefixLen, len(prefix))
		}
	}, func() {
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
	})
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

type relayWritevRawConnStub struct {
	writeCalls int
}

func (s *relayWritevRawConnStub) Control(func(uintptr)) error { return nil }

func (s *relayWritevRawConnStub) Read(func(uintptr) bool) error { return nil }

func (s *relayWritevRawConnStub) Write(fn func(uintptr) bool) error {
	for {
		s.writeCalls++
		if fn(1) {
			return nil
		}
	}
}

func TestRelayWritevAll_RetriesOnEAGAINViaRawConn(t *testing.T) {
	oldWritev := relayWritevFunc
	defer func() { relayWritevFunc = oldWritev }()

	var calls int
	relayWritevFunc = func(_ int, segs [][]byte) (int, error) {
		calls++
		switch calls {
		case 1:
			if len(segs) != 2 || string(segs[0]) != "ab" || string(segs[1]) != "cd" {
				t.Fatalf("unexpected initial segments: %q %q", segs[0], segs[1])
			}
			return 2, nil
		case 2:
			if len(segs) != 1 || string(segs[0]) != "cd" {
				t.Fatalf("segments were not advanced before EAGAIN retry: %q", segs[0])
			}
			return 0, syscall.EAGAIN
		case 3:
			if len(segs) != 1 || string(segs[0]) != "cd" {
				t.Fatalf("unexpected retry segments: %q", segs[0])
			}
			return 2, nil
		default:
			return 0, errors.New("unexpected extra writev call")
		}
	}

	rawConn := &relayWritevRawConnStub{}
	written, err := relayWritevAll(rawConn, [][]byte{[]byte("ab"), []byte("cd")})
	if err != nil {
		t.Fatalf("relayWritevAll failed: %v", err)
	}
	if written != 4 {
		t.Fatalf("unexpected bytes written: got %d want 4", written)
	}
	if rawConn.writeCalls != 2 {
		t.Fatalf("expected RawConn.Write to be retried after EAGAIN, got %d calls", rawConn.writeCalls)
	}
	if calls != 3 {
		t.Fatalf("unexpected writev call count: got %d want 3", calls)
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

	var hookCalled bool
	withRelayGatherWriteTestHook(func(prefixLen, bodyLen int) {
		hookCalled = true
		if prefixLen != len(prefix) {
			t.Fatalf("unexpected prefix len: got %d want %d", prefixLen, len(prefix))
		}
	}, func() {
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
	})
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

	var hookCalled bool
	withRelayGatherWriteTestHook(func(prefixLen, bodyLen int) {
		hookCalled = true
		if prefixLen == 0 {
			t.Fatal("expected prefetched bytes from ConnSniffer")
		}
	}, func() {
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
	})
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

	var hookCalled bool
	withRelayGatherWriteTestHook(func(prefixLen, bodyLen int) {
		hookCalled = true
		if prefixLen < len(prefix) {
			t.Fatalf("expected at least %d buffered bytes, got %d", len(prefix), prefixLen)
		}
	}, func() {
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
	})
}

func TestDefaultRelayCopyEngine_GatherWriteContinuesWithFastPath(t *testing.T) {
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
	payload := bytes.Repeat([]byte("x"), relayCopyBufferSize*2)
	go func() {
		_, _ = srcClient.Write(payload)
		_ = srcClient.CloseWrite()
	}()

	trackedSrc := &trackedPrefixedWriterToConn{prefixedConn: &prefixedConn{
		Conn:   srcServer,
		prefix: append([]byte(nil), prefix...),
	}}

	var hookCalled bool
	withRelayGatherWriteTestHook(func(prefixLen, gotBodyLen int) {
		hookCalled = true
		if prefixLen != len(prefix) {
			t.Fatalf("unexpected prefix len: got %d want %d", prefixLen, len(prefix))
		}
	}, func() {
		n, err := (defaultRelayCopyEngine{}).Copy(context.Background(), dstServer, trackedSrc)
		if err != nil {
			t.Fatalf("copy failed: %v", err)
		}
		if n != int64(len(prefix)+len(payload)) {
			t.Fatalf("unexpected copied bytes: got %d want %d", n, len(prefix)+len(payload))
		}
		if !hookCalled {
			t.Fatal("expected gather-write hook to be hit before fast path continuation")
		}
		if !trackedSrc.writeToCalled {
			t.Fatal("expected gather-write path to continue with fast path WriterTo for remaining payload")
		}

		_ = dstServer.CloseWrite()
		got, err := io.ReadAll(dstClient)
		if err != nil {
			t.Fatalf("read destination failed: %v", err)
		}
		want := append(append([]byte(nil), prefix...), payload...)
		if !bytes.Equal(got, want) {
			t.Fatalf("payload mismatch: got %d bytes want %d bytes", len(got), len(want))
		}
	})
}

func TestDefaultRelayCopyEngine_GatherWriteAvoidsWriterToFastPathAfterPrefix(t *testing.T) {
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
	payload := bytes.Repeat([]byte("x"), relayCopyBufferSize*2)
	go func() {
		_, _ = srcClient.Write(payload)
		_ = srcClient.CloseWrite()
	}()

	trackedSrc := &writerToOnlyRelaySource{
		Conn:   srcServer,
		prefix: append([]byte(nil), prefix...),
	}

	var hookCalled bool
	withRelayGatherWriteTestHook(func(prefixLen, bodyLen int) {
		hookCalled = true
		if prefixLen != len(prefix) {
			t.Fatalf("unexpected prefix len: got %d want %d", prefixLen, len(prefix))
		}
		_ = bodyLen
	}, func() {
		n, err := (defaultRelayCopyEngine{}).Copy(context.Background(), dstServer, trackedSrc)
		if err != nil {
			t.Fatalf("copy failed: %v", err)
		}
		if n != int64(len(prefix)+len(payload)) {
			t.Fatalf("unexpected copied bytes: got %d want %d", n, len(prefix)+len(payload))
		}
		if !hookCalled {
			t.Fatal("expected gather-write hook to be hit")
		}
		if trackedSrc.writeToCalled {
			t.Fatal("expected gather-write continuation to stay on stable read loop instead of WriterTo fast path")
		}

		_ = dstServer.CloseWrite()
		got, err := io.ReadAll(dstClient)
		if err != nil {
			t.Fatalf("read destination failed: %v", err)
		}
		want := append(append([]byte(nil), prefix...), payload...)
		if !bytes.Equal(got, want) {
			t.Fatalf("payload mismatch: got %d bytes want %d bytes", len(got), len(want))
		}
	})
}

func TestDefaultRelayCopyEngine_UsesGatherWriteForWrappedWriterDestination(t *testing.T) {
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
		_, _ = srcClient.Write(payload)
		_ = srcClient.CloseWrite()
	}()

	wrappedDst := &gatherWriteWrappedDstConn{Conn: dstServer}

	var hookCalled bool
	withRelayGatherWriteTestHook(func(prefixLen, bodyLen int) {
		hookCalled = true
		if prefixLen != len(prefix) {
			t.Fatalf("unexpected prefix len: got %d want %d", prefixLen, len(prefix))
		}
		_ = bodyLen
	}, func() {
		n, err := (defaultRelayCopyEngine{}).Copy(context.Background(), wrappedDst, &prefixedConn{
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
			t.Fatal("expected gather-write path to be used for wrapped writer destination")
		}
		if wrappedDst.writeCalls == 0 {
			t.Fatal("expected wrapped destination Write to be used via net.Buffers fallback")
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
	})
}

func TestDefaultRelayCopyEngine_GatherWriteUsesContinuationForWrappedDestination(t *testing.T) {
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
	payload := bytes.Repeat([]byte("x"), relayCopyBufferSize*2)
	go func() {
		_, _ = srcClient.Write(payload)
		_ = srcClient.CloseWrite()
	}()

	trackedSrc := &trackedPrefixedWriterToConn{prefixedConn: &prefixedConn{
		Conn:   srcServer,
		prefix: append([]byte(nil), prefix...),
	}}
	wrappedDst := &gatherWriteWrappedDstConn{Conn: dstServer}

	var hookCalled bool
	withRelayGatherWriteTestHook(func(prefixLen, bodyLen int) {
		hookCalled = true
		if prefixLen != len(prefix) {
			t.Fatalf("unexpected prefix len: got %d want %d", prefixLen, len(prefix))
		}
		_ = bodyLen
	}, func() {
		n, err := (defaultRelayCopyEngine{}).Copy(context.Background(), wrappedDst, trackedSrc)
		if err != nil {
			t.Fatalf("copy failed: %v", err)
		}
		if n != int64(len(prefix)+len(payload)) {
			t.Fatalf("unexpected copied bytes: got %d want %d", n, len(prefix)+len(payload))
		}
		if !hookCalled {
			t.Fatal("expected gather-write hook to be hit before continuation path")
		}
		if !trackedSrc.writeToCalled {
			t.Fatal("expected explicit continuation source to handle wrapped destination remainder copy")
		}

		_ = dstServer.CloseWrite()
		got, err := io.ReadAll(dstClient)
		if err != nil {
			t.Fatalf("read destination failed: %v", err)
		}
		want := append(append([]byte(nil), prefix...), payload...)
		if !bytes.Equal(got, want) {
			t.Fatalf("payload mismatch: got %d bytes want %d bytes", len(got), len(want))
		}
	})
}

func TestDefaultRelayCopyEngine_UsesGatherWriteForMultiSegmentSource(t *testing.T) {
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

	seg1 := []byte("prefetched-")
	seg2 := []byte("headers-")
	payload := bytes.Repeat([]byte("x"), relayCopyBufferSize*2)
	go func() {
		_, _ = srcClient.Write(payload)
		_ = srcClient.CloseWrite()
	}()

	trackedSrc := &multiSegmentRelaySource{
		Conn: srcServer,
		segments: [][]byte{
			append([]byte(nil), seg1...),
			append([]byte(nil), seg2...),
		},
	}

	var hookCalled bool
	withRelayGatherWriteTestHook(func(prefixLen, bodyLen int) {
		hookCalled = true
		if prefixLen != len(seg1)+len(seg2) {
			t.Fatalf("unexpected prefix len: got %d want %d", prefixLen, len(seg1)+len(seg2))
		}
		_ = bodyLen
	}, func() {
		n, err := (defaultRelayCopyEngine{}).Copy(context.Background(), dstServer, trackedSrc)
		if err != nil {
			t.Fatalf("copy failed: %v", err)
		}
		if n != int64(len(seg1)+len(seg2)+len(payload)) {
			t.Fatalf("unexpected copied bytes: got %d want %d", n, len(seg1)+len(seg2)+len(payload))
		}
		if !hookCalled {
			t.Fatal("expected gather-write hook to be hit for multi-segment source")
		}
		if !trackedSrc.writeToCalled {
			t.Fatal("expected multi-segment source to continue with fast path WriterTo")
		}

		_ = dstServer.CloseWrite()
		got, err := io.ReadAll(dstClient)
		if err != nil {
			t.Fatalf("read destination failed: %v", err)
		}
		want := append(append(append([]byte(nil), seg1...), seg2...), payload...)
		if !bytes.Equal(got, want) {
			t.Fatalf("payload mismatch: got %d bytes want %d bytes", len(got), len(want))
		}
	})
}
