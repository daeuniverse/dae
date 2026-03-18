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
)

type copyEngineMockConn struct {
	reader io.Reader
	writer bytes.Buffer

	writeToCalled bool
	readCalled    bool
}

func newCopyEngineMockConnFromBytes(p []byte) *copyEngineMockConn {
	return &copyEngineMockConn{
		reader: bytes.NewReader(p),
	}
}

func (c *copyEngineMockConn) Read(p []byte) (int, error) {
	c.readCalled = true
	if c.reader == nil {
		return 0, io.EOF
	}
	return c.reader.Read(p)
}

func (c *copyEngineMockConn) Write(p []byte) (int, error) {
	return c.writer.Write(p)
}

func (c *copyEngineMockConn) WriteTo(w io.Writer) (int64, error) {
	c.writeToCalled = true
	if c.reader == nil {
		return 0, nil
	}
	return io.Copy(w, c.reader)
}

func (c *copyEngineMockConn) Close() error                       { return nil }
func (c *copyEngineMockConn) SetDeadline(_ time.Time) error      { return nil }
func (c *copyEngineMockConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *copyEngineMockConn) SetWriteDeadline(_ time.Time) error { return nil }

var _ netproxy.Conn = (*copyEngineMockConn)(nil)
var _ io.WriterTo = (*copyEngineMockConn)(nil)

func TestDefaultRelayCopyEngine_UsesStableCopyLoopForNonWhitelistedConn(t *testing.T) {
	srcPayload := []byte("hello relay engine")
	src := newCopyEngineMockConnFromBytes(srcPayload)
	dst := &copyEngineMockConn{}

	n, err := (defaultRelayCopyEngine{}).Copy(context.Background(), dst, src)
	if err != nil {
		t.Fatalf("copy failed: %v", err)
	}
	if n != int64(len(srcPayload)) {
		t.Fatalf("unexpected copied bytes: got %d want %d", n, len(srcPayload))
	}
	if src.writeToCalled {
		t.Fatal("stable copy loop should not call src.WriteTo on non-whitelisted connections")
	}
	if !bytes.Equal(dst.writer.Bytes(), srcPayload) {
		t.Fatalf("payload mismatch: got %q want %q", dst.writer.Bytes(), srcPayload)
	}
}

type wrappedConn struct {
	netproxy.Conn
}

type underlyingTCPWrapper struct {
	netproxy.Conn
	inner net.Conn
}

func (c underlyingTCPWrapper) UnderlyingConn() net.Conn {
	return c.inner
}

func TestShouldUseRelayFastPath_UsesConcreteTypeWhitelist(t *testing.T) {
	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	serverCh := make(chan *net.TCPConn, 1)
	errCh := make(chan error, 1)
	go func() {
		conn, e := ln.AcceptTCP()
		if e != nil {
			errCh <- e
			return
		}
		serverCh <- conn
	}()

	client, err := net.DialTCP("tcp", nil, ln.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	var server *net.TCPConn
	select {
	case e := <-errCh:
		t.Fatal(e)
	case server = <-serverCh:
	}
	defer server.Close()

	// Local loopback connections now use splice fast path.
	// Modern kernel implementations optimize splice for loopback scenarios,
	// providing zero-copy forwarding without the overhead previously observed.
	got := shouldUseRelayFastPath(client, server)
	if !got {
		t.Fatal("local loopback connections should use splice fast path")
	}

	// Non-whitelisted wrapped connections should still not use fast path
	if shouldUseRelayFastPath(wrappedConn{client}, server) {
		t.Fatal("wrapped connections should not pass fast-path concrete-type whitelist")
	}
}

func TestShouldUseRelayFastPath_AcceptsUnderlyingConnProvider(t *testing.T) {
	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	serverCh := make(chan *net.TCPConn, 1)
	errCh := make(chan error, 1)
	go func() {
		conn, e := ln.AcceptTCP()
		if e != nil {
			errCh <- e
			return
		}
		serverCh <- conn
	}()

	client, err := net.DialTCP("tcp", nil, ln.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	var server *net.TCPConn
	select {
	case e := <-errCh:
		t.Fatal(e)
	case server = <-serverCh:
	}
	defer server.Close()

	got := shouldUseRelayFastPath(
		underlyingTCPWrapper{Conn: client, inner: client},
		underlyingTCPWrapper{Conn: server, inner: server},
	)
	// Local loopback connections with UnderlyingConn wrapper should use splice
	if !got {
		t.Fatal("local loopback connections with UnderlyingConn wrapper should use splice fast path")
	}
}

func TestShouldUseRelayFastPath_AcceptsConnSnifferOverTCP(t *testing.T) {
	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	serverCh := make(chan *net.TCPConn, 1)
	errCh := make(chan error, 1)
	go func() {
		conn, e := ln.AcceptTCP()
		if e != nil {
			errCh <- e
			return
		}
		serverCh <- conn
	}()

	client, err := net.DialTCP("tcp", nil, ln.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	var server *net.TCPConn
	select {
	case e := <-errCh:
		t.Fatal(e)
	case server = <-serverCh:
	}
	defer server.Close()

	snifferConn := sniffing.NewConnSniffer(client, time.Second)
	defer snifferConn.Close()

	got := shouldUseRelayFastPath(snifferConn, server)
	// ConnSniffer supports UnwrapTCPConn for splice after sniffing completes
	if !got {
		t.Fatal("local loopback connections with ConnSniffer should use splice fast path")
	}
}

func TestShouldUseRelayFastPath_AcceptsFakeNetConnOverTCP(t *testing.T) {
	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	serverCh := make(chan *net.TCPConn, 1)
	errCh := make(chan error, 1)
	go func() {
		conn, e := ln.AcceptTCP()
		if e != nil {
			errCh <- e
			return
		}
		serverCh <- conn
	}()

	client, err := net.DialTCP("tcp", nil, ln.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	var server *net.TCPConn
	select {
	case e := <-errCh:
		t.Fatal(e)
	case server = <-serverCh:
	}
	defer server.Close()

	fakeClient := &netproxy.FakeNetConn{Conn: client, LAddr: client.LocalAddr(), RAddr: client.RemoteAddr()}
	fakeServer := &netproxy.FakeNetConn{Conn: server, LAddr: server.LocalAddr(), RAddr: server.RemoteAddr()}

	got := shouldUseRelayFastPath(fakeClient, fakeServer)
	// FakeNetConn can be unwrapped to TCPConn, so it should use splice
	if !got {
		t.Fatal("local loopback connections with FakeNetConn should use splice fast path")
	}
}

func TestRelayCopyLoop_HonorsCanceledContextBeforeRead(t *testing.T) {
	src := newCopyEngineMockConnFromBytes([]byte("data should not be read"))
	dst := &copyEngineMockConn{}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	buf := make([]byte, relayCopyBufferSize)
	n, err := relayCopyLoop(ctx, dst, src, buf)
	if err == nil || err != context.Canceled {
		t.Fatalf("expected context.Canceled, got n=%d err=%v", n, err)
	}
	if src.readCalled {
		t.Fatal("relayCopyLoop should return on canceled context before reading src")
	}
}
