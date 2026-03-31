package netproxy

import (
	"net"
	"testing"
	"time"
)

type testUnderlyingWrapper struct {
	net.Conn
	underlying net.Conn
}

func (w *testUnderlyingWrapper) UnderlyingConn() net.Conn {
	if w == nil {
		return nil
	}
	return w.underlying
}

type testLoopWrapper struct{}

func (w *testLoopWrapper) UnderlyingConn() net.Conn {
	return w
}

func (w *testLoopWrapper) Read(_ []byte) (int, error)         { return 0, nil }
func (w *testLoopWrapper) Write(p []byte) (int, error)        { return len(p), nil }
func (w *testLoopWrapper) Close() error                       { return nil }
func (w *testLoopWrapper) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (w *testLoopWrapper) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (w *testLoopWrapper) SetDeadline(_ time.Time) error      { return nil }
func (w *testLoopWrapper) SetReadDeadline(_ time.Time) error  { return nil }
func (w *testLoopWrapper) SetWriteDeadline(_ time.Time) error { return nil }

func tcpPair(tb testing.TB) (*net.TCPConn, *net.TCPConn) {
	tb.Helper()

	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = ln.Close() })

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
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = client.Close() })

	var server *net.TCPConn
	select {
	case e := <-errCh:
		tb.Fatal(e)
	case server = <-serverCh:
	}
	tb.Cleanup(func() { _ = server.Close() })
	return client, server
}

func TestUnwrapTCPConn_DirectTCPConn(t *testing.T) {
	client, _ := tcpPair(t)

	got, ok := UnwrapTCPConn(client)
	if !ok {
		t.Fatal("expected direct *net.TCPConn to unwrap")
	}
	if got != client {
		t.Fatalf("unexpected tcp conn: got %p want %p", got, client)
	}
}

func TestUnwrapTCPConn_FakeNetConn(t *testing.T) {
	client, _ := tcpPair(t)

	wrapped := &FakeNetConn{
		Conn:  client,
		LAddr: client.LocalAddr(),
		RAddr: client.RemoteAddr(),
	}
	got, ok := UnwrapTCPConn(wrapped)
	if !ok {
		t.Fatal("expected FakeNetConn over *net.TCPConn to unwrap")
	}
	if got != client {
		t.Fatalf("unexpected tcp conn: got %p want %p", got, client)
	}
}

func TestUnwrapTCPConn_MultiLayerWrapper(t *testing.T) {
	client, _ := tcpPair(t)

	l1 := &testUnderlyingWrapper{Conn: client, underlying: client}
	l2 := &testUnderlyingWrapper{Conn: client, underlying: l1}
	l3 := &testUnderlyingWrapper{Conn: client, underlying: l2}

	got, ok := UnwrapTCPConn(l3)
	if !ok {
		t.Fatal("expected multi-layer wrapper to unwrap")
	}
	if got != client {
		t.Fatalf("unexpected tcp conn: got %p want %p", got, client)
	}
}

func TestUnwrapTCPConn_CycleGuard(t *testing.T) {
	loop := &testLoopWrapper{}
	if _, ok := UnwrapTCPConn(loop); ok {
		t.Fatal("expected cycle wrapper to fail unwrap due to depth guard")
	}
}

func TestUnwrapTCPConn_Nil(t *testing.T) {
	if _, ok := UnwrapTCPConn(nil); ok {
		t.Fatal("expected nil to fail unwrap")
	}
}
