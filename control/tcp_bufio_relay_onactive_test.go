package control

import (
	"bufio"
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

type onActivePipe struct {
	r *io.PipeReader
	w *io.PipeWriter
}

func newOnActivePipe() (*onActivePipe, *onActivePipe) {
	ar, aw := io.Pipe()
	br, bw := io.Pipe()
	return &onActivePipe{r: ar, w: bw}, &onActivePipe{r: br, w: aw}
}

func (c *onActivePipe) Read(b []byte) (int, error)  { return c.r.Read(b) }
func (c *onActivePipe) Write(b []byte) (int, error) { return c.w.Write(b) }
func (c *onActivePipe) Close() error {
	_ = c.r.Close()
	return c.w.Close()
}
func (c *onActivePipe) LocalAddr() net.Addr              { return pipeAddr("local") }
func (c *onActivePipe) RemoteAddr() net.Addr             { return pipeAddr("remote") }
func (c *onActivePipe) SetDeadline(time.Time) error      { return nil }
func (c *onActivePipe) SetReadDeadline(time.Time) error  { return nil }
func (c *onActivePipe) SetWriteDeadline(time.Time) error { return nil }

type pipeAddr string

func (a pipeAddr) Network() string { return "pipe" }
func (a pipeAddr) String() string  { return string(a) }

func TestBufioConnCopyRelayRemainderInvokesOnActive(t *testing.T) {
	src, peer := newOnActivePipe()
	t.Cleanup(func() {
		_ = src.Close()
		_ = peer.Close()
	})

	payload := []byte("remainder-bytes")
	go func() {
		_, _ = peer.Write(payload)
		_ = peer.w.Close()
	}()

	reader := bufio.NewReader(src)
	if _, err := reader.Peek(1); err != nil && err != io.EOF {
		t.Fatalf("Peek: %v", err)
	}
	if reader.Buffered() == 0 {
		t.Fatal("expected buffered remainder bytes")
	}
	c := &bufioConn{Conn: src, reader: reader}
	var active atomic.Int64
	n, err := c.CopyRelayRemainder(context.Background(), io.Discard, make([]byte, 64), nil, func(v int64) { active.Add(v) })
	if err != nil && err != io.EOF {
		t.Fatalf("CopyRelayRemainder: %v", err)
	}
	if n != int64(len(payload)) {
		t.Fatalf("written = %d, want %d", n, len(payload))
	}
	if active.Load() == 0 {
		t.Fatal("onActive was not invoked on the buffered remainder path")
	}
}

func TestBufioConnCopyRelayRemainderInvokesOnActiveAfterDrain(t *testing.T) {
	src, peer := newOnActivePipe()
	t.Cleanup(func() {
		_ = src.Close()
		_ = peer.Close()
	})

	payload := []byte("after-drain")
	reader := bufio.NewReader(src)
	if reader.Buffered() != 0 {
		t.Fatal("expected empty bufio buffer before remainder copy")
	}
	go func() {
		_, _ = peer.Write(payload)
		_ = peer.w.Close()
	}()

	c := &bufioConn{Conn: src, reader: reader}
	var active atomic.Int64
	n, err := c.CopyRelayRemainder(context.Background(), io.Discard, make([]byte, 64), nil, func(v int64) { active.Add(v) })
	if err != nil && err != io.EOF {
		t.Fatalf("CopyRelayRemainder: %v", err)
	}
	if n != int64(len(payload)) {
		t.Fatalf("written = %d, want %d", n, len(payload))
	}
	if active.Load() == 0 {
		t.Fatal("onActive was not invoked after the buffered prefix was drained")
	}
}

func TestBufioConnCopyRelayRemainderInvokesOnActiveViaSplice(t *testing.T) {
	lnSrc, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lnSrc.Close() })
	lnDst, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lnDst.Close() })

	srcClient, err := net.Dial("tcp", lnSrc.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srcClient.Close() })
	srcAccepted, err := lnSrc.Accept()
	if err != nil {
		t.Fatal(err)
	}
	srcTCP := srcAccepted.(*net.TCPConn)
	t.Cleanup(func() { _ = srcTCP.Close() })

	dstClient, err := net.Dial("tcp", lnDst.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	dstTCP := dstClient.(*net.TCPConn)
	t.Cleanup(func() { _ = dstTCP.Close() })
	dstAccepted, err := lnDst.Accept()
	if err != nil {
		t.Fatal(err)
	}
	dstPeer := dstAccepted.(*net.TCPConn)
	t.Cleanup(func() { _ = dstPeer.Close() })

	payload := []byte("splice-remainder")
	go func() {
		_, _ = srcClient.Write(payload)
		_ = srcClient.(*net.TCPConn).CloseWrite()
	}()

	reader := bufio.NewReader(srcTCP)
	if reader.Buffered() != 0 {
		t.Fatal("expected empty bufio buffer so remainder uses the splice path")
	}
	c := &bufioConn{Conn: srcTCP, reader: reader}
	var active atomic.Int64
	var recorded atomic.Int64
	n, err := c.CopyRelayRemainder(context.Background(), dstTCP, make([]byte, 64), func(v int64) { recorded.Add(v) }, func(v int64) { active.Add(v) })
	if err != nil && err != io.EOF {
		t.Fatalf("CopyRelayRemainder: %v", err)
	}
	if n != int64(len(payload)) {
		t.Fatalf("written = %d, want %d", n, len(payload))
	}
	if active.Load() == 0 {
		t.Fatal("onActive was not invoked on the TCP splice remainder path")
	}
	if recorded.Load() == 0 {
		t.Fatal("record was not invoked on the TCP splice remainder path")
	}

	got := make([]byte, len(payload))
	if err := dstPeer.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(dstPeer, got); err != nil {
		t.Fatalf("read spliced payload: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("spliced payload = %q, want %q", got, payload)
	}
}

func TestRelayFastCopyNilRecordStillInvokesOnActive(t *testing.T) {
	lnSrc, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lnSrc.Close() })
	lnDst, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lnDst.Close() })

	srcClient, err := net.Dial("tcp", lnSrc.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srcClient.Close() })
	srcAccepted, err := lnSrc.Accept()
	if err != nil {
		t.Fatal(err)
	}
	srcTCP := srcAccepted.(*net.TCPConn)
	t.Cleanup(func() { _ = srcTCP.Close() })

	dstClient, err := net.Dial("tcp", lnDst.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	dstTCP := dstClient.(*net.TCPConn)
	t.Cleanup(func() { _ = dstTCP.Close() })
	dstAccepted, err := lnDst.Accept()
	if err != nil {
		t.Fatal(err)
	}
	dstPeer := dstAccepted.(*net.TCPConn)
	t.Cleanup(func() { _ = dstPeer.Close() })

	payload := []byte("fast-copy-no-record")
	go func() {
		_, _ = srcClient.Write(payload)
		_ = srcClient.(*net.TCPConn).CloseWrite()
	}()

	// record == nil must not disable activity refreshes: the idle watchdog
	// is armed unconditionally by relayCore.run, so a nil-record relay that
	// drops onActive would be reclaimed mid-flow.
	var active atomic.Int64
	n, err := relayFastCopy(context.Background(), dstTCP, srcTCP, nil, func(v int64) { active.Add(v) })
	if err != nil && err != io.EOF {
		t.Fatalf("relayFastCopy: %v", err)
	}
	if n != int64(len(payload)) {
		t.Fatalf("written = %d, want %d", n, len(payload))
	}
	if active.Load() == 0 {
		t.Fatal("onActive was not invoked: nil record must not take the bare io.Copy shortcut")
	}

	got := make([]byte, len(payload))
	if err := dstPeer.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(dstPeer, got); err != nil {
		t.Fatalf("read relayed payload: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("relayed payload = %q, want %q", got, payload)
	}
}
