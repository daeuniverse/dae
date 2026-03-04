package sniffing

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

type testAddr string

func (a testAddr) Network() string { return "tcp" }
func (a testAddr) String() string  { return string(a) }

type benchPayloadConn struct {
	mu          sync.Mutex
	payload     []byte
	offset      int
	readDls     []time.Time
	writeBuffer []byte
}

func newBenchPayloadConn(payload []byte) *benchPayloadConn {
	buf := make([]byte, len(payload))
	copy(buf, payload)
	return &benchPayloadConn{
		payload: buf,
	}
}

func (c *benchPayloadConn) Read(p []byte) (n int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.offset >= len(c.payload) {
		return 0, io.EOF
	}
	n = copy(p, c.payload[c.offset:])
	c.offset += n
	return n, nil
}

func (c *benchPayloadConn) Write(p []byte) (n int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeBuffer = append(c.writeBuffer, p...)
	return len(p), nil
}

func (c *benchPayloadConn) Close() error { return nil }

func (c *benchPayloadConn) LocalAddr() net.Addr  { return testAddr("127.0.0.1:10000") }
func (c *benchPayloadConn) RemoteAddr() net.Addr { return testAddr("127.0.0.1:20000") }

func (c *benchPayloadConn) SetDeadline(t time.Time) error {
	return c.SetReadDeadline(t)
}

func (c *benchPayloadConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDls = append(c.readDls, t)
	c.mu.Unlock()
	return nil
}

func (c *benchPayloadConn) SetWriteDeadline(time.Time) error { return nil }

func (c *benchPayloadConn) readDeadlines() []time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]time.Time, len(c.readDls))
	copy(out, c.readDls)
	return out
}

type benchPayloadConnNoRecord struct {
	payload []byte
	offset  int
}

func newBenchPayloadConnNoRecord(payload []byte) *benchPayloadConnNoRecord {
	buf := make([]byte, len(payload))
	copy(buf, payload)
	return &benchPayloadConnNoRecord{
		payload: buf,
	}
}

func (c *benchPayloadConnNoRecord) Read(p []byte) (n int, err error) {
	if c.offset >= len(c.payload) {
		return 0, io.EOF
	}
	n = copy(p, c.payload[c.offset:])
	c.offset += n
	return n, nil
}

func (c *benchPayloadConnNoRecord) Write(p []byte) (n int, err error) { return len(p), nil }
func (c *benchPayloadConnNoRecord) Close() error                      { return nil }
func (c *benchPayloadConnNoRecord) LocalAddr() net.Addr               { return testAddr("127.0.0.1:10002") }
func (c *benchPayloadConnNoRecord) RemoteAddr() net.Addr              { return testAddr("127.0.0.1:20002") }
func (c *benchPayloadConnNoRecord) SetDeadline(t time.Time) error     { return c.SetReadDeadline(t) }
func (c *benchPayloadConnNoRecord) SetReadDeadline(time.Time) error   { return nil }
func (c *benchPayloadConnNoRecord) SetWriteDeadline(time.Time) error  { return nil }

type deadlineBlockConn struct {
	mu       sync.Mutex
	readDls  []time.Time
	deadline time.Time
}

func (c *deadlineBlockConn) Read([]byte) (int, error) {
	c.mu.Lock()
	deadline := c.deadline
	c.mu.Unlock()

	if deadline.IsZero() {
		time.Sleep(10 * time.Millisecond)
		return 0, io.EOF
	}
	if wait := time.Until(deadline); wait > 0 {
		time.Sleep(wait)
	}
	return 0, os.ErrDeadlineExceeded
}

func (c *deadlineBlockConn) Write(p []byte) (n int, err error) { return len(p), nil }
func (c *deadlineBlockConn) Close() error                      { return nil }
func (c *deadlineBlockConn) LocalAddr() net.Addr               { return testAddr("127.0.0.1:10001") }
func (c *deadlineBlockConn) RemoteAddr() net.Addr              { return testAddr("127.0.0.1:20001") }
func (c *deadlineBlockConn) SetDeadline(t time.Time) error     { return c.SetReadDeadline(t) }
func (c *deadlineBlockConn) SetWriteDeadline(time.Time) error  { return nil }

func (c *deadlineBlockConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	c.readDls = append(c.readDls, t)
	c.mu.Unlock()
	return nil
}

func (c *deadlineBlockConn) readDeadlines() []time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]time.Time, len(c.readDls))
	copy(out, c.readDls)
	return out
}

// sniffTcpLegacyOnce reproduces the previous one-read stream path:
// goroutine + channel + context wait.
func sniffTcpLegacyOnce(s *Sniffer) (string, error) {
	dataReady := make(chan struct{})
	var dataErr error
	go func() {
		_, err := s.buf.ReadFromOnce(s.r)
		if err != nil {
			dataErr = err
		}
		close(dataReady)
	}()

	select {
	case <-dataReady:
		if dataErr != nil {
			return "", dataErr
		}
	case <-s.ctx.Done():
		return "", fmt.Errorf("%w: %w", ErrNotApplicable, context.DeadlineExceeded)
	}

	if s.buf.Len() == 0 {
		return "", ErrNotApplicable
	}
	return sniffGroup(s.SniffTls, s.SniffHttp)
}

func TestSniffTcp_NetConnReadDeadlineLifecycle(t *testing.T) {
	conn := newBenchPayloadConn([]byte(
		"GET / HTTP/1.1\r\n" +
			"Host: lifecycle.example.com\r\n\r\n",
	))
	s := NewStreamSniffer(conn, 100*time.Millisecond)
	defer s.Close()

	domain, err := s.SniffTcp()
	if err != nil {
		t.Fatalf("sniff failed: %v", err)
	}
	if domain != "lifecycle.example.com" {
		t.Fatalf("unexpected domain: %q", domain)
	}

	deadlines := conn.readDeadlines()
	if len(deadlines) < 2 {
		t.Fatalf("expected read deadline set+restore, got %d call(s)", len(deadlines))
	}
	if deadlines[0].IsZero() {
		t.Fatal("first read deadline should be non-zero")
	}
	if !deadlines[len(deadlines)-1].IsZero() {
		t.Fatal("last read deadline should restore zero value")
	}
}

func TestSniffTcp_NetConnTimeoutBehavior(t *testing.T) {
	conn := &deadlineBlockConn{}
	s := NewStreamSniffer(conn, 20*time.Millisecond)
	defer s.Close()

	done := make(chan error, 1)
	go func() {
		_, err := s.SniffTcp()
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected timeout error, got nil")
		}
		if !IsSniffingError(err) {
			t.Fatalf("expected sniffing error, got: %v", err)
		}
		if !strings.Contains(err.Error(), context.DeadlineExceeded.Error()) {
			t.Fatalf("expected context deadline marker, got: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("SniffTcp timeout path blocked unexpectedly")
	}

	deadlines := conn.readDeadlines()
	if len(deadlines) < 2 {
		t.Fatalf("expected read deadline set+restore, got %d call(s)", len(deadlines))
	}
	if deadlines[0].IsZero() {
		t.Fatal("first read deadline should be non-zero")
	}
	if !deadlines[len(deadlines)-1].IsZero() {
		t.Fatal("last read deadline should restore zero value")
	}
}

func BenchmarkSniffTcpReadStrategy(b *testing.B) {
	payload := []byte(
		"GET /path HTTP/1.1\r\n" +
			"User-Agent: dae\r\n" +
			"Host: benchmark.example.com\r\n\r\n",
	)

	b.Run("legacy_async_read", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			conn := newBenchPayloadConnNoRecord(payload)
			s := NewStreamSniffer(conn, 100*time.Millisecond)
			domain, err := sniffTcpLegacyOnce(s)
			_ = s.Close()
			if err != nil {
				b.Fatalf("sniff failed: %v", err)
			}
			if domain != "benchmark.example.com" {
				b.Fatalf("unexpected domain: %q", domain)
			}
		}
	})

	b.Run("deadline_sync_read", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			conn := newBenchPayloadConnNoRecord(payload)
			s := NewStreamSniffer(conn, 100*time.Millisecond)
			domain, err := s.SniffTcp()
			_ = s.Close()
			if err != nil {
				b.Fatalf("sniff failed: %v", err)
			}
			if domain != "benchmark.example.com" {
				b.Fatalf("unexpected domain: %q", domain)
			}
		}
	})
}
