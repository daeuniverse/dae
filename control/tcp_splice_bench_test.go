package control

import (
	"context"
	"io"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
)

// mockConn implements netproxy.Conn for testing
type mockConn struct {
	net.TCPConn
	reader *io.PipeReader
	writer *io.PipeWriter
}

func newMockConnPair() (c1, c2 *mockConn) {
	r1, w1 := io.Pipe()
	r2, w2 := io.Pipe()

	c1 = &mockConn{reader: r1, writer: w2}
	c2 = &mockConn{reader: r2, writer: w1}
	return c1, c2
}

func (m *mockConn) Read(b []byte) (n int, err error)  { return m.reader.Read(b) }
func (m *mockConn) Write(b []byte) (n int, err error) { return m.writer.Write(b) }
func (m *mockConn) Close() error {
	m.reader.Close()
	m.writer.Close()
	return nil
}
func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

// BenchmarkTCPRelayWithMock benchmarks TCP relay with mock connections
func BenchmarkTCPRelayWithMock(b *testing.B) {
	// This benchmark uses mock connections to measure relay overhead
	// Note: Mock connections don't support splice, so this tests standard copy path

	b.Run("StandardCopy", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			c1, c2 := newMockConnPair()

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
			defer cancel()

			// Start relay in goroutine
			go func() {
				_, _ = copyWait(ctx, c1, c2)
			}()

			// Send some data
			data := make([]byte, 1400)
			_, _ = c2.Write(data)

			c1.Close()
			c2.Close()
		}
	})
}

// BenchmarkNetproxyReadFrom benchmarks netproxy.ReadFrom performance
func BenchmarkNetproxyReadFrom(b *testing.B) {
	// Create a simple in-memory pipe for testing
	r, w := io.Pipe()
	defer r.Close()
	defer w.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Write data
		go func() {
			data := make([]byte, 1400)
			w.Write(data)
		}()

		// Read data
		buf := make([]byte, 1400)
		r.Read(buf)
	}
}

// BenchmarkIOCopy vs netproxy.ReadFrom
func BenchmarkCopyMethods(b *testing.B) {
	data := make([]byte, 1400)
	for i := range data {
		data[i] = byte(i % 256)
	}

	b.Run("StandardIOCopy", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			r, w := io.Pipe()
			done := make(chan int64)

			go func() {
				n, _ := io.Copy(w, &reader{data: data})
				done <- n
			}()

			buf := make([]byte, len(data))
			r.Read(buf)
			r.Close()
			w.Close()
			<-done
		}
	})

	b.Run("NetproxyReadFrom", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			r, w := io.Pipe()
			done := make(chan int64)

			go func() {
				// Note: This will fallback to io.Copy for pipes
				n, _ := netproxy.ReadFrom(&mockWriter{w}, &reader{data: data})
				done <- n
			}()

			buf := make([]byte, len(data))
			r.Read(buf)
			r.Close()
			w.Close()
			<-done
		}
	})
}

// Helper types for benchmarking
type reader struct {
	data   []byte
	offset int
}

func (r *reader) Read(b []byte) (n int, err error) {
	if r.offset >= len(r.data) {
		return 0, io.EOF
	}
	n = copy(b, r.data[r.offset:])
	r.offset += n
	return n, nil
}

type mockWriter struct {
	*io.PipeWriter
}

func (m *mockWriter) SyscallConn() (syscall.RawConn, error) {
	// Return nil to simulate non-splice path
	return nil, io.ErrNoProgress
}
