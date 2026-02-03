package control

import (
	"errors"
	"io"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
)

// Ensure mockConn implements netproxy.Conn
var _ netproxy.Conn = (*mockConn)(nil)

// Mock connection implementing netproxy.Conn
type mockConn struct {
	readBlock  chan struct{}
	readRetErr error
	deadline   time.Time
	mu         sync.Mutex
	once       sync.Once
	closed     bool
}

func newMockConn(block bool, retErr error) *mockConn {
	m := &mockConn{
		readBlock:  make(chan struct{}),
		readRetErr: retErr,
	}
	if !block {
		m.once.Do(func() {
			close(m.readBlock)
		})
	}
	return m
}

func (m *mockConn) Read(b []byte) (n int, err error) {
	if m.closed {
		return 0, io.EOF
	}
	<-m.readBlock

	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if deadline triggered
	if !m.deadline.IsZero() && m.deadline.Before(time.Now()) {
		return 0, os.ErrDeadlineExceeded
	}

	if m.readRetErr != nil {
		return 0, m.readRetErr
	}
	return 0, io.EOF
}

func (m *mockConn) Write(b []byte) (n int, err error) {
	return len(b), nil
}

func (m *mockConn) Close() error {
	m.closed = true
	return nil
}

func (m *mockConn) SetDeadline(t time.Time) error {
	return m.SetReadDeadline(t)
}

func (m *mockConn) SetReadDeadline(t time.Time) error {
	m.mu.Lock()
	m.deadline = t
	m.mu.Unlock()

	// If deadline is in the past, unblock Read
	if !t.IsZero() && t.Before(time.Now()) {
		m.once.Do(func() {
			close(m.readBlock)
		})
	}
	return nil
}

func (m *mockConn) SetWriteDeadline(t time.Time) error {
	return nil
}

// Satisfy WriteCloser interface check in RelayTCP
func (m *mockConn) CloseWrite() error {
	return nil
}

func TestRelayTCP_Cancellation(t *testing.T) {
	// Scenario:
	// lConn is blocked on Read.
	// rConn returns an error immediately.
	// RelayTCP should detect rConn error, cancel context, and force lConn to unblock via SetReadDeadline.

	lConn := newMockConn(true, nil) // blocking
	rConn := newMockConn(false, errors.New("immediate error"))

	// Run RelayTCP in a goroutine or just call it since it should return.
	// We expect it to return quickly.
	done := make(chan error)
	go func() {
		done <- RelayTCP(lConn, rConn)
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		// In RelayTCP:
		// 1. copyWait(ctx, lConn, rConn) -> io.Copy(lConn, rConn) returns error (rConn read fails)
		// 2. copyWait returns, context canceled.
		// 3. The other goroutine: copyWait(ctx, rConn, lConn) -> io.Copy(rConn, lConn) is blocked.
		// 4. Context cancel triggers lConn.SetReadDeadline.
		// 5. lConn.Read unblocks with ErrDeadlineExceeded.
		// 6. RelayTCP collects errors.

		// The error returned is usually the first one or combined.
		// Since rConn failed first, we expect "immediate error".
		if !errors.Is(err, rConn.readRetErr) {
			// It might be wrapped
			if err.Error() != "immediate error" && !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Logf("Got error: %v", err)
			}
		}
	case <-time.After(2 * time.Second):
		t.Fatal("RelayTCP timed out - deadlock suspected")
	}

	// Verify lConn.SetReadDeadline was called with past time
	lConn.mu.Lock()
	dl := lConn.deadline
	lConn.mu.Unlock()

	if dl.IsZero() {
		t.Error("lConn.SetReadDeadline should have been called")
	} else if !dl.Before(time.Now()) {
		t.Errorf("lConn.SetReadDeadline should be in the past, got %v", dl)
	}
}
