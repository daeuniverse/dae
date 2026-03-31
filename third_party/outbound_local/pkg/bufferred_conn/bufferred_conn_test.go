package bufferred_conn

import (
	"io"
	"net"
	"testing"
)

func TestBufferedConnUnderlyingConn(t *testing.T) {
	left, right := net.Pipe()
	defer func() { _ = left.Close() }()
	defer func() { _ = right.Close() }()

	conn := NewBufferedConn(left)
	if got := conn.UnderlyingConn(); got != left {
		t.Fatalf("unexpected underlying conn: got %T want %T", got, left)
	}
}

func TestBufferedConnTakeRelayPrefix(t *testing.T) {
	left, right := net.Pipe()
	defer func() { _ = left.Close() }()
	defer func() { _ = right.Close() }()

	conn := NewBufferedConnSize(left, 64)
	defer func() { _ = conn.Close() }()

	payload := []byte("prefetched-body")
	writeErr := make(chan error, 1)
	go func() {
		_, err := right.Write(payload)
		defer func() { _ = right.Close() }()
		writeErr <- err
	}()

	prefetched, err := conn.Peek(len("prefetched-"))
	if err != nil {
		t.Fatalf("peek failed: %v", err)
	}
	if string(prefetched) != "prefetched-" {
		t.Fatalf("unexpected prefetched bytes: %q", prefetched)
	}

	prefix := conn.TakeRelayPrefix()
	if string(prefix) != "prefetched-body" {
		t.Fatalf("unexpected relay prefix: %q", prefix)
	}

	rest, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read remaining payload failed: %v", err)
	}
	if len(rest) != 0 {
		t.Fatalf("unexpected remaining payload: %q", rest)
	}

	if err := <-writeErr; err != nil {
		t.Fatalf("writer failed: %v", err)
	}
}
