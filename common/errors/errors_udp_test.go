package errors

import (
	"context"
	stderrors "errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"testing"

	"github.com/olicesx/quic-go"
)

func TestIsUDPEndpointNormalClose_ConnectionRefused(t *testing.T) {
	err := &net.OpError{
		Op:  "read",
		Net: "udp",
		Err: &os.SyscallError{
			Syscall: "read",
			Err:     syscall.ECONNREFUSED,
		},
	}

	if IsUDPEndpointNormalClose(err) {
		t.Fatalf("expected ECONNREFUSED to be treated as a real UDP endpoint failure, got normal close")
	}
}

func TestIsUDPEndpointNormalClose_WebsocketNormalClosure(t *testing.T) {
	err := stderrors.New("websocket: close 1000 (normal)")
	if !IsUDPEndpointNormalClose(err) {
		t.Fatal("expected websocket normal closure to be treated as normal close")
	}
}

func TestIsIgnorableTCPRelayError_WebsocketNormalClosure(t *testing.T) {
	err := stderrors.New("websocket: close 1000 (normal)")
	if !IsIgnorableTCPRelayError(err) {
		t.Fatal("expected websocket normal closure to be ignored for TCP relay")
	}
}

func TestIsIgnorableConnectionError_WebsocketNormalClosure(t *testing.T) {
	err := stderrors.New("websocket: close 1000 (normal)")
	if !IsIgnorableConnectionError(err) {
		t.Fatal("expected websocket normal closure to be ignored for connection handling")
	}
}

func TestIsCanceledOrClosed_ContextCanceled(t *testing.T) {
	if !IsCanceledOrClosed(context.Canceled) {
		t.Fatal("expected context cancellation to be treated as teardown")
	}
}

func TestIsCanceledOrClosed_OperationCanceledString(t *testing.T) {
	err := stderrors.New("dial tcp 1.2.3.4:443: operation was canceled")
	if !IsCanceledOrClosed(err) {
		t.Fatal("expected operation was canceled to be treated as teardown")
	}
	if !IsIgnorableConnectionError(err) {
		t.Fatal("expected operation was canceled to be ignored for connection handling")
	}
}

func TestTypedQUICStreamErrorCodeZeroIsNormalClose(t *testing.T) {
	err := &quic.StreamError{StreamID: 1, ErrorCode: 0, Remote: true}
	if !IsIgnorableTCPRelayError(err) {
		t.Fatal("expected StreamError code 0 to be ignorable for TCP relay")
	}
	if !IsUDPEndpointNormalClose(err) {
		t.Fatal("expected StreamError code 0 to be a normal UDP close")
	}

	wrapped := fmt.Errorf("relay: %w", err)
	if !IsIgnorableTCPRelayError(wrapped) {
		t.Fatal("expected wrapped StreamError code 0 to be ignorable")
	}
	if !IsUDPEndpointNormalClose(wrapped) {
		t.Fatal("expected wrapped StreamError code 0 to be a normal UDP close")
	}

	nonzero := &quic.StreamError{StreamID: 1, ErrorCode: 1, Remote: true}
	if IsIgnorableTCPRelayError(nonzero) {
		t.Fatal("StreamError with a non-zero code must not be treated as ignorable")
	}
	if IsUDPEndpointNormalClose(nonzero) {
		t.Fatal("StreamError with a non-zero code must not be a normal UDP close")
	}
}

// TestReplayFamilyClassificationCoversExpiredTimestamps pins the consumer side
// of the outbound classification split. SS2022 reports a message timestamp
// outside its clock window with its own sentinel ("timestamp expired"); that
// rejection is still a per-packet anti-replay rejection, so it must keep the
// soft classification here instead of retiring the UDP endpoint on the first
// skewed reply.
func TestReplayFamilyClassificationCoversExpiredTimestamps(t *testing.T) {
	replay := stderrors.New("replay attack")
	expired := stderrors.New("timestamp expired")
	wrapped := fmt.Errorf("udp read: %w", expired)

	for _, err := range []error{replay, expired, wrapped} {
		if !IsReplayAttackError(err) {
			t.Fatalf("%v must be classified as a replay-family rejection", err)
		}
		if !IsUDPEndpointNormalClose(err) {
			t.Fatalf("%v must stay a soft (normal-close) UDP endpoint error", err)
		}
	}

	// The classification must not widen: an unrelated transport failure keeps
	// retiring the endpoint.
	fatal := stderrors.New("unexpected EOF")
	if IsReplayAttackError(fatal) {
		t.Fatalf("%v must not be classified as a replay", fatal)
	}
	if IsUDPEndpointNormalClose(fatal) {
		t.Fatalf("%v must not be a normal UDP close", fatal)
	}
}
