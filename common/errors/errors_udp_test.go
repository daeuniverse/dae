package errors

import (
	stderrors "errors"
	"net"
	"os"
	"syscall"
	"testing"
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
