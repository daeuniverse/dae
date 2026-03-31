package errors

import (
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
