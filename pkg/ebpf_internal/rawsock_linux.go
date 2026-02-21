// Copied from https://github.com/cilium/ebpf/blob/v0.10.0/example_sock_elf_test.go

package internal

import (
	"encoding/binary"
	"syscall"
)

// Htons converts the unsigned short integer from host byte order to network byte order (big-endian).
// This is used for socket protocol numbers which are expected in network byte order.
func Htons(i uint16) uint16 {
	// Use binary.BigEndian.Uint16 to properly convert from big-endian bytes to uint16.
	// This ensures the result is correct regardless of the host's native endianness.
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i)
	return binary.BigEndian.Uint16(b)
}

func OpenRawSock(index int) (int, error) {
	sock, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, int(Htons(syscall.ETH_P_ALL)))
	if err != nil {
		return 0, err
	}
	sll := syscall.SockaddrLinklayer{
		Ifindex:  index,
		Protocol: Htons(syscall.ETH_P_ALL),
	}
	if err := syscall.Bind(sock, &sll); err != nil {
		return 0, err
	}
	return sock, nil
}
