package common

import (
	"net/netip"
	"sync"
)

var uniqueFakeAddrPort = struct {
	addr netip.Addr
	port uint16
	mu   sync.Mutex
}{
	addr: netip.MustParseAddr("::1"),
	mu:   sync.Mutex{},
}

func GetUniqueFakeAddrPort() (fake netip.AddrPort) {
	uniqueFakeAddrPort.mu.Lock()
	if uniqueFakeAddrPort.port == 65535 {
		uniqueFakeAddrPort.addr = uniqueFakeAddrPort.addr.Next()
		uniqueFakeAddrPort.port = 0
	} else {
		uniqueFakeAddrPort.port++
	}
	fake = netip.AddrPortFrom(uniqueFakeAddrPort.addr, uniqueFakeAddrPort.port)
	uniqueFakeAddrPort.mu.Unlock()
	return fake
}
