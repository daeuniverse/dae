package udphop

import (
	"net"
	"testing"
)

func TestParseUDPHopAddrPreservesHost(t *testing.T) {
	addr, err := ParseUDPHopAddr("example.com:443,8443-8444")
	if err != nil {
		t.Fatalf("ParseUDPHopAddr() error = %v", err)
	}
	if addr.Host != "example.com" {
		t.Fatalf("unexpected host: %q", addr.Host)
	}
	if addr.IP != nil {
		t.Fatalf("expected unresolved host, got IP %v", addr.IP)
	}
	if got, want := addr.String(), "example.com:443,8443-8444"; got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
	if got, want := len(addr.Ports), 3; got != want {
		t.Fatalf("len(Ports) = %d, want %d", got, want)
	}
}

func TestUDPHopAddrAddrsKeepsHostnameForSinglePorts(t *testing.T) {
	addr, err := ParseUDPHopAddr("example.com:443,8443")
	if err != nil {
		t.Fatalf("ParseUDPHopAddr() error = %v", err)
	}
	addrs, err := addr.addrs()
	if err != nil {
		t.Fatalf("addrs() error = %v", err)
	}
	if got, want := len(addrs), 2; got != want {
		t.Fatalf("len(addrs) = %d, want %d", got, want)
	}
	if got, want := addrs[0].String(), "example.com:443"; got != want {
		t.Fatalf("addrs[0] = %q, want %q", got, want)
	}
	if got, want := addrs[1].String(), "example.com:8443"; got != want {
		t.Fatalf("addrs[1] = %q, want %q", got, want)
	}
}

func TestResolveUDPHopAddrNormalizesHostToIP(t *testing.T) {
	addr, err := ResolveUDPHopAddr("127.0.0.1:443,8443")
	if err != nil {
		t.Fatalf("ResolveUDPHopAddr() error = %v", err)
	}
	if got, want := addr.Host, "127.0.0.1"; got != want {
		t.Fatalf("Host = %q, want %q", got, want)
	}
	if got := addr.IP.String(); got != "127.0.0.1" {
		t.Fatalf("IP = %q, want %q", got, "127.0.0.1")
	}
}

func TestUDPHopAddrAddrsReturnsUDPAddrForIPs(t *testing.T) {
	addr, err := ParseUDPHopAddr("127.0.0.1:443")
	if err != nil {
		t.Fatalf("ParseUDPHopAddr() error = %v", err)
	}
	addrs, err := addr.addrs()
	if err != nil {
		t.Fatalf("addrs() error = %v", err)
	}
	if got, want := len(addrs), 1; got != want {
		t.Fatalf("len(addrs) = %d, want %d", got, want)
	}
	if _, ok := addrs[0].(*net.UDPAddr); !ok {
		t.Fatalf("expected *net.UDPAddr, got %T", addrs[0])
	}
}
