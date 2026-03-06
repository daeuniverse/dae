package control

import (
	"bytes"
	"net"
	"net/netip"
	"runtime"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/sniffing"
	"github.com/daeuniverse/outbound/netproxy"
)

func TestCanOffloadToEBPF_DirectTCPOnly(t *testing.T) {
	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	serverCh := make(chan *net.TCPConn, 1)
	errCh := make(chan error, 1)
	go func() {
		conn, e := ln.AcceptTCP()
		if e != nil {
			errCh <- e
			return
		}
		serverCh <- conn
	}()

	client, err := net.DialTCP("tcp", nil, ln.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	var server *net.TCPConn
	select {
	case e := <-errCh:
		t.Fatal(e)
	case server = <-serverCh:
	}
	defer server.Close()

	if runtime.GOOS != "linux" {
		t.Skip("socket offload eligibility is only meaningful on linux")
	}
	if !canOffloadToEBPF(netproxy.Conn(client), netproxy.Conn(server)) {
		t.Fatal("plain tcp sockets should be eligible for future eBPF offload")
	}
}

func TestCanOffloadToEBPF_ConnSnifferRejected(t *testing.T) {
	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	serverCh := make(chan *net.TCPConn, 1)
	errCh := make(chan error, 1)
	go func() {
		conn, e := ln.AcceptTCP()
		if e != nil {
			errCh <- e
			return
		}
		serverCh <- conn
	}()

	client, err := net.DialTCP("tcp", nil, ln.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	var server *net.TCPConn
	select {
	case e := <-errCh:
		t.Fatal(e)
	case server = <-serverCh:
	}
	defer server.Close()

	if runtime.GOOS != "linux" {
		t.Skip("socket offload eligibility is only meaningful on linux")
	}
	snifferConn := sniffing.NewConnSniffer(client, time.Second)
	defer snifferConn.Close()
	if canOffloadToEBPF(snifferConn, netproxy.Conn(server)) {
		t.Fatal("ConnSniffer should be rejected because it may buffer prefetched bytes")
	}
}

func TestCanOffloadToEBPF_WrappedConnRejected(t *testing.T) {
	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	serverCh := make(chan *net.TCPConn, 1)
	errCh := make(chan error, 1)
	go func() {
		conn, e := ln.AcceptTCP()
		if e != nil {
			errCh <- e
			return
		}
		serverCh <- conn
	}()

	client, err := net.DialTCP("tcp", nil, ln.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	var server *net.TCPConn
	select {
	case e := <-errCh:
		t.Fatal(e)
	case server = <-serverCh:
	}
	defer server.Close()

	if canOffloadToEBPF(wrappedConn{netproxy.Conn(client)}, netproxy.Conn(server)) {
		t.Fatal("generic wrappers should not be treated as eBPF-offload-safe")
	}
}

func TestCanOffloadToEBPF_IPv6Supported(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("socket offload eligibility is only meaningful on linux")
	}

	ln, err := net.ListenTCP("tcp6", &net.TCPAddr{IP: net.IPv6loopback, Port: 0})
	if err != nil {
		t.Skipf("IPv6 not available on this system: %v", err)
	}
	defer ln.Close()

	serverCh := make(chan *net.TCPConn, 1)
	errCh := make(chan error, 1)
	go func() {
		conn, e := ln.AcceptTCP()
		if e != nil {
			errCh <- e
			return
		}
		serverCh <- conn
	}()

	client, err := net.DialTCP("tcp6", nil, ln.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	var server *net.TCPConn
	select {
	case e := <-errCh:
		t.Fatal(e)
	case server = <-serverCh:
	}
	defer server.Close()

	if !canOffloadToEBPF(netproxy.Conn(client), netproxy.Conn(server)) {
		t.Fatal("plain IPv6 tcp sockets should be eligible for eBPF offload")
	}
}

func TestCanOffloadToEBPF_WrappedConnWithUnderlyingConn(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("socket offload eligibility is only meaningful on linux")
	}

	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	serverCh := make(chan *net.TCPConn, 1)
	errCh := make(chan error, 1)
	go func() {
		conn, e := ln.AcceptTCP()
		if e != nil {
			errCh <- e
			return
		}
		serverCh <- conn
	}()

	client, err := net.DialTCP("tcp", nil, ln.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	var server *net.TCPConn
	select {
	case e := <-errCh:
		t.Fatal(e)
	case server = <-serverCh:
	}
	defer server.Close()

	// Simulate SOCKS5-like wrapper that exposes UnderlyingConn
	wrappedClient := underlyingTCPWrapper{Conn: client, inner: client}
	wrappedServer := underlyingTCPWrapper{Conn: server, inner: server}

	// unwrapRelayTCPConn should be able to unwrap and allow offload
	_, clientOK := unwrapRelayTCPConn(wrappedClient)
	_, serverOK := unwrapRelayTCPConn(wrappedServer)
	if !clientOK || !serverOK {
		t.Fatal("wrapped TCP sockets with UnderlyingConn should be unwrappable for eBPF offload")
	}
}

func TestMakeTuplesKey_UsesRemoteToLocalSocketOrientation(t *testing.T) {
	src := netip.MustParseAddrPort("198.51.100.10:54321")
	dst := netip.MustParseAddrPort("203.0.113.80:443")

	key := makeTuplesKey(src, dst, 6)
	src16 := src.Addr().As16()
	dst16 := dst.Addr().As16()

	if key.Sport != 0x31d4 {
		t.Fatalf("unexpected source port encoding: got %#x", key.Sport)
	}
	if key.Dport != 0xbb01 {
		t.Fatalf("unexpected destination port encoding: got %#x", key.Dport)
	}
	if !bytes.Equal(key.Sip.U6Addr8[:], src16[:]) {
		t.Fatal("source ip encoding mismatch")
	}
	if !bytes.Equal(key.Dip.U6Addr8[:], dst16[:]) {
		t.Fatal("destination ip encoding mismatch")
	}
}
