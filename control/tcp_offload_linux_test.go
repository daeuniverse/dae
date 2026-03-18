//go:build linux
// +build linux

package control

import (
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/sniffing"
	"github.com/daeuniverse/outbound/netproxy"
)

func TestIsLocalConnection_LoopbackToLoopback(t *testing.T) {
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

	if !isLocalConnection(client, server) {
		t.Fatal("expected loopback-to-loopback connection to be detected as local")
	}
}

func TestIsLocalConnection_RemoteIsLoopback(t *testing.T) {
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

	// When connecting to loopback, the remote address is loopback
	if !isLocalConnection(client, server) {
		t.Fatal("expected connection to loopback remote to be detected as local")
	}
}

func TestIsLocalConnection_IPv6Loopback(t *testing.T) {
	ln, err := net.ListenTCP("tcp6", &net.TCPAddr{IP: net.IPv6loopback, Port: 0})
	if err != nil {
		t.Skipf("IPv6 not available: %v", err)
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
		t.Skipf("IPv6 dial not available: %v", err)
	}
	defer client.Close()

	var server *net.TCPConn
	select {
	case e := <-errCh:
		t.Fatal(e)
	case server = <-serverCh:
	}
	defer server.Close()

	if !isLocalConnection(client, server) {
		t.Fatal("expected IPv6 loopback-to-loopback connection to be detected as local")
	}
}

func TestMakeHostLocalAddrChecker(t *testing.T) {
	checker := makeHostLocalAddrChecker([]netip.Addr{
		netip.MustParseAddr("192.0.2.10"),
		netip.MustParseAddr("2001:db8::10"),
	})

	tests := []struct {
		name  string
		left  string
		right string
		want  bool
	}{
		{
			name:  "loopback peers stay local",
			left:  "127.0.0.1",
			right: "::1",
			want:  true,
		},
		{
			name:  "configured local and loopback are local-to-local",
			left:  "192.0.2.10",
			right: "127.0.0.1",
			want:  true,
		},
		{
			name:  "ipv4 mapped local is converged",
			left:  "::ffff:192.0.2.10",
			right: "127.0.0.1",
			want:  true,
		},
		{
			name:  "only one peer local is not local-to-local",
			left:  "192.0.2.10",
			right: "198.51.100.20",
			want:  false,
		},
		{
			name:  "neither peer local is not local-to-local",
			left:  "198.51.100.20",
			right: "203.0.113.30",
			want:  false,
		},
		{
			name:  "two configured host addresses are local-to-local",
			left:  "192.0.2.10",
			right: "2001:db8::10",
			want:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			left := netip.MustParseAddr(tc.left)
			right := netip.MustParseAddr(tc.right)
			if got := checker(left) && checker(right); got != tc.want {
				t.Fatalf("checker(%s, %s) = %v, want %v", tc.left, tc.right, got, tc.want)
			}
		})
	}
}

func TestTcpConnHasPendingReadData(t *testing.T) {
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

	pending, err := tcpConnHasPendingReadData(server)
	if err != nil {
		t.Fatal(err)
	}
	if pending {
		t.Fatal("fresh server socket should not report pending data")
	}

	if _, err := client.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		pending, err = tcpConnHasPendingReadData(server)
		if err != nil {
			t.Fatal(err)
		}
		if pending {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("server socket never reported pending data")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestTcpConnSupportsEBPFRedirect_IPv4AndIPv6(t *testing.T) {
	ln4, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer ln4.Close()

	acc4 := make(chan *net.TCPConn, 1)
	go func() {
		conn, _ := ln4.AcceptTCP()
		acc4 <- conn
	}()
	c4, err := net.DialTCP("tcp4", nil, ln4.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer c4.Close()
	s4 := <-acc4
	defer s4.Close()

	if !tcpConnSupportsEBPFRedirect(c4) || !tcpConnSupportsEBPFRedirect(s4) {
		t.Fatal("ipv4 tcp sockets should be offload eligible")
	}

	ln6, err := net.ListenTCP("tcp6", &net.TCPAddr{IP: net.IPv6loopback, Port: 0})
	if err != nil {
		t.Skipf("ipv6 unavailable: %v", err)
	}
	defer ln6.Close()

	acc6 := make(chan *net.TCPConn, 1)
	go func() {
		conn, _ := ln6.AcceptTCP()
		acc6 <- conn
	}()
	c6, err := net.DialTCP("tcp6", nil, ln6.Addr().(*net.TCPAddr))
	if err != nil {
		t.Skipf("ipv6 dial unavailable: %v", err)
	}
	defer c6.Close()
	s6 := <-acc6
	defer s6.Close()

	if !tcpConnSupportsEBPFRedirect(c6) || !tcpConnSupportsEBPFRedirect(s6) {
		t.Fatal("ipv6 tcp sockets should be offload eligible")
	}
}

func TestNewTCPRelayOffloadSession_LocalConnectionAccepted(t *testing.T) {
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

	// newTCPRelayOffloadSession should no longer reject local-to-local connections.
	// The eBPF sockmap/sockops is specifically designed to optimize local-to-local
	// traffic by bypassing the kernel TCP/IP stack.
	//
	// The session creation will still fail here because we pass nil for the eBPF map,
	// but the error should be about the missing map, not about local connection.
	_, err = newTCPRelayOffloadSession(nil, netproxy.Conn(client), netproxy.Conn(server))
	if err == nil {
		t.Fatal("newTCPRelayOffloadSession should fail when fast_sock map is nil")
	}
	if !errors.Is(err, errTCPRelayOffloadUnavailable) {
		t.Fatalf("expected errTCPRelayOffloadUnavailable, got: %v", err)
	}
	// Verify the error is NOT about local connection being rejected
	if strings.Contains(err.Error(), "local to local connection") {
		t.Fatalf("local connections should not be rejected, got error: %v", err)
	}
	// The error should be about the missing map
	if !strings.Contains(err.Error(), "fast_sock map") {
		t.Fatalf("expected 'fast_sock map' error, got: %v", err)
	}
}

// TestTcpOffloadFlushLeftPrefix_ConnSniffer verifies that ConnSniffer
// implements the necessary interfaces for eBPF offload after sniffing.
func TestTcpOffloadFlushLeftPrefix_ConnSniffer(t *testing.T) {
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

	// Wrap server in ConnSniffer
	sniffer := sniffing.NewConnSniffer(server, time.Second)
	defer sniffer.Close()

	// Verify ConnSniffer can be unwrapped for eBPF offload
	unwrapped, ok := unwrapRelayTCPConn(sniffer)
	if !ok {
		t.Fatal("ConnSniffer should be unwrappable to *net.TCPConn")
	}
	if unwrapped != server {
		t.Fatal("unwrapped conn should be the original server conn")
	}

	// Verify ConnSniffer has TakeRelayPrefix method (implements relayPrefixSource)
	// This is verified at compile time - just call it to ensure it exists
	_ = sniffer.TakeRelayPrefix

	// Verify TIOCINQ check works on fresh connection
	hasPending, err := tcpConnHasPendingReadData(server)
	if err != nil {
		t.Fatalf("tcpConnHasPendingReadData failed: %v", err)
	}
	if hasPending {
		t.Fatal("fresh connection should have no pending data")
	}

	// Client sends TLS Client Hello (simulated)
	testData := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	if _, err := client.Write(testData); err != nil {
		t.Fatal(err)
	}

	// Wait for data to arrive in server's kernel queue (TIOCINQ > 0)
	deadline := time.Now().Add(2 * time.Second)
	for {
		hasPending, err = tcpConnHasPendingReadData(server)
		if err != nil {
			t.Fatalf("tcpConnHasPendingReadData failed: %v", err)
		}
		if hasPending {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("data never arrived in kernel queue")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// After sniffing consumes data, TIOCINQ should return 0
	// This is verified in integration tests where SniffTcp() is called
	// For this unit test, we just verify the TIOCINQ mechanism works

	// At this point, if SniffTcp() were called:
	// 1. Data would be read from kernel queue (TIOCINQ -> 0)
	// 2. Data would be buffered in ConnSniffer
	// 3. TakeRelayPrefix() would return the buffered data
	// 4. tcpOffloadFlushLeftPrefix() would flush it to the other peer
	// 5. eBPF offload would be eligible (both connections unwrappable, TIOCINQ=0)
}
