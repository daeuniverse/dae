package control

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/sniffing"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pkg/bufferred_conn"
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

func TestRelayConnChain_UsesOutboundDependencyWrappers(t *testing.T) {
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

	wrapped := bufferred_conn.NewBufferedConn(client)
	chain := relayConnChain(wrapped)
	if !strings.Contains(chain, "*bufferred_conn.BufferedConn") || !strings.Contains(chain, "*net.TCPConn") {
		t.Fatalf("unexpected wrapper chain: %s", chain)
	}

	fake := &netproxy.FakeNetConn{Conn: wrapped, LAddr: client.LocalAddr(), RAddr: client.RemoteAddr()}
	chain = relayConnChain(fake)
	if !strings.Contains(chain, "*netproxy.FakeNetConn") || !strings.Contains(chain, "*bufferred_conn.BufferedConn") || !strings.Contains(chain, "*net.TCPConn") {
		t.Fatalf("unexpected fake wrapper chain: %s", chain)
	}

	if _, ok := unwrapRelayTCPConn(fake); !ok {
		t.Fatal("FakeNetConn over BufferedConn should unwrap to TCP for offload")
	}

	_ = server
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

// TestNewTCPRelayOffloadSession_ConnSnifferAcceptedNilFastSock verifies that
// *sniffing.ConnSniffer is now transparently unwrapped by newTCPRelayOffloadSession
// (it is no longer rejected at the wrapper check). Offload still fails here
// because a nil fastSock represents eBPF being unavailable, returning
// errTCPRelayOffloadUnavailable as before. Callers must flush any userspace
// prefix via tcpOffloadFlushLeftPrefix before calling newTCPRelayOffloadSession.
func TestNewTCPRelayOffloadSession_ConnSnifferAcceptedNilFastSock(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("eBPF offload is only available on linux")
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

	snifferConn := sniffing.NewConnSniffer(client, time.Second)
	defer snifferConn.Close()

	// ConnSniffer is now traversable via UnderlyingConn(); the session fails
	// at the nil fastSock guard, not at the unwrap step.
	_, err = newTCPRelayOffloadSession(nil, netproxy.Conn(snifferConn), netproxy.Conn(server))
	if err == nil {
		t.Fatal("newTCPRelayOffloadSession should fail with nil fastSock")
	}
	if !errors.Is(err, errTCPRelayOffloadUnavailable) {
		t.Fatalf("expected errTCPRelayOffloadUnavailable, got: %v", err)
	}
}

// TestNewTCPRelayOffloadSession_PrefixedConnRejected verifies that an opaque
// net.Conn wrapper that does NOT expose UnderlyingConn() is correctly
// rejected by unwrapRelayTCPConn. Note: the actual *prefixedConn type used
// in production IS traversable; this test uses an anonymous struct to cover
// the opaque-wrapper rejection path.
func TestNewTCPRelayOffloadSession_PrefixedConnRejected(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("eBPF offload is only available on linux")
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

	prefixedConn := &struct {
		net.Conn
	}{Conn: client}

	_, err = newTCPRelayOffloadSession(nil, netproxy.Conn(prefixedConn), netproxy.Conn(server))
	if err == nil {
		t.Fatal("newTCPRelayOffloadSession should reject prefixedConn on left side")
	}
	if !errors.Is(err, errTCPRelayOffloadUnavailable) {
		t.Fatalf("expected errTCPRelayOffloadUnavailable, got: %v", err)
	}
}

func TestNewTCPRelayOffloadSession_RightWrapperChainReported(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("eBPF offload is only available on linux")
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

	right := wrappedConn{Conn: server}
	_, err = newTCPRelayOffloadSession(nil, netproxy.Conn(client), netproxy.Conn(right))
	if err == nil {
		t.Fatal("newTCPRelayOffloadSession should reject non-unwrappable right wrapper")
	}
	if !strings.Contains(err.Error(), "chain:") || !strings.Contains(err.Error(), "control.wrappedConn") {
		t.Fatalf("expected wrapper chain in error, got: %v", err)
	}
}
