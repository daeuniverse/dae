//go:build linux
// +build linux

package control

import (
	"net"
	"testing"
	"time"
)

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
		t.Fatal("ipv6 tcp sockets should now be offload eligible with sk_skb ipv6 support")
	}
}
