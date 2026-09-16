//go:build linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net"
	"testing"
	"time"
)

// listenerAddrs mirrors the tcp4/tcp6/udp sockets a real Listener owns.
type listenerAddrs struct {
	tcp4 string
	tcp6 string
	udp  string
}

func newTestListener(t *testing.T) (*Listener, listenerAddrs) {
	t.Helper()
	tcp4, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp4: %v", err)
	}
	tcp6, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		_ = tcp4.Close()
		t.Fatalf("listen tcp6: %v", err)
	}
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		_ = tcp4.Close()
		_ = tcp6.Close()
		t.Fatalf("listen udp4: %v", err)
	}
	t.Cleanup(func() {
		_ = tcp4.Close()
		_ = tcp6.Close()
		_ = udp.Close()
	})
	return &Listener{
			tcp4Listener: tcp4,
			tcp6Listener: tcp6,
			packetConn:   udp,
		}, listenerAddrs{
			tcp4: tcp4.Addr().String(),
			tcp6: tcp6.Addr().String(),
			udp:  udp.LocalAddr().String(),
		}
}

// tryReclaim asserts that a previously bound address can be rebound without
// an explicit GC: a deterministic cleanup must have closed the duplicated
// socket synchronously with Clone's error return.
func tryReclaim(t *testing.T, kind, addr string, afterCloneErr error) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		var err error
		switch kind {
		case "tcp":
			var ln net.Listener
			ln, err = net.Listen("tcp", addr)
			if err == nil {
				_ = ln.Close()
				return
			}
		case "udp":
			var pc net.PacketConn
			pc, err = net.ListenPacket("udp", addr)
			if err == nil {
				_ = pc.Close()
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("address %s still occupied after Clone error (%v); partial clone sockets were not closed deterministically", addr, afterCloneErr)
}

func TestListenerCloneClosesPartialOnTcp6Failure(t *testing.T) {
	l, addrs := newTestListener(t)

	// Force the second duplication step to fail while the first succeeded:
	// closing tcp6 makes dupTCPListenerFile fail on its fd.
	_ = l.tcp6Listener.Close()

	cloned, err := l.Clone()
	if err == nil {
		t.Fatal("Clone() succeeded with a closed tcp6 listener; want error")
	}
	if cloned != nil {
		t.Fatalf("Clone() returned non-nil listener %p alongside error", cloned)
	}

	// Release the original sockets; the duplicated tcp4 socket created before
	// the failure must already be closed by Clone's cleanup.
	_ = l.tcp4Listener.Close()
	_ = l.packetConn.Close()
	tryReclaim(t, "tcp", addrs.tcp4, err)
}

func TestListenerCloneClosesPartialOnUdpFailure(t *testing.T) {
	l, addrs := newTestListener(t)

	// TCP4/TCP6 duplication succeeds; the UDP duplication fails.
	_ = l.packetConn.(*net.UDPConn).Close()

	cloned, err := l.Clone()
	if err == nil {
		t.Fatal("Clone() succeeded with a closed udp packet conn; want error")
	}
	if cloned != nil {
		t.Fatalf("Clone() returned non-nil listener %p alongside error", cloned)
	}

	_ = l.tcp4Listener.Close()
	_ = l.tcp6Listener.Close()
	tryReclaim(t, "tcp", addrs.tcp4, err)
	tryReclaim(t, "tcp", addrs.tcp6, err)
	tryReclaim(t, "udp", addrs.udp, err)
}

func TestListenerCloneSuccessDuplicatesAllSockets(t *testing.T) {
	l, addrs := newTestListener(t)

	cloned, err := l.Clone()
	if err != nil {
		t.Fatalf("Clone() failed: %v", err)
	}
	defer func() { _ = cloned.Close() }()

	// The duplicates must be independently usable and must own distinct fds:
	// closing the originals through the aggregate Close path must not tear
	// down the clones.
	if err := l.Close(); err != nil {
		t.Fatalf("close originals: %v", err)
	}
	conn, err := net.Dial("tcp", addrs.tcp4)
	if err != nil {
		t.Fatalf("dial original tcp4 addr: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if err := cloned.tcp4Listener.(*net.TCPListener).SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set accept deadline: %v", err)
	}
	accepted, err := cloned.tcp4Listener.Accept()
	if err != nil {
		t.Fatalf("cloned tcp4 listener did not accept after original close: %v", err)
	}
	_ = accepted.Close()

	// The cloned tcp6 socket must survive the same aggregate close.
	conn6, err := net.Dial("tcp", addrs.tcp6)
	if err != nil {
		t.Fatalf("dial original tcp6 addr: %v", err)
	}
	defer func() { _ = conn6.Close() }()
	if err := cloned.tcp6Listener.(*net.TCPListener).SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set accept deadline (tcp6): %v", err)
	}
	accepted6, err := cloned.tcp6Listener.Accept()
	if err != nil {
		t.Fatalf("cloned tcp6 listener did not accept after original close: %v", err)
	}
	_ = accepted6.Close()
}
