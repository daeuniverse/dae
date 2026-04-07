/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"runtime/debug"
	"strconv"
	"syscall"
	"testing"
	"time"
)

func waitChannelResult[T any](t *testing.T, ch <-chan T, timeout time.Duration, what string) T {
	t.Helper()

	select {
	case result := <-ch:
		return result
	case <-time.After(timeout):
		t.Fatalf("timeout waiting for %s", what)
		var zero T
		return zero
	}
}

func sampleHeapAlloc() uint64 {
	runtime.GC()
	debug.FreeOSMemory()

	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	return stats.HeapAlloc
}

func startListenerBlockingWorkers(t *testing.T, listener *Listener, payloadBytes int) (<-chan error, <-chan error) {
	t.Helper()

	tcpStarted := make(chan struct{})
	tcpDone := make(chan error, 1)
	tcpPayload := make([]byte, payloadBytes)
	tcpPayload[0] = 0x1
	go func(payload []byte) {
		close(tcpStarted)
		_, err := listener.tcp4Listener.Accept()
		if err == nil {
			err = fmt.Errorf("accept returned nil error after close")
		}
		payload[0] ^= 0x1
		tcpDone <- err
	}(tcpPayload)
	<-tcpStarted

	udpStarted := make(chan struct{})
	udpDone := make(chan error, 1)
	udpPayload := make([]byte, payloadBytes)
	udpPayload[0] = 0x2
	go func(payload []byte) {
		close(udpStarted)
		buf := make([]byte, 1)
		_, _, err := listener.packetConn.ReadFrom(buf)
		if err == nil {
			err = fmt.Errorf("read returned nil error after close")
		}
		payload[0] ^= 0x2
		udpDone <- err
	}(udpPayload)
	<-udpStarted

	return tcpDone, udpDone
}

func TestListenerCloneCloseOriginalKeepsCloneServing(t *testing.T) {
	tcp4Listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp4: %v", err)
	}
	udpConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		_ = tcp4Listener.Close()
		t.Fatalf("listen udp4: %v", err)
	}

	original := &Listener{
		tcp4Listener: tcp4Listener,
		packetConn:   udpConn,
	}

	cloned, err := original.Clone()
	if err != nil {
		_ = original.Close()
		t.Fatalf("clone listener: %v", err)
	}
	defer func() { _ = cloned.Close() }()

	tcpBlocked := make(chan struct{})
	tcpAcceptDone := make(chan error, 1)
	go func() {
		close(tcpBlocked)
		_, err := original.tcp4Listener.Accept()
		if err == nil {
			err = fmt.Errorf("accept returned nil error after close")
		}
		tcpAcceptDone <- err
	}()
	<-tcpBlocked

	udpBlocked := make(chan struct{})
	udpReadDone := make(chan error, 1)
	go func() {
		close(udpBlocked)
		buf := make([]byte, 1)
		_, _, err := original.packetConn.ReadFrom(buf)
		if err == nil {
			err = fmt.Errorf("read returned nil error after close")
		}
		udpReadDone <- err
	}()
	<-udpBlocked

	if err := original.Close(); err != nil {
		t.Fatalf("close original listener: %v", err)
	}

	if err := waitChannelResult(t, tcpAcceptDone, time.Second, "original tcp accept to exit"); err == nil {
		t.Fatal("expected original tcp accept to exit with error")
	}
	if err := waitChannelResult(t, udpReadDone, time.Second, "original udp read to exit"); err == nil {
		t.Fatal("expected original udp read to exit with error")
	}

	tcpServeDone := make(chan error, 1)
	go func() {
		conn, err := cloned.tcp4Listener.Accept()
		if err == nil {
			_ = conn.Close()
		}
		tcpServeDone <- err
	}()

	client, err := net.DialTimeout("tcp4", cloned.tcp4Listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("dial cloned tcp4 listener: %v", err)
	}
	_ = client.Close()

	if err := waitChannelResult(t, tcpServeDone, time.Second, "cloned tcp accept"); err != nil {
		t.Fatalf("cloned tcp accept failed: %v", err)
	}

	udpServeDone := make(chan error, 1)
	go func() {
		buf := make([]byte, 16)
		if err := cloned.packetConn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			udpServeDone <- err
			return
		}
		n, _, err := cloned.packetConn.ReadFrom(buf)
		if err == nil && string(buf[:n]) != "x" {
			err = fmt.Errorf("unexpected udp payload %q", string(buf[:n]))
		}
		udpServeDone <- err
	}()

	udpClient, err := net.DialTimeout("udp4", cloned.packetConn.LocalAddr().String(), time.Second)
	if err != nil {
		t.Fatalf("dial cloned udp listener: %v", err)
	}
	if _, err := udpClient.Write([]byte("x")); err != nil {
		_ = udpClient.Close()
		t.Fatalf("write cloned udp listener: %v", err)
	}
	_ = udpClient.Close()

	if err := waitChannelResult(t, udpServeDone, time.Second, "cloned udp read"); err != nil {
		t.Fatalf("cloned udp read failed: %v", err)
	}
}

func TestListenerCloneCloseOriginalKeepsTCP6CloneServing(t *testing.T) {
	tcp6Listener, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("listen tcp6 unsupported: %v", err)
	}

	original := &Listener{
		tcp6Listener: tcp6Listener,
	}

	cloned, err := original.Clone()
	if err != nil {
		_ = original.Close()
		t.Fatalf("clone tcp6 listener: %v", err)
	}
	defer func() { _ = cloned.Close() }()

	acceptDone := make(chan error, 1)
	go func() {
		_, err := original.tcp6Listener.Accept()
		if err == nil {
			err = fmt.Errorf("accept returned nil error after close")
		}
		acceptDone <- err
	}()

	if err := original.Close(); err != nil {
		t.Fatalf("close original tcp6 listener: %v", err)
	}
	if err := waitChannelResult(t, acceptDone, time.Second, "original tcp6 accept to exit"); err == nil {
		t.Fatal("expected original tcp6 accept to exit with error")
	}

	serveDone := make(chan error, 1)
	go func() {
		conn, err := cloned.tcp6Listener.Accept()
		if err == nil {
			_ = conn.Close()
		}
		serveDone <- err
	}()

	client, err := net.DialTimeout("tcp6", cloned.tcp6Listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("dial cloned tcp6 listener: %v", err)
	}
	_ = client.Close()

	if err := waitChannelResult(t, serveDone, time.Second, "cloned tcp6 accept"); err != nil {
		t.Fatalf("cloned tcp6 accept failed: %v", err)
	}
}

func TestListenerCloneCloseOriginalKeepsDualStackUDPCloneServing(t *testing.T) {
	listenConfig := net.ListenConfig{
		Control: func(_, _ string, c syscall.RawConn) error {
			return enableUDPDualStackSocket(c)
		},
	}
	packetConn, err := listenConfig.ListenPacket(context.Background(), "udp6", "[::]:0")
	if err != nil {
		t.Skipf("listen dual-stack udp6 unsupported: %v", err)
	}

	original := &Listener{
		packetConn: packetConn,
	}

	cloned, err := original.Clone()
	if err != nil {
		_ = original.Close()
		t.Fatalf("clone dual-stack udp listener: %v", err)
	}
	defer func() { _ = cloned.Close() }()

	readDone := make(chan error, 1)
	go func() {
		buf := make([]byte, 1)
		_, _, err := original.packetConn.ReadFrom(buf)
		if err == nil {
			err = fmt.Errorf("read returned nil error after close")
		}
		readDone <- err
	}()

	if err := original.Close(); err != nil {
		t.Fatalf("close original dual-stack udp listener: %v", err)
	}
	if err := waitChannelResult(t, readDone, time.Second, "original dual-stack udp read to exit"); err == nil {
		t.Fatal("expected original dual-stack udp read to exit with error")
	}

	udpAddr, ok := cloned.packetConn.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("unexpected cloned packetConn local addr type %T", cloned.packetConn.LocalAddr())
	}
	serveDone := make(chan error, 1)
	go func() {
		buf := make([]byte, 16)
		if err := cloned.packetConn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			serveDone <- err
			return
		}
		n, _, err := cloned.packetConn.ReadFrom(buf)
		if err == nil && string(buf[:n]) != "v4-over-v6" {
			err = fmt.Errorf("unexpected udp payload %q", string(buf[:n]))
		}
		serveDone <- err
	}()

	udpClient, err := net.DialTimeout("udp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(udpAddr.Port)), time.Second)
	if err != nil {
		t.Fatalf("dial cloned dual-stack udp listener over udp4: %v", err)
	}
	if _, err := udpClient.Write([]byte("v4-over-v6")); err != nil {
		_ = udpClient.Close()
		t.Fatalf("write cloned dual-stack udp listener: %v", err)
	}
	_ = udpClient.Close()

	if err := waitChannelResult(t, serveDone, time.Second, "cloned dual-stack udp read"); err != nil {
		t.Fatalf("cloned dual-stack udp read failed: %v", err)
	}
}

func TestListenerCloneReloadLikeCyclesKeepHeapFlat(t *testing.T) {
	const (
		reloadLikeCycles     = 12
		payloadPerWorker     = 2 << 20
		maxHeapGrowth        = 8 << 20
		workersPerGeneration = 2
	)

	tcp4Listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp4: %v", err)
	}
	udpConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		_ = tcp4Listener.Close()
		t.Fatalf("listen udp4: %v", err)
	}

	current := &Listener{
		tcp4Listener: tcp4Listener,
		packetConn:   udpConn,
	}
	t.Cleanup(func() {
		if current != nil {
			_ = current.Close()
		}
	})

	baseGoroutines := runtime.NumGoroutine()
	baseHeap := sampleHeapAlloc()

	for i := 0; i < reloadLikeCycles; i++ {
		tcpDone, udpDone := startListenerBlockingWorkers(t, current, payloadPerWorker)

		cloned, err := current.Clone()
		if err != nil {
			t.Fatalf("cycle %d: clone listener: %v", i+1, err)
		}
		if err := current.Close(); err != nil {
			_ = cloned.Close()
			t.Fatalf("cycle %d: close current listener: %v", i+1, err)
		}
		current = cloned

		if err := waitChannelResult(t, tcpDone, time.Second, fmt.Sprintf("cycle %d tcp accept exit", i+1)); err == nil {
			t.Fatalf("cycle %d: expected tcp accept to exit with error", i+1)
		}
		if err := waitChannelResult(t, udpDone, time.Second, fmt.Sprintf("cycle %d udp read exit", i+1)); err == nil {
			t.Fatalf("cycle %d: expected udp read to exit with error", i+1)
		}
	}

	if err := current.Close(); err != nil {
		t.Fatalf("close final listener: %v", err)
	}
	current = nil

	time.Sleep(100 * time.Millisecond)
	finalHeap := sampleHeapAlloc()
	finalGoroutines := runtime.NumGoroutine()

	var heapGrowth uint64
	if finalHeap > baseHeap {
		heapGrowth = finalHeap - baseHeap
	}

	theoreticalLeak := reloadLikeCycles * workersPerGeneration * payloadPerWorker
	t.Logf(
		"reload-like cycles=%d payload_per_worker=%dKiB theoretical_leak_if_old_generations_stick=%dKiB heap_growth=%dKiB goroutines_before=%d goroutines_after=%d",
		reloadLikeCycles,
		payloadPerWorker/1024,
		theoreticalLeak/1024,
		heapGrowth/1024,
		baseGoroutines,
		finalGoroutines,
	)

	if heapGrowth > maxHeapGrowth {
		t.Fatalf(
			"heap grew by %dKiB after %d listener reload-like cycles; want <= %dKiB",
			heapGrowth/1024,
			reloadLikeCycles,
			maxHeapGrowth/1024,
		)
	}
	if finalGoroutines > baseGoroutines+2 {
		t.Fatalf(
			"goroutines grew from %d to %d after listener reload-like cycles; want <= %d",
			baseGoroutines,
			finalGoroutines,
			baseGoroutines+2,
		)
	}
}

func TestListenerCloseReturnsPromptlyAfterServeLikeFileExports(t *testing.T) {
	tcp4Listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp4: %v", err)
	}
	udpConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		_ = tcp4Listener.Close()
		t.Fatalf("listen udp4: %v", err)
	}

	listener := &Listener{
		tcp4Listener: tcp4Listener,
		packetConn:   udpConn,
	}

	tcpFile, err := dupTCPListenerFile(listener.tcp4Listener)
	if err != nil {
		_ = listener.Close()
		t.Fatalf("dupTCPListenerFile(): %v", err)
	}
	defer func() { _ = tcpFile.Close() }()

	udpFile, err := dupUDPPacketConnFile(listener.packetConn)
	if err != nil {
		_ = listener.Close()
		t.Fatalf("dupUDPPacketConnFile(): %v", err)
	}
	defer func() { _ = udpFile.Close() }()

	cloned, err := listener.Clone()
	if err != nil {
		_ = listener.Close()
		t.Fatalf("clone listener: %v", err)
	}
	defer func() { _ = cloned.Close() }()

	tcpDone, udpDone := startListenerBlockingWorkers(t, listener, 1)

	closeDone := make(chan error, 1)
	go func() {
		closeDone <- listener.Close()
	}()

	if err := waitChannelResult(t, closeDone, time.Second, "listener close"); err != nil {
		t.Fatalf("listener close failed: %v", err)
	}
	if err := waitChannelResult(t, tcpDone, time.Second, "tcp accept exit"); err == nil {
		t.Fatal("expected tcp accept to exit with error")
	}
	if err := waitChannelResult(t, udpDone, time.Second, "udp read exit"); err == nil {
		t.Fatal("expected udp read to exit with error")
	}
}
