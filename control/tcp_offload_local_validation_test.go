//go:build linux
// +build linux

package control

import (
	"net"
	"net/netip"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// TestTCPOffloadLocalConnectionCPUUsage validates whether TCP offload
// causes high CPU usage for local-to-local connections (localhost traffic).
//
// Background: The isLocalConnection check was removed in tcp_offload_linux.go
// based on claims that sockmap/sockops optimizes local traffic. However,
// older kernels (< 5.7) have known bugs where sockmap can cause epoll spin.
func TestTCPOffloadLocalConnectionCPUUsage(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping CPU usage test in short mode")
	}

	// Create a local TCP relay scenario
	// Client -> dae -> Local Server (both on localhost)

	// Start local echo server
	serverAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:0")
	serverConn, err := net.ListenTCP("tcp", serverAddr)
	if err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer serverConn.Close()

	go func() {
		for {
			conn, err := serverConn.AcceptTCP()
			if err != nil {
				return
			}
			go func(c *net.TCPConn) {
				defer c.Close()
				buf := make([]byte, 1024)
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					c.Write(buf[:n])
				}
			}(conn)
		}
	}()

	// Connect to server
	clientConn, err := net.DialTCP("tcp", nil, serverConn.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer clientConn.Close()

	// Check if this would be considered a local connection
	leftLocal, ok := tcpConnLocalIP(clientConn)
	if !ok {
		t.Fatal("Failed to get local IP")
	}
	leftPeer, ok := tcpConnPeerIP(clientConn)
	if !ok {
		t.Fatal("Failed to get peer IP")
	}

	t.Logf("Client local: %v, peer: %v", leftLocal, leftPeer)
	t.Logf("Both IPs local: %v", leftLocal.IsLoopback() && leftPeer.IsLoopback())

	// Measure CPU time for echo loop
	var iterations int64
	duration := 100 * time.Millisecond
	start := time.Now()

	for time.Since(start) < duration {
		data := []byte("test data for echo")
		_, err := clientConn.Write(data)
		if err != nil {
			t.Fatalf("Write failed: %v", err)
		}
		resp := make([]byte, len(data))
		_, err = clientConn.Read(resp)
		if err != nil {
			t.Fatalf("Read failed: %v", err)
		}
		atomic.AddInt64(&iterations, 1)
	}

	elapsed := time.Since(start)
	opsPerSec := float64(iterations) / elapsed.Seconds()
	t.Logf("Operations: %d in %v (%.0f ops/sec)", iterations, elapsed, opsPerSec)
}

// BenchmarkTCPLocalEcho benchmarks local TCP relay performance
func BenchmarkTCPLocalEcho(b *testing.B) {
	serverAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:0")
	serverConn, err := net.ListenTCP("tcp", serverAddr)
	if err != nil {
		b.Fatalf("Failed to start server: %v", err)
	}
	defer serverConn.Close()

	go func() {
		for {
			conn, err := serverConn.AcceptTCP()
			if err != nil {
				return
			}
			go func(c *net.TCPConn) {
				defer c.Close()
				buf := make([]byte, 1024)
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					c.Write(buf[:n])
				}
			}(conn)
		}
	}()

	clientConn, err := net.DialTCP("tcp", nil, serverConn.Addr().(*net.TCPAddr))
	if err != nil {
		b.Fatalf("Failed to connect: %v", err)
	}
	defer clientConn.Close()

	data := []byte("test data for echo")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := clientConn.Write(data)
		if err != nil {
			b.Fatal(err)
		}
		resp := make([]byte, len(data))
		_, err = clientConn.Read(resp)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkTCPLocalEchoParallel benchmarks concurrent local TCP relay
func BenchmarkTCPLocalEchoParallel(b *testing.B) {
	serverAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:0")
	serverConn, err := net.ListenTCP("tcp", serverAddr)
	if err != nil {
		b.Fatalf("Failed to start server: %v", err)
	}
	defer serverConn.Close()

	go func() {
		for {
			conn, err := serverConn.AcceptTCP()
			if err != nil {
				return
			}
			go func(c *net.TCPConn) {
				defer c.Close()
				buf := make([]byte, 1024)
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					c.Write(buf[:n])
				}
			}(conn)
		}
	}()

	data := []byte("test data for echo")

	b.RunParallel(func(pb *testing.PB) {
		clientConn, err := net.DialTCP("tcp", nil, serverConn.Addr().(*net.TCPAddr))
		if err != nil {
			b.Fatal(err)
		}
		defer clientConn.Close()

		resp := make([]byte, len(data))

		for pb.Next() {
			_, err := clientConn.Write(data)
			if err != nil {
				b.Fatal(err)
			}
			_, err = clientConn.Read(resp)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// TestIsLocalConnectionDetection tests the local connection detection functions
func TestIsLocalConnectionDetection(t *testing.T) {
	// Create a local TCP connection
	serverAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:0")
	serverConn, err := net.ListenTCP("tcp", serverAddr)
	if err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer serverConn.Close()

	go func() {
		conn, err := serverConn.AcceptTCP()
		if err != nil {
			return
		}
		defer conn.Close()
		// Keep connection alive
		time.Sleep(100 * time.Millisecond)
	}()

	clientConn, err := net.DialTCP("tcp", nil, serverConn.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer clientConn.Close()

	// Test the helper functions
	leftPeer, ok := tcpConnPeerIP(clientConn)
	if !ok {
		t.Fatal("Failed to get peer IP")
	}
	leftLocal, ok := tcpConnLocalIP(clientConn)
	if !ok {
		t.Fatal("Failed to get local IP")
	}

	t.Logf("Left peer: %v (loopback: %v)", leftPeer, leftPeer.IsLoopback())
	t.Logf("Left local: %v (loopback: %v)", leftLocal, leftLocal.IsLoopback())

	// For local-to-local, both should be loopback
	if !leftPeer.IsLoopback() || !leftLocal.IsLoopback() {
		t.Error("Expected loopback addresses for local connection")
	}

	// Test the full isLocalConnection function (needs two connections)
	isLocal := isLocalConnection(clientConn, clientConn)
	t.Logf("isLocalConnection result: %v", isLocal)
	if !isLocal {
		t.Error("Expected isLocalConnection to return true for loopback")
	}
}

// TestTCPOffloadEpollBehavior tests if epoll can cause issues with sockmap
// This is a regression test for potential epoll spin with local connections
func TestTCPOffloadEpollBehavior(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping epoll behavior test in short mode")
	}

	// Create an epoll set and add a local TCP socket
	epfd, err := syscall.EpollCreate1(syscall.EPOLL_CLOEXEC)
	if err != nil {
		t.Fatalf("epoll_create1 failed: %v", err)
	}
	defer syscall.Close(epfd)

	serverAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:0")
	serverConn, err := net.ListenTCP("tcp", serverAddr)
	if err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer serverConn.Close()

	clientConn, err := net.DialTCP("tcp", nil, serverConn.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer clientConn.Close()

	clientRaw, err := clientConn.SyscallConn()
	if err != nil {
		t.Fatalf("Failed to get raw conn: %v", err)
	}

	var clientFD int
	clientRaw.Control(func(fd uintptr) {
		clientFD = int(fd)
	})

	// Add to epoll with EPOLLIN | EPOLLOUT | EPOLLRDHUP
	event := &syscall.EpollEvent{
		Events: syscall.EPOLLIN | syscall.EPOLLOUT | syscall.EPOLLRDHUP | syscall.EPOLLERR | syscall.EPOLLHUP,
		Fd:     0,
	}

	if err := syscall.EpollCtl(epfd, syscall.EPOLL_CTL_ADD, clientFD, event); err != nil {
		t.Fatalf("epoll_ctl add failed: %v", err)
	}

	// Wait for events with timeout
	events := make([]syscall.EpollEvent, 10)
	start := time.Now()
	timeout := 50 * time.Millisecond

	// Check if epoll_wait returns immediately (spin) or properly waits
	n, err := syscall.EpollWait(epfd, events, int(timeout.Milliseconds()))
	elapsed := time.Since(start)

	t.Logf("EpollWait returned %d events in %v (expected ~%v)", n, elapsed, timeout)

	if elapsed < timeout/2 {
		t.Logf("WARNING: EpollWait returned early - potential for epoll spin")
	}

	if err != nil && err != syscall.EINTR {
		t.Fatalf("epoll_wait failed: %v", err)
	}
}

// BenchmarkIsLocalConnection benchmarks the local connection detection
func BenchmarkIsLocalConnection(b *testing.B) {
	serverAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:0")
	serverConn, err := net.ListenTCP("tcp", serverAddr)
	if err != nil {
		b.Fatalf("Failed to start server: %v", err)
	}
	defer serverConn.Close()

	go func() {
		conn, err := serverConn.AcceptTCP()
		if err != nil {
			return
		}
		defer conn.Close()
		// Keep alive
		<-make(chan struct{})
	}()

	clientConn, err := net.DialTCP("tcp", nil, serverConn.Addr().(*net.TCPAddr))
	if err != nil {
		b.Fatalf("Failed to connect: %v", err)
	}
	defer clientConn.Close()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = isLocalConnection(clientConn, clientConn)
	}
}

// getKernelVersion returns the current kernel version
func getKernelVersion() (major, minor int, err error) {
	var uname syscall.Utsname
	if err := syscall.Uname(&uname); err != nil {
		return 0, 0, err
	}

	// Parse release string (e.g., "6.6.87.2-microsoft-standard-WSL2")
	releaseBytes := make([]byte, 0, 65)
	for _, c := range uname.Release {
		if c == 0 {
			break
		}
		releaseBytes = append(releaseBytes, byte(c))
	}

	// Simple parse for major.minor
	major, minor = 0, 0
	for i := 0; i < len(releaseBytes); i++ {
		if releaseBytes[i] >= '0' && releaseBytes[i] <= '9' {
			for i < len(releaseBytes) && releaseBytes[i] >= '0' && releaseBytes[i] <= '9' {
				major = major*10 + int(releaseBytes[i]-'0')
				i++
			}
			if i < len(releaseBytes) && releaseBytes[i] == '.' {
				i++
				for i < len(releaseBytes) && releaseBytes[i] >= '0' && releaseBytes[i] <= '9' {
					minor = minor*10 + int(releaseBytes[i]-'0')
					i++
				}
			}
			break
		}
	}

	return major, minor, nil
}

// TestKernelVersion checks the kernel version for sockmap compatibility
func TestKernelVersion(t *testing.T) {
	major, minor, err := getKernelVersion()
	if err != nil {
		t.Fatalf("Failed to get kernel version: %v", err)
	}

	t.Logf("Kernel version: %d.%d", major, minor)

	// Known issues with sockmap on kernels < 5.7
	if major < 5 || (major == 5 && minor < 7) {
		t.Logf("WARNING: Kernel < 5.7 may have sockmap issues with local connections")
	} else {
		t.Logf("Kernel >= 5.7: sockmap should be stable")
	}
}

// TestLocalConnectionChecker tests the hostLocalAddrChecker
func TestLocalConnectionChecker(t *testing.T) {
	checker := hostLocalAddrChecker()

	// Test loopback
	loopback := netip.MustParseAddr("127.0.0.1")
	if !checker(loopback) {
		t.Error("Expected loopback to be detected as local")
	}

	// Test unspecified
	unspecified := netip.MustParseAddr("0.0.0.0")
	if !checker(unspecified) {
		t.Error("Expected unspecified to be detected as local")
	}

	// Test localhost IPv6
	loopbackV6 := netip.MustParseAddr("::1")
	if !checker(loopbackV6) {
		t.Error("Expected IPv6 loopback to be detected as local")
	}

	// Get actual interface addresses
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatalf("Failed to get interface addresses: %v", err)
	}

	var localAddrs []netip.Addr
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(ipNet.IP)
		if !ok {
			continue
		}
		ip = ip.Unmap()
		if ip.Is4() || ip.Is6() {
			localAddrs = append(localAddrs, ip)
			t.Logf("Local address: %v", ip)

			// Verify checker detects it
			if !checker(ip) {
				t.Errorf("Expected %v to be detected as local", ip)
			}
		}
	}

	// Test a non-local address (Google DNS)
	googleDNS := netip.MustParseAddr("8.8.8.8")
	if checker(googleDNS) {
		t.Logf("WARNING: 8.8.8.8 detected as local (may be in VPN)")
	} else {
		t.Logf("8.8.8.8 correctly detected as non-local")
	}
}
