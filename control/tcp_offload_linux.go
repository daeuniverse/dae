//go:build linux
// +build linux

// Package control provides TCP relay eBPF offload functionality.
//
// *** DISABLED DUE TO KERNEL BUG ***
// ===================================
// TCP relay eBPF offload is PERMANENTLY DISABLED due to kernel panic issues
// with the bpf_msg_redirect_hash() helper.
//
// Issue: https://github.com/daeuniverse/dae/pull/912
// Cause: bpf_msg_redirect_hash() causes kernel panics in certain scenarios
// Impact: System instability and crashes
//
// The code below is preserved for potential future re-enabling after:
// 1. Upstream kernel bug is fixed
// 2. Fix is backported to stable kernels
// 3. Thorough testing confirms stability
//
// Current behavior: All TCP traffic uses userspace relay (stable but slower)
package control

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/outbound/netproxy"
	"golang.org/x/sys/unix"
)

var errTCPRelayOffloadUnavailable = errors.New("tcp relay eBPF offload unavailable")

// tcpRelayOffloadSession manages an eBPF-based TCP relay offload session.
//
// *** DISABLED *** This type is not currently used due to kernel panic issues.
// The implementation is preserved for potential future re-enabling.
type tcpRelayOffloadSession struct {
	fastSock *ebpf.Map

	leftKey  bpfTuplesKey
	rightKey bpfTuplesKey
	leftFD   int
	rightFD  int

	closeOnce sync.Once
}

var hostLocalAddrCache struct {
	mu      sync.RWMutex
	expires time.Time
	checker func(netip.Addr) bool
}

const hostLocalAddrCacheTTL = time.Minute

// isLocalConnection checks whether this is a local-to-local forwarding scenario.
// This is used to skip eBPF offload for host-local relays, which can otherwise
// spin in the epoll loop when dae bridges two local TCP peers.
//
// We detect local forwarding in two cases:
// 1. Both peers are local (e.g., local client -> dae -> local service)
// 2. Right socket connects to a local service (e.g., remote client -> dae -> local service on 127.0.0.1 or LAN IP)
//
// This is distinct from direct forwarding (remote client -> dae -> remote server),
// where eBPF offload should be used for optimal performance.
func isLocalConnection(left, right *net.TCPConn) bool {
	leftPeer, ok := tcpConnPeerIP(left)
	if !ok {
		return false
	}
	rightPeer, ok := tcpConnPeerIP(right)
	if !ok {
		return false
	}

	leftLocal, ok := tcpConnLocalIP(left)
	if !ok {
		return false
	}
	rightLocal, ok := tcpConnLocalIP(right)
	if !ok {
		return false
	}

	isHostLocal := hostLocalAddrChecker()

	// Case 1: Both peers are local (e.g., local client -> dae -> local service on 127.0.0.1)
	bothPeersLocal := isHostLocal(leftPeer) && isHostLocal(rightPeer)
	if bothPeersLocal {
		return true
	}

	// Case 2: Right socket connects to a local service on this host
	// (e.g., remote client -> dae -> local service on 127.0.0.1 or LAN IP)
	// Key distinction: right.RemoteAddr is local, meaning dae is forwarding to a local service
	rightPeerIsLocal := isHostLocal(rightPeer)

	// Also verify both sockets are on the same host (defensive check)
	bothLocalOnHost := isHostLocal(leftLocal) && isHostLocal(rightLocal)

	// Local forwarding: right connects to local service
	// Direct forwarding: right connects to remote service (rightPeer is not local)
	return rightPeerIsLocal && bothLocalOnHost
}

// tcpConnLocalIP extracts the local IP address from a TCP connection.
func tcpConnLocalIP(conn *net.TCPConn) (netip.Addr, bool) {
	local, ok := conn.LocalAddr().(*net.TCPAddr)
	if !ok {
		return netip.Addr{}, false
	}
	ip, ok := netip.AddrFromSlice(local.IP)
	if !ok {
		return netip.Addr{}, false
	}
	return common.ConvergeAddr(ip), true
}

func tcpConnPeerIP(conn *net.TCPConn) (netip.Addr, bool) {
	peer, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return netip.Addr{}, false
	}
	ip, ok := netip.AddrFromSlice(peer.IP)
	if !ok {
		return netip.Addr{}, false
	}
	return common.ConvergeAddr(ip), true
}

func hostLocalAddrChecker() func(netip.Addr) bool {
	now := time.Now()
	hostLocalAddrCache.mu.RLock()
	if hostLocalAddrCache.checker != nil && now.Before(hostLocalAddrCache.expires) {
		checker := hostLocalAddrCache.checker
		hostLocalAddrCache.mu.RUnlock()
		return checker
	}
	hostLocalAddrCache.mu.RUnlock()

	checker := loadHostLocalAddrChecker()

	hostLocalAddrCache.mu.Lock()
	defer hostLocalAddrCache.mu.Unlock()
	if hostLocalAddrCache.checker == nil || now.After(hostLocalAddrCache.expires) {
		hostLocalAddrCache.checker = checker
		hostLocalAddrCache.expires = now.Add(hostLocalAddrCacheTTL)
	}
	return hostLocalAddrCache.checker
}

func loadHostLocalAddrChecker() func(netip.Addr) bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return makeHostLocalAddrChecker(nil)
	}

	localAddrs := make([]netip.Addr, 0, len(addrs))
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(ipNet.IP)
		if !ok {
			continue
		}
		localAddrs = append(localAddrs, common.ConvergeAddr(ip))
	}
	return makeHostLocalAddrChecker(localAddrs)
}

func makeHostLocalAddrChecker(localAddrs []netip.Addr) func(netip.Addr) bool {
	localSet := make(map[netip.Addr]struct{}, len(localAddrs))
	for _, addr := range localAddrs {
		addr = common.ConvergeAddr(addr)
		if !addr.IsValid() {
			continue
		}
		localSet[addr] = struct{}{}
	}

	return func(addr netip.Addr) bool {
		addr = common.ConvergeAddr(addr)
		if !addr.IsValid() {
			return false
		}
		if addr.IsLoopback() || addr.IsUnspecified() {
			return true
		}
		_, ok := localSet[addr]
		return ok
	}
}

// tryOffloadTCPRelay attempts to use eBPF sockmap for TCP relay offload.
//
// DISABLED: TCP relay eBPF offload is permanently disabled due to kernel panic issues.
// The bpf_msg_redirect_hash() helper causes kernel panics in certain scenarios.
// See: https://github.com/daeuniverse/dae/pull/912
//
// The function below is preserved for potential future re-enabling when the kernel bug is fixed.
// Currently, it always returns (false, "disabled", nil) to fall back to userspace relay.
func (c *ControlPlane) tryOffloadTCPRelay(ctx context.Context, left, right netproxy.Conn) (bool, string, error) {
	// Permanently disabled due to kernel panic issues with bpf_msg_redirect_hash()
	// Re-enable only after upstream kernel bug is fixed and thoroughly tested
	return false, "eBPF offload disabled due to kernel bug", nil
}

// newTCPRelayOffloadSession creates a new TCP relay offload session.
//
// *** DISABLED *** This function is not currently called due to kernel panic issues.
// The implementation is preserved for potential future re-enabling after the kernel bug is fixed.
func newTCPRelayOffloadSession(fastSock *ebpf.Map, left, right netproxy.Conn) (*tcpRelayOffloadSession, error) {
	// unwrapRelayTCPConn traverses transparent wrapper chains (ConnSniffer,
	// prefixedConn, FakeNetConn, etc.) to reach the underlying socket.
	// Callers must flush any userspace prefix via tcpOffloadFlushLeftPrefix
	// before this call; only the kernel receive queue matters for TIOCINQ.
	leftTCP, ok := unwrapRelayTCPConn(left)
	if !ok {
		return nil, fmt.Errorf("%w: left connection cannot be unwrapped to *net.TCPConn (chain: %s)", errTCPRelayOffloadUnavailable, relayConnChain(left))
	}
	rightTCP, ok := unwrapRelayTCPConn(right)
	if !ok {
		return nil, fmt.Errorf("%w: right connection cannot be unwrapped to plain tcp (chain: %s)", errTCPRelayOffloadUnavailable, relayConnChain(right))
	}
	if !tcpConnSupportsEBPFRedirect(leftTCP) {
		return nil, fmt.Errorf("%w: left connection is not ipv4/ipv6 tcp", errTCPRelayOffloadUnavailable)
	}
	if !tcpConnSupportsEBPFRedirect(rightTCP) {
		return nil, fmt.Errorf("%w: right connection is not ipv4/ipv6 tcp", errTCPRelayOffloadUnavailable)
	}

	// Local connection check removed: eBPF sockmap/sockops is specifically designed
	// to optimize local-to-local traffic by bypassing the kernel TCP/IP stack.
	// Industry practice (Kmesh, Cilium, ebpf-sockops) confirms this improves
	// performance for localhost connections (e.g., client -> dae -> local SOCKS5 proxy).
	// The previous "high CPU due to epoll loop" concern was likely specific to
	// early kernel implementations and has been addressed in modern kernels.

	leftPending, err := tcpConnHasPendingReadData(leftTCP)
	if err != nil {
		return nil, fmt.Errorf("%w: inspect left receive queue: %v", errTCPRelayOffloadUnavailable, err)
	}
	if leftPending {
		return nil, fmt.Errorf("%w: left receive queue already has data", errTCPRelayOffloadUnavailable)
	}

	rightPending, err := tcpConnHasPendingReadData(rightTCP)
	if err != nil {
		return nil, fmt.Errorf("%w: inspect right receive queue: %v", errTCPRelayOffloadUnavailable, err)
	}
	if rightPending {
		return nil, fmt.Errorf("%w: right receive queue already has data", errTCPRelayOffloadUnavailable)
	}

	leftKey, err := tcpConnTuplesKey(leftTCP)
	if err != nil {
		return nil, fmt.Errorf("%w: left tuple: %v", errTCPRelayOffloadUnavailable, err)
	}
	rightKey, err := tcpConnTuplesKey(rightTCP)
	if err != nil {
		return nil, fmt.Errorf("%w: right tuple: %v", errTCPRelayOffloadUnavailable, err)
	}

	leftFD, err := tcpConnFD(leftTCP)
	if err != nil {
		return nil, fmt.Errorf("%w: left fd: %v", errTCPRelayOffloadUnavailable, err)
	}
	rightFD, err := tcpConnFD(rightTCP)
	if err != nil {
		return nil, fmt.Errorf("%w: right fd: %v", errTCPRelayOffloadUnavailable, err)
	}
	if fastSock == nil {
		return nil, fmt.Errorf("%w: fast_sock map is unavailable", errTCPRelayOffloadUnavailable)
	}

	session := &tcpRelayOffloadSession{
		fastSock: fastSock,
		leftKey:  leftKey,
		rightKey: rightKey,
		leftFD:   leftFD,
		rightFD:  rightFD,
	}
	if err := session.register(); err != nil {
		return nil, err
	}
	return session, nil
}

// tcpOffloadFlushLeftPrefix writes any userspace-buffered prefix from left
// to right via writev (single syscall when possible). After this call the
// wrapper's in-memory buffer is empty, so tcpConnHasPendingReadData on the
// inner *net.TCPConn accurately reflects only kernel-buffered data.
// If left carries no prefix this is a no-op.
func tcpOffloadFlushLeftPrefix(left, right netproxy.Conn) error {
	var segs [][]byte
	if ss, ok := left.(relaySegmentSource); ok {
		segs = relayNonEmptySegments(ss.TakeRelaySegments())
	} else if ps, ok := left.(relayPrefixSource); ok {
		if p := ps.TakeRelayPrefix(); len(p) > 0 {
			segs = [][]byte{p}
		}
	}
	if len(segs) == 0 {
		return nil
	}
	_, err := relayGatherWriteTo(right, segs)
	return err
}

func unwrapPlainTCPConn(conn netproxy.Conn) (*net.TCPConn, bool) {
	tcpConn, ok := conn.(*net.TCPConn)
	return tcpConn, ok
}

func tcpConnSupportsEBPFRedirect(conn *net.TCPConn) bool {
	localAddr, ok := conn.LocalAddr().(*net.TCPAddr)
	if !ok {
		return false
	}
	remoteAddr, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return false
	}
	localIP := common.ConvergeAddrPort(localAddr.AddrPort()).Addr()
	remoteIP := common.ConvergeAddrPort(remoteAddr.AddrPort()).Addr()
	return (localIP.Is4() || localIP.Is6()) && (remoteIP.Is4() || remoteIP.Is6())
}

func tcpConnTuplesKey(conn *net.TCPConn) (bpfTuplesKey, error) {
	localAddr, ok := conn.LocalAddr().(*net.TCPAddr)
	if !ok {
		return bpfTuplesKey{}, fmt.Errorf("unexpected local addr type %T", conn.LocalAddr())
	}
	remoteAddr, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return bpfTuplesKey{}, fmt.Errorf("unexpected remote addr type %T", conn.RemoteAddr())
	}
	return makeTuplesKey(
		common.ConvergeAddrPort(remoteAddr.AddrPort()),
		common.ConvergeAddrPort(localAddr.AddrPort()),
		consts.IPPROTO_TCP,
	), nil
}

func tcpConnFD(conn *net.TCPConn) (int, error) {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}

	var fd int
	if err := rawConn.Control(func(fileDesc uintptr) {
		fd = int(fileDesc)
	}); err != nil {
		return 0, err
	}
	return fd, nil
}

func tcpConnHasPendingReadData(conn *net.TCPConn) (bool, error) {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return false, err
	}

	var (
		pending int
		ctrlErr error
	)
	if err := rawConn.Control(func(fd uintptr) {
		pending, ctrlErr = unix.IoctlGetInt(int(fd), unix.TIOCINQ)
	}); err != nil {
		return false, err
	}
	if ctrlErr != nil {
		return false, ctrlErr
	}
	return pending > 0, nil
}

func (s *tcpRelayOffloadSession) register() error {
	if err := s.fastSock.Update(&s.leftKey, uint64(s.rightFD), ebpf.UpdateAny); err != nil {
		return fmt.Errorf("%w: register left socket: %v", errTCPRelayOffloadUnavailable, err)
	}
	if err := s.fastSock.Update(&s.rightKey, uint64(s.leftFD), ebpf.UpdateAny); err != nil {
		_ = s.fastSock.Delete(&s.leftKey)
		return fmt.Errorf("%w: register right socket: %v", errTCPRelayOffloadUnavailable, err)
	}
	return nil
}

func (s *tcpRelayOffloadSession) Close() error {
	var errs []error
	s.closeOnce.Do(func() {
		if err := s.fastSock.Delete(&s.leftKey); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			errs = append(errs, fmt.Errorf("delete left fast_sock key: %w", err))
		}
		if err := s.fastSock.Delete(&s.rightKey); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			errs = append(errs, fmt.Errorf("delete right fast_sock key: %w", err))
		}
	})
	return errors.Join(errs...)
}

func (s *tcpRelayOffloadSession) Run(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}

	epfd, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		return fmt.Errorf("epoll_create1: %w", err)
	}
	defer unix.Close(epfd)

	for _, reg := range []struct {
		fd    int
		index int32
	}{
		{fd: s.leftFD, index: 0},
		{fd: s.rightFD, index: 1},
	} {
		event := &unix.EpollEvent{
			Events: unix.EPOLLRDHUP | unix.EPOLLHUP | unix.EPOLLERR,
			Fd:     reg.index,
		}
		if err := unix.EpollCtl(epfd, unix.EPOLL_CTL_ADD, reg.fd, event); err != nil {
			return fmt.Errorf("epoll_ctl add fd %d: %w", reg.fd, err)
		}
	}

	var (
		events     [2]unix.EpollEvent
		closedMask uint8
		firstClose time.Time
	)

	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		waitMs := int((time.Second).Milliseconds())
		if !firstClose.IsZero() {
			remaining := relayHalfCloseTimeout - time.Since(firstClose)
			if remaining <= 0 {
				return nil
			}
			waitMs = int(remaining.Milliseconds())
			if waitMs < 1 {
				waitMs = 1
			}
		}

		n, err := unix.EpollWait(epfd, events[:], waitMs)
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			return fmt.Errorf("epoll_wait: %w", err)
		}
		if n == 0 {
			if !firstClose.IsZero() {
				return nil
			}
			continue
		}

		for i := 0; i < n; i++ {
			if events[i].Events&(unix.EPOLLRDHUP|unix.EPOLLHUP|unix.EPOLLERR) == 0 {
				continue
			}
			switch events[i].Fd {
			case 0:
				closedMask |= 1
			case 1:
				closedMask |= 2
			}
		}
		if closedMask == 0 {
			continue
		}
		if closedMask == 0x3 {
			return nil
		}
		if firstClose.IsZero() {
			firstClose = time.Now()
		}
	}
}
