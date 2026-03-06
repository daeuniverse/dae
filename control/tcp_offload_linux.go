//go:build linux
// +build linux

package control

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

var errTCPRelayOffloadUnavailable = errors.New("tcp relay eBPF offload unavailable")

type tcpRelayOffloadSession struct {
	fastSock *ebpf.Map

	leftKey  bpfTuplesKey
	rightKey bpfTuplesKey
	leftFD   int
	rightFD  int

	closeOnce sync.Once
}

func (c *ControlPlane) tryOffloadTCPRelay(ctx context.Context, left, right netproxy.Conn) (bool, error) {
	if c == nil || c.core == nil || !c.core.tcpRelayOffload {
		return false, nil
	}

	session, err := newTCPRelayOffloadSession(c.core.bpf.FastSock, left, right)
	if err != nil {
		if errors.Is(err, errTCPRelayOffloadUnavailable) {
			if c.log != nil && c.log.IsLevelEnabled(logrus.DebugLevel) {
				c.log.Debugf("Skip TCP relay eBPF offload: %v", err)
			}
			return false, nil
		}
		return false, err
	}
	defer session.Close()

	if c.log != nil && c.log.IsLevelEnabled(logrus.DebugLevel) {
		c.log.Debug("Use TCP relay eBPF offload")
	}
	return true, session.Run(ctx)
}

func newTCPRelayOffloadSession(fastSock *ebpf.Map, left, right netproxy.Conn) (*tcpRelayOffloadSession, error) {
	if fastSock == nil {
		return nil, fmt.Errorf("%w: fast_sock map is unavailable", errTCPRelayOffloadUnavailable)
	}

	leftTCP, ok := unwrapPlainTCPConn(left)
	if !ok {
		return nil, fmt.Errorf("%w: left is not a plain *net.TCPConn, has buffered data (type: %T)", errTCPRelayOffloadUnavailable, left)
	}
	rightTCP, ok := unwrapRelayTCPConn(right)
	if !ok {
		return nil, fmt.Errorf("%w: right connection cannot be unwrapped to plain tcp (type: %T)", errTCPRelayOffloadUnavailable, right)
	}
	if !tcpConnSupportsEBPFRedirect(leftTCP) {
		return nil, fmt.Errorf("%w: left connection is not ipv4/ipv6 tcp", errTCPRelayOffloadUnavailable)
	}
	if !tcpConnSupportsEBPFRedirect(rightTCP) {
		return nil, fmt.Errorf("%w: right connection is not ipv4/ipv6 tcp", errTCPRelayOffloadUnavailable)
	}

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
