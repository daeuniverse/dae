//go:build linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"structs"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

const (
	// tcpOffloadIdlePollInterval is the cadence at which the offload session
	// samples tcp_info receive counters to detect progress (idle watchdog) and
	// to compute final traffic accounting.
	tcpOffloadIdlePollInterval = 30 * time.Second
	// tcpOffloadEpollWaitCap caps each epoll wait so the idle watchdog and the
	// half-close timer stay responsive.
	tcpOffloadEpollWaitCap = 1 * time.Second
	// tcpOffloadMaxPeerBacklog bounds the egress retry-queue backlog
	// (redirected bytes not yet pushed into the peers' send paths, the
	// kernel-buffered tail that is not charged to socket buffers or memcg,
	// bpf-next 2025-04 series issue #4). Exceeding it engages the backlog
	// fuse: the verdict passes data through and the userspace fallback
	// forwards it while the kernel drains the queue.
	tcpOffloadMaxPeerBacklog = 64 << 20
	// relayPassWriteTimeout bounds a userspace-fallback write to a congested
	// peer socket so one stalled direction cannot wedge the session loop.
	relayPassWriteTimeout = 5 * time.Second
	// tcpOffloadFuseDrainWait pauses the userspace fallback after the first
	// SK_PASS data (the pause signal) so the kernel drains the retry queue
	// of already-redirected skbs first. Writing immediately would let new
	// data starve that queue forever (tail debt). While paused, data stays
	// in the bounded kernel receive queue and TCP flow control freezes the
	// sender. The wait must exceed the backlog drain time (backlog size
	// divided by the peer consumption rate).
	tcpOffloadFuseDrainWait = 10 * time.Second // tcpOffloadFuseResumeBytes is the backlog level below which the fuse
	// lifts: the pause key is removed and the verdict redirects again.
	tcpOffloadFuseResumeBytes = 1 << 20
)

var errTCPRelayOffloadUnavailable = errors.New("tcp relay eBPF offload unavailable")

// epollCtlAddIgnoreExist adds fd to epfd. EEXIST means the fd is already a
// member (fuse recovery re-ADD); that is not a fatal error.
func epollCtlAddIgnoreExist(epfd int, fd int, event *unix.EpollEvent) error {
	if err := unix.EpollCtl(epfd, unix.EPOLL_CTL_ADD, fd, event); err != nil && err != unix.EEXIST {
		return err
	}
	return nil
}

// tcpRelayOffloadSession wires one relay pair into the fast_sock SOCKHASH.
//
// Keying convention (shared with tcp_offload_redirect in tproxy.c): a socket
// is registered under its reversed four-tuple
// (sip=remote, dip=local, sport=remote_port, dport=local_port) and the value
// stored is the peer socket's fd. When the sk_skb stream-verdict program runs
// on received data it computes the same key and redirects to the peer's
// egress path, so the peer socket transmits the data.
type tcpRelayOffloadSession struct {
	fastSock *ebpf.Map
	pauseMap *ebpf.Map
	sentMap  *ebpf.Map
	log      *logrus.Logger

	left    *net.TCPConn
	right   *net.TCPConn
	leftFD  int
	rightFD int

	leftKey  bpfTuplesKey
	rightKey bpfTuplesKey

	// Baseline tcp_info receive counters at registration, for final accounting.
	leftRxBase  uint64
	rightRxBase uint64

	// finalLeftRx/finalRightRx capture the accounting deltas before the
	// sockets are force-closed: tcp_info is unreadable after close, and most
	// exit paths (half-close timeout, idle, backlog guard, ctx cancellation)
	// close the sockets themselves.
	finalLeftRx  int64
	finalRightRx int64
	accounted    atomic.Bool

	// fused marks the backlog fuse as engaged: the verdict program passes
	// data through (pause map) and the userspace fallback forwards it.
	fused bool
	// fusePassBytes accumulates userspace-fallback bytes so the backlog
	// metric stays continuous without racing the kernel-side accounting.
	fusePassBytes uint64
	// fuseDrainUntil (zero while inactive) marks the drain window after the
	// fuse engages: the fallback pauses so the kernel drains the retry queue
	// of already-redirected skbs before userspace writes compete with it.
	fuseDrainUntil time.Time

	forceCloseOnce sync.Once
	closeOnce      sync.Once

	// pendingErrs collects fuse-map failures detected after the session
	// started (lift deletes) so Close joins them into its own error instead of
	// them being visible only as a log line. Guarded by pendingErrsMu; Run is
	// the only writer today, but Close reads it from the caller's goroutine.
	pendingErrsMu sync.Mutex
	pendingErrs   []error

	// epollArmed is true while both fds are in the session epoll set.
	// Run is the only writer, so a plain bool is enough. Fuse recovery
	// must not EPOLL_CTL_ADD an already-armed fd (EEXIST is not fatal).
	epollArmed bool
}

func (c *ControlPlane) tryOffloadTCPRelay(ctx context.Context, left, right netproxy.Conn, leftRecord, rightRecord func(int64)) (offloaded bool, reason string, err error) {
	if c == nil || c.core == nil {
		return false, "", nil
	}
	if !c.core.tcpSockmapOffloadReady.Load() {
		return false, "offload disabled", nil
	}
	bpf := c.core.bpf.Load()
	if bpf == nil || bpf.FastSock == nil || bpf.TcpOffloadPause == nil || bpf.TcpOffloadSent == nil {
		return false, "fast_sock/pause/sent unavailable", nil
	}

	// Flush any userspace-buffered prefix (sniff leftovers) before registering,
	// so the kernel receive queues are the only source of pending data.
	// Direction note: bytes taken from left (client side) are written to right
	// (egress), i.e. upload traffic; relayCore's l2r direction counts them via
	// rightRecord. Drained kernel-queue bytes are not covered by the tcp_info
	// baselines (which are sampled after the drain), so record them explicitly.
	prefixN, err := tcpOffloadFlushLeftPrefix(left, right)
	if err != nil {
		return false, "prefix flush failed", err
	}
	if prefixN > 0 {
		rightRecord(int64(prefixN))
	}

	session, err := newTCPRelayOffloadSession(c.log, bpf.FastSock, bpf.TcpOffloadPause, bpf.TcpOffloadSent, left, right, leftRecord, rightRecord)
	if err != nil {
		if errors.Is(err, errTCPRelayOffloadUnavailable) {
			return false, tcpRelayOffloadReason(err), nil
		}
		return false, "", err
	}
	defer func() { _ = session.Close() }()

	if c.log != nil && c.log.IsLevelEnabled(logrus.DebugLevel) {
		c.log.Debugf("TCP relay eBPF offload: %v <-> %v", session.left.RemoteAddr(), session.right.RemoteAddr())
	}

	leftRx, rightRx, err := session.Run(ctx)
	if leftRx > 0 {
		rightRecord(leftRx) // left (client) received => upload
	}
	if rightRx > 0 {
		leftRecord(rightRx) // right (egress) received => download
	}
	return true, "", err
}

func newTCPRelayOffloadSession(log *logrus.Logger, fastSock, pauseMap, sentMap *ebpf.Map, left, right netproxy.Conn, leftRecord, rightRecord func(int64)) (*tcpRelayOffloadSession, error) {
	// Callers must flush the userspace prefix via tcpOffloadFlushLeftPrefix
	// before this call; only the kernel receive queue matters for TIOCINQ.
	leftTCP, ok := unwrapRelayTCPConn(left)
	if !ok {
		return nil, fmt.Errorf("%w: left connection cannot be unwrapped to *net.TCPConn", errTCPRelayOffloadUnavailable)
	}
	rightTCP, ok := unwrapRelayTCPConn(right)
	if !ok {
		return nil, fmt.Errorf("%w: right connection cannot be unwrapped to *net.TCPConn", errTCPRelayOffloadUnavailable)
	}
	if !tcpConnSupportsEBPFRedirect(leftTCP) {
		return nil, fmt.Errorf("%w: left connection is not ipv4/ipv6 tcp", errTCPRelayOffloadUnavailable)
	}
	if !tcpConnSupportsEBPFRedirect(rightTCP) {
		return nil, fmt.Errorf("%w: right connection is not ipv4/ipv6 tcp", errTCPRelayOffloadUnavailable)
	}

	// Drain any early data already sitting in the kernel receive queues into
	// the peer before registration: the user-space prefix flush only covers
	// userspace-buffered bytes, while clients (and server-first protocols)
	// routinely have payload queued in-kernel by the time the dial completes.
	// Drained bytes are recorded explicitly because the tcp_info baselines
	// below are sampled after the drain.
	drainedN, err := tcpConnDrainKernelQueue(leftTCP, rightTCP)
	if err != nil {
		return nil, fmt.Errorf("%w: drain left kernel queue: %v", errTCPRelayOffloadUnavailable, err)
	}
	if drainedN > 0 {
		rightRecord(int64(drainedN)) // left -> right is upload traffic
	}
	drainedN, err = tcpConnDrainKernelQueue(rightTCP, leftTCP)
	if err != nil {
		return nil, fmt.Errorf("%w: drain right kernel queue: %v", errTCPRelayOffloadUnavailable, err)
	}
	if drainedN > 0 {
		leftRecord(int64(drainedN)) // right -> left is download traffic
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

	leftRxBase, err := tcpConnRxBytes(leftTCP)
	if err != nil {
		return nil, fmt.Errorf("%w: left tcp_info: %v", errTCPRelayOffloadUnavailable, err)
	}
	rightRxBase, err := tcpConnRxBytes(rightTCP)
	if err != nil {
		return nil, fmt.Errorf("%w: right tcp_info: %v", errTCPRelayOffloadUnavailable, err)
	}

	session := &tcpRelayOffloadSession{
		fastSock:    fastSock,
		pauseMap:    pauseMap,
		sentMap:     sentMap,
		log:         log,
		left:        leftTCP,
		right:       rightTCP,
		leftFD:      leftFD,
		rightFD:     rightFD,
		leftKey:     leftKey,
		rightKey:    rightKey,
		leftRxBase:  leftRxBase,
		rightRxBase: rightRxBase,
	}
	if err := session.register(); err != nil {
		return nil, err
	}
	return session, nil
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

// Close unregisters the pair from fast_sock and clears the fuse maps.
// Sockets are closed by the caller.
func (s *tcpRelayOffloadSession) Close() error {
	var errs []error
	s.closeOnce.Do(func() {
		if err := s.fastSock.Delete(&s.leftKey); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			errs = append(errs, fmt.Errorf("delete left fast_sock key: %w", err))
		}
		if err := s.fastSock.Delete(&s.rightKey); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			errs = append(errs, fmt.Errorf("delete right fast_sock key: %w", err))
		}
		// Clear fuse state so a future connection reusing the same tuples
		// starts with a clean backlog baseline and no residual pause. A
		// missing key is the normal case (the fuse never engaged), anything
		// else is counted and warned about instead of being dropped: a
		// residual pause entry would keep the next connection's datapath
		// paused with no way to detect it.
		for _, cleanup := range []struct {
			name string
			m    *ebpf.Map
			key  *bpfTuplesKey
		}{
			{"pause-left", s.pauseMap, &s.leftKey},
			{"pause-right", s.pauseMap, &s.rightKey},
			{"sent-left", s.sentMap, &s.leftKey},
			{"sent-right", s.sentMap, &s.rightKey},
		} {
			if err := cleanup.m.Delete(cleanup.key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				s.reportOffloadMapFailure(cleanup.name, err)
				errs = append(errs, fmt.Errorf("delete %s map key: %w", cleanup.name, err))
			}
		}
		s.pendingErrsMu.Lock()
		errs = append(errs, s.pendingErrs...)
		s.pendingErrsMu.Unlock()
	})
	return errors.Join(errs...)
}

// tcpOffloadMapFailureCount counts fuse-map maintenance failures (pause/sent
// updates, deletes and rollbacks) across all offload sessions. The failures do
// not stop the relay - it keeps running in userspace - but they must not be
// silent, because a paused-but-not-lifted or not-paused-while-expected map
// changes which path carries the data.
var tcpOffloadMapFailureCount atomic.Uint64

// reportOffloadMapFailure counts one fuse-map failure and warns on the first
// and every 2^n-th occurrence so a persistently failing map stays visible
// without flooding the log (the fuse guard runs once per epoll wait cap).
func (s *tcpRelayOffloadSession) reportOffloadMapFailure(op string, err error) {
	if err == nil {
		return
	}
	count := tcpOffloadMapFailureCount.Add(1)
	if s.log == nil || !s.log.IsLevelEnabled(logrus.WarnLevel) || count&(count-1) != 0 {
		return
	}
	fields := logrus.Fields{
		"op":       op,
		"error":    err.Error(),
		"failures": count,
	}
	if s.left != nil {
		fields["left"] = s.left.RemoteAddr().String()
	}
	if s.right != nil {
		fields["right"] = s.right.RemoteAddr().String()
	}
	s.log.WithFields(fields).Warn("TCP relay eBPF offload fuse map maintenance failed")
}

// fuseStep evaluates the backlog fuse once: it computes the egress retry
// queue backlog (tcp_info receive deltas since registration minus bytes
// already pushed into the peers' send paths, tracked by the skb_send_sock
// kprobe and by the userspace fallback), engages the pause when the backlog
// exceeds tcpOffloadMaxPeerBacklog, and lifts it once the backlog drains.
// Returns (engage, lift, err): engage demands the fds be dropped from epoll
// while the kernel drains already-redirected skbs; lift demands they be
// re-added.
func (s *tcpRelayOffloadSession) fuseStep(lastProgress *time.Time) (engage, lift bool) {
	lrx, err := tcpConnRxBytes(s.left)
	if err != nil {
		return false, false // transient; skip this round
	}
	rrx, err := tcpConnRxBytes(s.right)
	if err != nil {
		return false, false
	}
	var lSent, rSent uint64
	var lv, rv []uint64
	_ = s.sentMap.Lookup(&s.leftKey, &lv)
	_ = s.sentMap.Lookup(&s.rightKey, &rv)
	for _, v := range lv {
		lSent += v
	}
	for _, v := range rv {
		rSent += v
	}
	inflow := int64((lrx - s.leftRxBase) + (rrx - s.rightRxBase))
	backlog := inflow - int64(lSent+rSent+s.fusePassBytes)
	if s.fused {
		if backlog <= tcpOffloadFuseResumeBytes {
			// Drain residual SK_PASS data before lifting: once the verdict
			// redirects again, late userspace writes would compete with the
			// kernel redirect on the peer send path and reorder bytes.
			if s.drainResidual(lastProgress) {
				return false, false
			}
			s.fused = false
			// A failed lift leaves the kernel verdict paused while userspace
			// stops forwarding: the relay would wedge until the idle timeout.
			// Surface it (counted + warned, and joined into Close's errs)
			// instead of ignoring the returned error.
			var liftErrs []error
			for _, key := range []*bpfTuplesKey{&s.leftKey, &s.rightKey} {
				if err := s.pauseMap.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
					s.reportOffloadMapFailure("pause-lift", err)
					liftErrs = append(liftErrs, err)
				}
			}
			if len(liftErrs) > 0 {
				s.pendingErrsMu.Lock()
				s.pendingErrs = append(s.pendingErrs, errors.Join(liftErrs...))
				s.pendingErrsMu.Unlock()
			}
			if s.log != nil && s.log.IsLevelEnabled(logrus.DebugLevel) {
				s.log.Debugf("TCP relay eBPF offload fuse lifted: %v <-> %v", s.left.RemoteAddr(), s.right.RemoteAddr())
			}
			return false, true
		}
		return false, false
	}
	if backlog > int64(tcpOffloadMaxPeerBacklog) {
		// Engage all-or-nothing: the pause must cover BOTH directions before
		// the caller drops the fds from epoll (delFds). With the fds removed
		// from epoll but only one side paused, the still-redirecting side is
		// served by the kernel while the paused side's data sits in a receive
		// queue nobody drains. On a partial failure, roll back the side that
		// was written and keep the relay on the userspace path (availability
		// first, failure visible).
		one := uint8(1)
		updateErr := s.pauseMap.Update(&s.leftKey, &one, ebpf.UpdateAny)
		if updateErr == nil {
			updateErr = s.pauseMap.Update(&s.rightKey, &one, ebpf.UpdateAny)
		}
		if updateErr != nil {
			for _, key := range []*bpfTuplesKey{&s.leftKey, &s.rightKey} {
				if err := s.pauseMap.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
					s.reportOffloadMapFailure("pause-rollback", err)
				}
			}
			s.reportOffloadMapFailure("pause-engage", updateErr)
			return false, false
		}
		s.fused = true
		s.fuseDrainUntil = time.Now().Add(tcpOffloadFuseDrainWait)
		if s.log != nil && s.log.IsLevelEnabled(logrus.DebugLevel) {
			s.log.Debugf("TCP relay eBPF offload fuse engaged (backlog=%d): %v <-> %v", backlog, s.left.RemoteAddr(), s.right.RemoteAddr())
		}
		return true, false
	}
	return false, false
}

// drainResidual forwards SK_PASS data still queued in the receive queues
// until both are empty (or a bounded number of iterations elapses). Returns
// true when data is still pending so fuseStep can defer the lift.
func (s *tcpRelayOffloadSession) drainResidual(lastProgress *time.Time) bool {
	for range 64 {
		lPending, err := tcpConnHasPendingReadData(s.left)
		if err == nil && lPending {
			_, _ = s.relayPassData(0, lastProgress)
			continue
		}
		rPending, err := tcpConnHasPendingReadData(s.right)
		if err == nil && rPending {
			_, _ = s.relayPassData(1, lastProgress)
			continue
		}
		return false
	}
	return true
}

// Run blocks until both relay sockets are closed (or close their pair on
// half-close timeout / idle timeout / context cancellation) and returns the
// bytes received on each side since registration for traffic accounting.
// The counters mirror what the user-space relay would have recorded: the
// left/right record callbacks count bytes written to the peer, which equals
// the bytes received on the corresponding socket.
func (s *tcpRelayOffloadSession) Run(ctx context.Context) (leftRx, rightRx int64, err error) {
	defer func() {
		// Prefer the snapshot taken before a force-close; fall back to a live
		// read when the sockets are still open (graceful double-close exit).
		if l, r, ok := s.accountedDeltas(); ok {
			leftRx, rightRx = l, r
			return
		}
		l, r, aerr := s.rxDeltas()
		if aerr == nil {
			leftRx, rightRx = l, r
		}
	}()

	if ctx == nil {
		ctx = context.Background()
	}

	epfd, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		return 0, 0, fmt.Errorf("epoll_create1: %w", err)
	}
	defer func() { _ = unix.Close(epfd) }()

	fds := []struct {
		fd    int
		index int32
	}{
		{fd: s.leftFD, index: 0},
		{fd: s.rightFD, index: 1},
	}
	addFds := func() error {
		if s.epollArmed {
			return nil
		}
		for _, reg := range fds {
			event := &unix.EpollEvent{
				Events: unix.EPOLLRDHUP | unix.EPOLLHUP | unix.EPOLLERR | unix.EPOLLIN,
				Fd:     reg.index,
			}
			if err := epollCtlAddIgnoreExist(epfd, reg.fd, event); err != nil {
				return fmt.Errorf("epoll_ctl add fd %d: %w", reg.fd, err)
			}
		}
		s.epollArmed = true
		return nil
	}
	delFds := func() {
		if !s.epollArmed {
			return
		}
		_ = unix.EpollCtl(epfd, unix.EPOLL_CTL_DEL, s.leftFD, nil)
		_ = unix.EpollCtl(epfd, unix.EPOLL_CTL_DEL, s.rightFD, nil)
		s.epollArmed = false
	}
	if err := addFds(); err != nil {
		s.forceClose()
		return 0, 0, err
	}

	var (
		events       [2]unix.EpollEvent
		closedMask   uint8
		firstClose   time.Time
		lastProgress = time.Now()
		lastPoll     = time.Now()
		lastGuard    = time.Now()
		lastRxTotal  uint64
	)

	for {
		if err := ctx.Err(); err != nil {
			// Generation retirement: force-close both sides. This is a normal
			// exit, mirroring how relayCore unblocks via SetReadDeadline.
			s.forceClose()
			return 0, 0, nil
		}

		// Backlog fuse guard: compute the egress retry-queue backlog
		// (tcp_info receive deltas minus skb_send_sock accounting), engage
		// or lift the pause, and manage the drain window. Checked at the
		// top of every iteration (throttled) so a busy event stream cannot
		// starve it.
		if time.Since(lastGuard) >= tcpOffloadEpollWaitCap {
			lastGuard = time.Now()
			engage, lift := s.fuseStep(&lastProgress)
			if engage {
				// Drop the fds from epoll while the kernel drains the
				// already-redirected skbs; level-triggered IN would
				// busy-loop otherwise.
				delFds()
			} else if lift || (!s.fuseDrainUntil.IsZero() && time.Now().After(s.fuseDrainUntil)) {
				s.fuseDrainUntil = time.Time{}
				if err := addFds(); err != nil {
					s.forceClose()
					return 0, 0, err
				}
			}
		}

		waitMs := int(tcpOffloadEpollWaitCap.Milliseconds())
		if !firstClose.IsZero() {
			remaining := relayHalfCloseTimeout - time.Since(firstClose)
			if remaining <= 0 {
				s.forceClose()
				return 0, 0, nil
			}
			if int(remaining.Milliseconds()) < waitMs {
				waitMs = max(int(remaining.Milliseconds()), 1)
			}
		}

		n, err := unix.EpollWait(epfd, events[:], waitMs)
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			s.forceClose()
			return 0, 0, fmt.Errorf("epoll_wait: %w", err)
		}

		if n == 0 {
			// Idle watchdog (relayCore parity): any traffic in either direction
			// refreshes lastProgress; a fully idle offloaded relay is reclaimed.
			if time.Since(lastPoll) >= tcpOffloadIdlePollInterval {
				lastPoll = time.Now()
				if rx, ok := s.rxTotalOK(); ok {
					if rx != lastRxTotal {
						lastRxTotal = rx
						lastProgress = time.Now()
					} else if time.Since(lastProgress) > relayIdleTimeout {
						s.forceClose()
						return 0, 0, nil
					}
				}
			}
			if !firstClose.IsZero() && time.Since(firstClose) >= relayHalfCloseTimeout {
				s.forceClose()
				return 0, 0, nil
			}
			continue
		}

		for i := range n {
			if events[i].Events&unix.EPOLLIN != 0 {
				// SK_PASS fallback: the verdict program passes data through
				// while the backlog fuse is engaged, so data sits in the
				// kernel receive queue and must be forwarded from
				// userspace. tcp_info receive counters already cover these
				// bytes for final accounting.
				closed, err := s.relayPassData(events[i].Fd, &lastProgress)
				if closed {
					switch events[i].Fd {
					case 0:
						closedMask |= 1
					case 1:
						closedMask |= 2
					}
				}
				if err != nil {
					s.forceClose()
					return 0, 0, fmt.Errorf("relay pass data: %w", err)
				}
			}
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
		if closedMask == 0x3 {
			return 0, 0, nil
		}
		if firstClose.IsZero() && closedMask != 0 {
			firstClose = time.Now()
		}
	}
}

// relayPassData forwards SK_PASS data sitting in one relay socket's receive
// queue to the peer socket. The verdict program declines to redirect when the
// session's fast_sock entry is detached (backlog fuse) or the peer's send
// path is congested; forwarded bytes are already counted by the tcp_info
// receive baselines used for final accounting.
// The first return value reports a read EOF (peer half-close); a non-nil
// error is a read/write failure that should end the session.
func (s *tcpRelayOffloadSession) relayPassData(index int32, lastProgress *time.Time) (bool, error) {
	src, dst := s.left, s.right
	if index == 1 {
		src, dst = s.right, s.left
	}
	bufPtr := relayCopyBufferPool.Get().(*[]byte)
	buf := *bufPtr
	defer relayCopyBufferPool.Put(bufPtr)

	_ = src.SetReadDeadline(time.Now().Add(relayPassWriteTimeout))
	defer func() { _ = src.SetReadDeadline(time.Time{}) }()
	_ = dst.SetWriteDeadline(time.Now().Add(relayPassWriteTimeout))
	defer func() { _ = dst.SetWriteDeadline(time.Time{}) }()
	n, err := src.Read(buf)
	if err != nil && errors.Is(err, os.ErrDeadlineExceeded) {
		return false, nil // transiently empty; level-triggered epoll re-reports
	}
	if n > 0 {
		if _, werr := dst.Write(buf[:n]); werr != nil {
			if errors.Is(werr, syscall.EPIPE) || errors.Is(werr, syscall.ECONNRESET) {
				return true, nil
			}
			return false, werr
		}
		s.fusePassBytes += uint64(n)
		*lastProgress = time.Now()
	}
	if err != nil {
		// Close races surface as read failures on the fallback path; the
		// half-close bookkeeping below owns that teardown.
		if errors.Is(err, io.EOF) || errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNRESET) {
			return true, nil
		}
		return false, err
	}
	return false, nil
}

func (s *tcpRelayOffloadSession) forceClose() {
	s.forceCloseOnce.Do(func() {
		l, r, aerr := s.rxDeltas()
		if aerr == nil {
			s.finalLeftRx, s.finalRightRx = l, r
		}
		s.accounted.Store(true)
	})
	_ = s.left.Close()
	_ = s.right.Close()
}

func (s *tcpRelayOffloadSession) accountedDeltas() (int64, int64, bool) {
	if !s.accounted.Load() {
		return 0, 0, false
	}
	return s.finalLeftRx, s.finalRightRx, true
}

func (s *tcpRelayOffloadSession) rxTotalOK() (uint64, bool) {
	l, err := tcpConnRxBytes(s.left)
	if err != nil {
		return 0, false
	}
	r, err := tcpConnRxBytes(s.right)
	if err != nil {
		return 0, false
	}
	return l + r, true
}

func (s *tcpRelayOffloadSession) rxDeltas() (int64, int64, error) {
	l, err := tcpConnRxBytes(s.left)
	if err != nil {
		return 0, 0, err
	}
	r, err := tcpConnRxBytes(s.right)
	if err != nil {
		return 0, 0, err
	}
	return int64(l - s.leftRxBase), int64(r - s.rightRxBase), nil
}

func tcpOffloadFlushLeftPrefix(left, right netproxy.Conn) (int, error) {
	var segs [][]byte
	if ss, ok := left.(relaySegmentSource); ok {
		segs = relayNonEmptySegments(ss.TakeRelaySegments())
	} else if ps, ok := left.(relayPrefixSource); ok {
		if p := ps.TakeRelayPrefix(); len(p) > 0 {
			segs = [][]byte{p}
		}
	}
	if len(segs) == 0 {
		return 0, nil
	}
	return relayGatherWriteTo(right, segs)
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

// makeTuplesKey builds the fast_sock key for a socket: sip=src (remote),
// dip=dst (local), with ports in network byte order. tcp_offload_redirect
// builds the identical layout from the skb context.
func makeTuplesKey(src, dst netip.AddrPort, l4proto uint8) bpfTuplesKey {
	return bpfTuplesKey{
		Sip:     bpfIp6FromAddr(src.Addr()),
		Dip:     bpfIp6FromAddr(dst.Addr()),
		Sport:   common.Htons(src.Port()),
		Dport:   common.Htons(dst.Port()),
		L4proto: l4proto,
	}
}

func bpfIp6FromAddr(addr netip.Addr) (out struct {
	_       structs.HostLayout
	U6Addr8 [16]uint8
}) {
	out.U6Addr8 = addr.As16()
	return out
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

const (
	tcpOffloadQueueDrainMaxIter = 16
	tcpOffloadQueueDrainMaxByte = 512 << 10
)

// tcpConnDrainKernelQueue moves data already sitting in src's kernel receive
// queue onto dst before the sockmap pair is registered, returning the number
// of bytes moved. The user-space prefix flush only covers userspace-buffered
// bytes; early client payload or server-first greetings arrive in the kernel
// queue instead.
func tcpConnDrainKernelQueue(src, dst *net.TCPConn) (int, error) {
	srcFD, err := tcpConnFD(src)
	if err != nil {
		return 0, err
	}
	total := 0
	for range tcpOffloadQueueDrainMaxIter {
		pending, err := tcpConnPendingBytes(src)
		if err != nil || pending <= 0 {
			return total, err
		}
		if pending > tcpOffloadQueueDrainMaxByte-total {
			return total, fmt.Errorf("kernel queue too large (%d pending)", pending)
		}
		buf := make([]byte, pending)
		n, err := unix.Read(srcFD, buf)
		if err != nil {
			if err == unix.EAGAIN {
				continue
			}
			return total, err
		}
		if n == 0 {
			return total, nil
		}
		written := 0
		for written < n {
			w, werr := dst.Write(buf[written:n])
			if w > 0 {
				written += w
			}
			if werr != nil {
				return total, werr
			}
			if w == 0 {
				return total, io.ErrShortWrite
			}
		}
		total += n
	}
	return total, nil
}

// tcpConnPendingBytes reports the byte count in the socket's kernel receive
// queue via TIOCINQ.
func tcpConnPendingBytes(conn *net.TCPConn) (int, error) {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var (
		pending int
		ctrlErr error
	)
	if err := rawConn.Control(func(fd uintptr) {
		pending, ctrlErr = unix.IoctlGetInt(int(fd), unix.TIOCINQ)
	}); err != nil {
		return 0, err
	}
	return pending, ctrlErr
}

func tcpConnInfo(conn *net.TCPConn) (*unix.TCPInfo, error) {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return nil, err
	}
	var (
		info    *unix.TCPInfo
		ctrlErr error
	)
	if err := rawConn.Control(func(fd uintptr) {
		info, ctrlErr = unix.GetsockoptTCPInfo(int(fd), unix.SOL_TCP, unix.TCP_INFO)
	}); err != nil {
		return nil, err
	}
	if ctrlErr != nil {
		return nil, ctrlErr
	}
	if info == nil {
		return nil, fmt.Errorf("empty tcp_info")
	}
	return info, nil
}

func tcpConnRxBytes(conn *net.TCPConn) (uint64, error) {
	info, err := tcpConnInfo(conn)
	if err != nil {
		return 0, err
	}
	return info.Bytes_received, nil
}

func tcpRelayOffloadReason(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	if errors.Is(err, errTCPRelayOffloadUnavailable) {
		prefix := errTCPRelayOffloadUnavailable.Error()
		msg = msg[len(prefix):]
		msg = strings.TrimPrefix(msg, ":")
		msg = strings.TrimSpace(msg)
		if msg == "" {
			return "unavailable"
		}
	}
	return msg
}
