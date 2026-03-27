/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"math"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/daeuniverse/dae/component/outbound/dialer"
	"golang.org/x/sys/unix"
)

var ErrAnyfromBindFailed = errors.New("anyfrom bind recently failed (negative cache)")

// ttlRefreshMinInterval is the minimum time between TTL refreshes.
// This throttles atomic stores on hot paths to reduce overhead under high QPS.
const ttlRefreshMinInterval = int64(200 * time.Millisecond)

type Anyfrom struct {
	*net.UDPConn
	ttl           time.Duration
	expiresAtNano atomic.Int64
	// lastRefreshNano tracks the last TTL refresh time for throttling.
	// Reduces atomic store frequency under high QPS from every I/O to ~5/sec max.
	lastRefreshNano atomic.Int64
	// GSO support is modified from quic-go with many thanks.
	gso bool
	// gotGSOError is set true the first time a GSO-related error is seen.
	// Declared as atomic.Bool because Anyfrom is shared across goroutines:
	// multiple goroutines may call Write methods concurrently, each triggering
	// afterWrite.  A plain bool would be a data race under go test -race.
	gotGSOError atomic.Bool

	failed atomic.Bool
}

// afterWrite handles post-write logic (GSO error tracking and TTL refresh).
// This is thread-safe because gotGSOError is atomic and refreshTtl uses atomics.
func (a *Anyfrom) afterWrite(err error) {
	// CAS-style: only pay the atomic-store cost when transitioning false→true.
	if !a.gotGSOError.Load() && isGSOError(err) {
		a.gotGSOError.Store(true)
	}
	a.refreshTtl()
}

// RefreshTtl updates the expiration time. Uses throttling to reduce atomic
// store overhead: only refreshes if at least ttlRefreshMinInterval has passed
// since the last refresh, or if TTL > 10s (refresh interval = TTL/50).
func (a *Anyfrom) RefreshTtl() {
	if a.ttl <= 0 {
		return
	}
	now := time.Now().UnixNano()
	last := a.lastRefreshNano.Load()
	// Throttle: skip if refreshed recently.
	// For long TTLs, use TTL/50 as interval; for short TTLs, use minimum.
	minInterval := ttlRefreshMinInterval
	if ttlNano := int64(a.ttl); ttlNano > 10*ttlRefreshMinInterval {
		minInterval = ttlNano / 50
	}
	if now-last < minInterval {
		return
	}
	// CAS to avoid thundering herd on the same connection.
	if a.lastRefreshNano.CompareAndSwap(last, now) {
		a.expiresAtNano.Store(now + int64(a.ttl))
	}
}

func (a *Anyfrom) refreshTtl() {
	a.RefreshTtl()
}

func (a *Anyfrom) IsExpired(nowNano int64) bool {
	expiresAt := a.expiresAtNano.Load()
	return expiresAt > 0 && nowNano >= expiresAt
}

// Close overrides the embedded UDPConn.Close to guard against nil —
// negatively-cached failure entries have a nil UDPConn.
func (a *Anyfrom) Close() error {
	if a.UDPConn != nil {
		return a.UDPConn.Close()
	}
	return nil
}
func (a *Anyfrom) SupportGso(size int) bool {
	if size > math.MaxUint16 {
		return false
	}
	return a.gso && !a.gotGSOError.Load()
}
func (a *Anyfrom) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	n, addr, err = a.UDPConn.ReadFrom(b)
	a.RefreshTtl()
	return n, addr, err
}
func (a *Anyfrom) ReadFromUDP(b []byte) (n int, addr *net.UDPAddr, err error) {
	n, addr, err = a.UDPConn.ReadFromUDP(b)
	a.RefreshTtl()
	return n, addr, err
}
func (a *Anyfrom) ReadFromUDPAddrPort(b []byte) (n int, addr netip.AddrPort, err error) {
	n, addr, err = a.UDPConn.ReadFromUDPAddrPort(b)
	a.RefreshTtl()
	return n, addr, err
}
func (a *Anyfrom) ReadMsgUDP(b []byte, oob []byte) (n int, oobn int, flags int, addr *net.UDPAddr, err error) {
	n, oobn, flags, addr, err = a.UDPConn.ReadMsgUDP(b, oob)
	a.RefreshTtl()
	return n, oobn, flags, addr, err
}
func (a *Anyfrom) ReadMsgUDPAddrPort(b []byte, oob []byte) (n int, oobn int, flags int, addr netip.AddrPort, err error) {
	n, oobn, flags, addr, err = a.UDPConn.ReadMsgUDPAddrPort(b, oob)
	a.RefreshTtl()
	return n, oobn, flags, addr, err
}
func (a *Anyfrom) SyscallConn() (rc syscall.RawConn, err error) {
	rc, err = a.UDPConn.SyscallConn()
	a.RefreshTtl()
	return rc, err
}
func (a *Anyfrom) WriteMsgUDP(b []byte, oob []byte, addr *net.UDPAddr) (n int, oobn int, err error) {
	// UDP GSO (UDP_SEGMENT) is NOT used here.
	// UDP GSO is designed for "super-buffer" sends: the caller concatenates multiple
	// equal-sized datagrams into one large buffer and the kernel splits them into
	// individual packets in hardware.  Anyfrom proxies ONE datagram per Write call;
	// there is no super-buffer.  Setting UDP_SEGMENT on a single payload would split
	// one large datagram into multiple smaller ones, breaking UDP datagram semantics.
	// Additionally, gsoSize=1500 would create 1528-byte IPv4 packets (1500+20+8),
	// exceeding the standard MTU.  The correct value for UDP_SEGMENT is MTU-28 (IPv4)
	// or MTU-48 (IPv6).  GSO support is retained for future batch-send redesign.
	n, oobn, err = a.UDPConn.WriteMsgUDP(b, oob, addr)
	a.afterWrite(err)
	return n, oobn, err
}

func (a *Anyfrom) WriteMsgUDPAddrPort(b []byte, oob []byte, addr netip.AddrPort) (n int, oobn int, err error) {
	n, oobn, err = a.UDPConn.WriteMsgUDPAddrPort(b, oob, addr)
	a.afterWrite(err)
	return n, oobn, err
}

func (a *Anyfrom) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	n, err = a.UDPConn.WriteTo(b, addr)
	a.afterWrite(err)
	return n, err
}

func (a *Anyfrom) WriteToUDP(b []byte, addr *net.UDPAddr) (n int, err error) {
	n, err = a.UDPConn.WriteToUDP(b, addr)
	a.afterWrite(err)
	return n, err
}

func (a *Anyfrom) WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (n int, err error) {
	n, err = a.UDPConn.WriteToUDPAddrPort(b, addr)
	a.afterWrite(err)
	return n, err
}

// isGSOSupported tests if the kernel supports GSO.
// Sending with GSO might still fail later on, if the interface doesn't support it (see isGSOError).
// isGSOSupported probes whether the kernel and interface support UDP GSO
// (UDP_SEGMENT socket option).  GSO is disabled by default — set DAE_ENABLE_GSO=1
// to opt in.  Note that the current Write methods do NOT use GSO because Anyfrom
// proxies one datagram per call (no super-buffer).  This detection is retained
// for a future batch-send redesign where multiple datagrams are coalesced.
func isGSOSupported(uc *net.UDPConn) bool {
	if enabled, _ := strconv.ParseBool(os.Getenv("DAE_ENABLE_GSO")); !enabled {
		return false
	}

	conn, err := uc.SyscallConn()
	if err != nil {
		return false
	}
	var serr error
	if err := conn.Control(func(fd uintptr) {
		_, serr = unix.GetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_SEGMENT)
	}); err != nil {
		return false
	}
	return serr == nil
}
func isGSOError(err error) bool {
	var serr *os.SyscallError
	if errors.As(err, &serr) {
		// EIO is returned by udp_send_skb() if the device driver does not have tx checksums enabled,
		// which is a hard requirement of UDP_SEGMENT. See:
		// https://git.kernel.org/pub/scm/docs/man-pages/man-pages.git/tree/man7/udp.7?id=806eabd74910447f21005160e90957bde4db0183#n228
		// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv4/udp.c?h=v6.2&id=c9c3395d5e3dcc6daee66c6908354d47bf98cb0c#n942
		return serr.Err == unix.EIO || serr.Err == unix.EINVAL
	}
	return false
}

// AnyfromPool is a full-cone udp listener pool
const (
	anyfromPoolShardCount = 64
	anyfromJanitorPeriod    = 500 * time.Millisecond
)

type anyfromPoolShard struct {
	mu       sync.RWMutex
	createMu sync.Mutex
	pool     map[netip.AddrPort]*Anyfrom
}

type AnyfromPool struct {
	shards      [anyfromPoolShardCount]anyfromPoolShard
	janitorOnce sync.Once
}

var DefaultAnyfromPool = NewAnyfromPool()

var soMarkFromDae uint32

func SetAnyfromSoMark(mark uint32) {
	soMarkFromDae = mark
}

func NewAnyfromPool() *AnyfromPool {
	p := &AnyfromPool{}
	for i := range anyfromPoolShardCount {
		p.shards[i].pool = make(map[netip.AddrPort]*Anyfrom, 16)
	}
	p.startJanitor()
	return p
}

// Reset clears all cached anyfrom connections.
// Called on reload to prevent stale connections from using pre-reload routing state.
// Uses two-phase deletion to avoid race with concurrent GetOrCreate:
// 1. Collect all keys under lock
// 2. Delete and close each entry
func (p *AnyfromPool) Reset() {
	for i := range anyfromPoolShardCount {
		shard := &p.shards[i]
		shard.mu.Lock()
		// Phase 1: Collect keys to avoid modifying map during iteration
		keys := make([]netip.AddrPort, 0, len(shard.pool))
		for key := range shard.pool {
			keys = append(keys, key)
		}
		// Phase 2: Delete and close each entry
		for _, key := range keys {
			if af, ok := shard.pool[key]; ok {
				delete(shard.pool, key)
				_ = af.Close() // Close errors are logged internally, safe to ignore here
			}
		}
		shard.mu.Unlock()
	}
}

func (p *AnyfromPool) GetOrCreate(lAddr netip.AddrPort, ttl time.Duration) (conn *Anyfrom, isNew bool, err error) {
	shard := p.shardFor(lAddr)

	// Fast path: existing socket
	shard.mu.RLock()
	af, ok := shard.pool[lAddr]
	if ok {
		if af.failed.Load() {
			if !af.IsExpired(time.Now().UnixNano()) {
				shard.mu.RUnlock()
				return nil, false, ErrAnyfromBindFailed
			}
		} else {
			af.RefreshTtl()
			shard.mu.RUnlock()
			return af, false, nil
		}
	}
	shard.mu.RUnlock()

	// Slow path: serialize creation for the same lAddr using a creation shard lock.
	// This prevents a thundering herd of concurrent bind() syscalls when many
	// packets arrive for the same unseen address simultaneously.
	shard.createMu.Lock()
	defer shard.createMu.Unlock()

	// Double-check under creation lock: another goroutine may have created it.
	shard.mu.RLock()
	af, ok = shard.pool[lAddr]
	if ok {
		if af.failed.Load() {
			if !af.IsExpired(time.Now().UnixNano()) {
				shard.mu.RUnlock()
				return nil, false, ErrAnyfromBindFailed
			}
			// Expired failure entry — fall through to recreate.
		} else {
			af.RefreshTtl()
			shard.mu.RUnlock()
			return af, false, nil
		}
	}
	shard.mu.RUnlock()

	// Only one goroutine per lAddr reaches here — safe to create.
	newAf, err := p.createAnyfromSocket(lAddr, ttl)

	shard.mu.Lock()
	defer shard.mu.Unlock()

	if err != nil {
		// Negative cache the failure to prevent bind storms under load.
		failedAf := &Anyfrom{
			ttl: 2 * time.Second,
		}
		failedAf.failed.Store(true)
		failedAf.expiresAtNano.Store(time.Now().Add(2 * time.Second).UnixNano())
		shard.pool[lAddr] = failedAf
		return nil, true, err
	}

	shard.pool[lAddr] = newAf
	return newAf, true, nil
}

// createAnyfromSocket creates a new Anyfrom socket without holding any pool locks.
// This is called by GetOrCreate after a cache miss, allowing concurrent socket
// creation for different addresses without blocking on the shard lock.
func (p *AnyfromPool) createAnyfromSocket(lAddr netip.AddrPort, ttl time.Duration) (*Anyfrom, error) {
	d := net.ListenConfig{
		Control: func(network string, address string, c syscall.RawConn) error {
			if err := dialer.TransparentControl(c); err != nil {
				return err
			}
			if soMarkFromDae != 0 {
				if err := dialer.SoMarkControl(c, int(soMarkFromDae)); err != nil {
					return err
				}
			}
			return nil
		},
		KeepAlive: 0,
	}
	var pc net.PacketConn
	if err := GetDaeNetns().WithRequired("listen anyfrom udp socket", func() error {
		var listenErr error
		pc, listenErr = d.ListenPacket(context.Background(), "udp", lAddr.String())
		return listenErr
	}); err != nil {
		return nil, err
	}
	uConn := pc.(*net.UDPConn)
	af := &Anyfrom{
		UDPConn: uConn,
		ttl:     ttl,
		gso:     isGSOSupported(uConn),
		// gotGSOError zero-value (false) is correct; set atomically on first error.
	}

	if ttl > 0 {
		af.RefreshTtl()
	}
	return af, nil
}

func (p *AnyfromPool) shardFor(lAddr netip.AddrPort) *anyfromPoolShard {
	idx := int(hashAddrPort(lAddr) & uint64(anyfromPoolShardCount-1))
	return &p.shards[idx]
}

func (p *AnyfromPool) startJanitor() {
	p.janitorOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(anyfromJanitorPeriod)
			defer ticker.Stop()

			// Reuse slice to reduce allocations across janitor cycles.
			var toClose []*Anyfrom

			for now := range ticker.C {
				nowNano := now.UnixNano()
				for i := range anyfromPoolShardCount {
					shard := &p.shards[i]
					// Collect expired connections under lock, close after release.
					// This minimizes lock hold time even with many expired entries.
					shard.mu.Lock()
					toClose = toClose[:0] // reset without reallocating
					for key, af := range shard.pool {
						if af.IsExpired(nowNano) {
							delete(shard.pool, key)
							toClose = append(toClose, af)
						}
					}
					shard.mu.Unlock()
					// Close connections outside the critical section.
					for _, af := range toClose {
						_ = af.Close()
					}
				}
			}
		}()
	})
}
