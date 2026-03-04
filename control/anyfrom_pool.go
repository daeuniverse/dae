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
	"unsafe"

	"github.com/daeuniverse/dae/component/outbound/dialer"
	"golang.org/x/sys/unix"
)

type Anyfrom struct {
	*net.UDPConn
	ttl           time.Duration
	expiresAtNano atomic.Int64
	// GSO support is modified from quic-go with many thanks.
	gso bool
	// gotGSOError is set true the first time a GSO-related error is seen.
	// Declared as atomic.Bool because Anyfrom is shared across goroutines:
	// multiple goroutines may call Write methods concurrently, each triggering
	// afterWrite.  A plain bool would be a data race under go test -race.
	gotGSOError atomic.Bool
}

func (a *Anyfrom) afterWrite(err error) {
	// CAS-style: only pay the atomic-store cost when transitioning false→true.
	if !a.gotGSOError.Load() && isGSOError(err) {
		a.gotGSOError.Store(true)
	}
	a.RefreshTtl()
}
func (a *Anyfrom) RefreshTtl() {
	if a.ttl > 0 {
		a.expiresAtNano.Store(time.Now().Add(a.ttl).UnixNano())
	}
}

func (a *Anyfrom) IsExpired(nowNano int64) bool {
	expiresAt := a.expiresAtNano.Load()
	return expiresAt > 0 && nowNano >= expiresAt
}
func (a *Anyfrom) SupportGso(size int) bool {
	if size > math.MaxUint16 {
		return false
	}
	return a.gso && !a.gotGSOError.Load()
}
func (a *Anyfrom) ReadFrom(b []byte) (int, net.Addr, error) {
	defer a.RefreshTtl()
	return a.UDPConn.ReadFrom(b)
}
func (a *Anyfrom) ReadFromUDP(b []byte) (n int, addr *net.UDPAddr, err error) {
	defer a.RefreshTtl()
	return a.UDPConn.ReadFromUDP(b)
}
func (a *Anyfrom) ReadFromUDPAddrPort(b []byte) (n int, addr netip.AddrPort, err error) {
	defer a.RefreshTtl()
	return a.UDPConn.ReadFromUDPAddrPort(b)
}
func (a *Anyfrom) ReadMsgUDP(b []byte, oob []byte) (n int, oobn int, flags int, addr *net.UDPAddr, err error) {
	defer a.RefreshTtl()
	return a.UDPConn.ReadMsgUDP(b, oob)
}
func (a *Anyfrom) ReadMsgUDPAddrPort(b []byte, oob []byte) (n int, oobn int, flags int, addr netip.AddrPort, err error) {
	defer a.RefreshTtl()
	return a.UDPConn.ReadMsgUDPAddrPort(b, oob)
}
func (a *Anyfrom) SyscallConn() (syscall.RawConn, error) {
	defer a.RefreshTtl()
	return a.UDPConn.SyscallConn()
}
func (a *Anyfrom) WriteMsgUDP(b []byte, oob []byte, addr *net.UDPAddr) (n int, oobn int, err error) {
	defer func() { a.afterWrite(err) }()
	// UDP GSO (UDP_SEGMENT) is NOT used here.
	// UDP GSO is designed for "super-buffer" sends: the caller concatenates multiple
	// equal-sized datagrams into one large buffer and the kernel splits them into
	// individual packets in hardware.  Anyfrom proxies ONE datagram per Write call;
	// there is no super-buffer.  Setting UDP_SEGMENT on a single payload would split
	// one large datagram into multiple smaller ones, breaking UDP datagram semantics.
	// Additionally, gsoSize=1500 would create 1528-byte IPv4 packets (1500+20+8),
	// exceeding the standard MTU.  The correct value for UDP_SEGMENT is MTU-28 (IPv4)
	// or MTU-48 (IPv6).  GSO support is retained for future batch-send redesign.
	return a.UDPConn.WriteMsgUDP(b, oob, addr)
}
func (a *Anyfrom) WriteMsgUDPAddrPort(b []byte, oob []byte, addr netip.AddrPort) (n int, oobn int, err error) {
	defer func() { a.afterWrite(err) }()
	return a.UDPConn.WriteMsgUDPAddrPort(b, oob, addr)
}
func (a *Anyfrom) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	defer func() { a.afterWrite(err) }()
	return a.UDPConn.WriteTo(b, addr)
}
func (a *Anyfrom) WriteToUDP(b []byte, addr *net.UDPAddr) (n int, err error) {
	defer func() { a.afterWrite(err) }()
	return a.UDPConn.WriteToUDP(b, addr)
}
func (a *Anyfrom) WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (n int, err error) {
	defer func() { a.afterWrite(err) }()
	return a.UDPConn.WriteToUDPAddrPort(b, addr)
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
func appendUDPSegmentSizeMsg(b []byte, size uint16) []byte {
	startLen := len(b)
	const dataLen = 2 // payload is a uint16
	b = append(b, make([]byte, unix.CmsgSpace(dataLen))...)
	h := (*unix.Cmsghdr)(unsafe.Pointer(&b[startLen]))
	h.Level = syscall.IPPROTO_UDP
	h.Type = unix.UDP_SEGMENT
	h.SetLen(unix.CmsgLen(dataLen))

	// UnixRights uses the private `data` method, but I *think* this achieves the same goal.
	offset := startLen + unix.CmsgSpace(0)
	*(*uint16)(unsafe.Pointer(&b[offset])) = size
	return b
}

// AnyfromPool is a full-cone udp listener pool
const (
	anyfromPoolShardCount = 64
	anyfromJanitorPeriod  = 500 * time.Millisecond
)

type anyfromPoolShard struct {
	mu   sync.RWMutex
	pool map[netip.AddrPort]*Anyfrom
}

type AnyfromPool struct {
	shards      [anyfromPoolShardCount]anyfromPoolShard
	janitorOnce sync.Once
}

var DefaultAnyfromPool = NewAnyfromPool()

func NewAnyfromPool() *AnyfromPool {
	p := &AnyfromPool{}
	for i := range anyfromPoolShardCount {
		p.shards[i].pool = make(map[netip.AddrPort]*Anyfrom, 16)
	}
	p.startJanitor()
	return p
}

func (p *AnyfromPool) GetOrCreate(lAddr netip.AddrPort, ttl time.Duration) (conn *Anyfrom, isNew bool, err error) {
	shard := p.shardFor(lAddr)
	shard.mu.RLock()
	af, ok := shard.pool[lAddr]
	if !ok {
		shard.mu.RUnlock()
		shard.mu.Lock()
		defer shard.mu.Unlock()
		if af, ok = shard.pool[lAddr]; ok {
			af.RefreshTtl()
			return af, false, nil
		}
		// Create an Anyfrom.
		isNew = true
		d := net.ListenConfig{
			Control: func(network string, address string, c syscall.RawConn) error {
				return dialer.TransparentControl(c)
			},
			KeepAlive: 0,
		}
		var pc net.PacketConn
		if err = GetDaeNetns().WithRequired("listen anyfrom udp socket", func() error {
			var listenErr error
			pc, listenErr = d.ListenPacket(context.Background(), "udp", lAddr.String())
			return listenErr
		}); err != nil {
			return nil, true, err
		}
		uConn := pc.(*net.UDPConn)
		af = &Anyfrom{
			UDPConn: uConn,
			ttl:     ttl,
			gso:     isGSOSupported(uConn),
			// gotGSOError zero-value (false) is correct; set atomically on first error.
		}

		if ttl > 0 {
			af.RefreshTtl()
			shard.pool[lAddr] = af
		}
		return af, true, nil
	} else {
		af.RefreshTtl()
		shard.mu.RUnlock()
		return af, false, nil
	}
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

			for now := range ticker.C {
				nowNano := now.UnixNano()
				for i := range anyfromPoolShardCount {
					shard := &p.shards[i]
					// UDPConn.Close() is a non-blocking O(1) syscall; safe to call
					// under the shard lock — eliminates the temporary expiredItem
					// slice allocation that occurred every janitor tick.
					shard.mu.Lock()
					for key, af := range shard.pool {
						if af.IsExpired(nowNano) {
							delete(shard.pool, key)
							_ = af.Close()
						}
					}
					shard.mu.Unlock()
				}
			}
		}()
	})
}
