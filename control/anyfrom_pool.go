/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/daeuniverse/dae/component/outbound/dialer"
	"golang.org/x/sys/unix"
)

type Anyfrom struct {
	*net.UDPConn
	deadlineTimer *time.Timer
	ttl           time.Duration
	// GSO support is modified from quic-go with many thanks.
	gso         bool
	gotGSOError bool
}

func (a *Anyfrom) afterWrite(err error) {
	if !a.gotGSOError && isGSOError(err) {
		a.gotGSOError = true
	}
	a.RefreshTtl()
}
func (a *Anyfrom) RefreshTtl() {
	if a.deadlineTimer != nil {
		a.deadlineTimer.Reset(a.ttl)
	}
}
func (a *Anyfrom) SupportGso(size int) bool {
	if size > math.MaxUint16 {
		return false
	}
	return a.gso && !a.gotGSOError
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
	defer a.afterWrite(err)
	if a.SupportGso(len(b)) {
		return a.UDPConn.WriteMsgUDP(b, appendUDPSegmentSizeMsg(oob, uint16(len(b))), addr)
	}
	return a.UDPConn.WriteMsgUDP(b, oob, addr)
}
func (a *Anyfrom) WriteMsgUDPAddrPort(b []byte, oob []byte, addr netip.AddrPort) (n int, oobn int, err error) {
	defer a.afterWrite(err)
	if a.SupportGso(len(b)) {
		return a.UDPConn.WriteMsgUDPAddrPort(b, appendUDPSegmentSizeMsg(oob, uint16(len(b))), addr)
	}
	return a.UDPConn.WriteMsgUDPAddrPort(b, oob, addr)
}
func (a *Anyfrom) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	defer a.afterWrite(err)
	if a.SupportGso(len(b)) {
		n, _, err = a.UDPConn.WriteMsgUDP(b, appendUDPSegmentSizeMsg(nil, uint16(len(b))), addr.(*net.UDPAddr))
		return n, err
	}
	return a.UDPConn.WriteTo(b, addr)
}
func (a *Anyfrom) WriteToUDP(b []byte, addr *net.UDPAddr) (n int, err error) {
	defer a.afterWrite(err)
	if a.SupportGso(len(b)) {
		n, _, err = a.UDPConn.WriteMsgUDP(b, appendUDPSegmentSizeMsg(nil, uint16(len(b))), addr)
		return n, err
	}
	return a.UDPConn.WriteToUDP(b, addr)
}
func (a *Anyfrom) WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (n int, err error) {
	defer a.afterWrite(err)
	if a.SupportGso(len(b)) {
		n, _, err = a.UDPConn.WriteMsgUDPAddrPort(b, appendUDPSegmentSizeMsg(nil, uint16(len(b))), addr)
		return n, err
	}
	return a.UDPConn.WriteToUDPAddrPort(b, addr)
}

// isGSOSupported tests if the kernel supports GSO.
// Sending with GSO might still fail later on, if the interface doesn't support it (see isGSOError).
func isGSOSupported(uc *net.UDPConn) bool {
	// TODO: We disable GSO because we haven't thought through how to design to use larger packets (we assume the max size of packet is 1500).
	// See https://github.com/daeuniverse/dae/blob/cab1e4290967340923d7d5ca52b80f781711c18e/control/control_plane.go#L721C37-L721C37.
	return false
	conn, err := uc.SyscallConn()
	if err != nil {
		return false
	}
	disabled, err := strconv.ParseBool(os.Getenv("DAE_DISABLE_GSO"))
	if err == nil && disabled {
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
type AnyfromPool struct {
	pool sync.Map // 使用sync.Map减少锁竞争
}

var DefaultAnyfromPool = NewAnyfromPool()

func NewAnyfromPool() *AnyfromPool {
	return &AnyfromPool{}
}

func (p *AnyfromPool) GetOrCreate(lAddr string, ttl time.Duration) (conn *Anyfrom, isNew bool, err error) {
	if af, ok := p.pool.Load(lAddr); ok {
		anyfrom := af.(*Anyfrom)
		anyfrom.RefreshTtl()
		return anyfrom, false, nil
	}

	// 使用更精确的双重检查锁定模式避免重复创建
	// 创建临时key用于创建锁
	createKey := lAddr + "_creating"
	if _, loaded := p.pool.LoadOrStore(createKey, struct{}{}); loaded {
		// 有其他goroutine在创建，使用退避重试机制
		for i := 0; i < 10; i++ {
			time.Sleep(time.Millisecond * time.Duration(i+1)) // 递增退避
			if af, ok := p.pool.Load(lAddr); ok {
				anyfrom := af.(*Anyfrom)
				anyfrom.RefreshTtl()
				return anyfrom, false, nil
			}
		}
		// 如果等待后仍未创建成功，返回错误而不是继续创建
		return nil, false, fmt.Errorf("timeout waiting for connection creation on %s", lAddr)
	}

	defer p.pool.Delete(createKey)

	// 再次检查是否已创建
	if af, ok := p.pool.Load(lAddr); ok {
		anyfrom := af.(*Anyfrom)
		anyfrom.RefreshTtl()
		return anyfrom, false, nil
	}

	// 创建新的Anyfrom
	d := net.ListenConfig{
		Control: func(network string, address string, c syscall.RawConn) error {
			return dialer.TransparentControl(c)
		},
		KeepAlive: 0,
	}
	var pc net.PacketConn
	GetDaeNetns().With(func() error {
		pc, err = d.ListenPacket(context.Background(), "udp", lAddr)
		return nil
	})
	if err != nil {
		return nil, true, fmt.Errorf("failed to create UDP connection for %s: %w", lAddr, err)
	}

	uConn := pc.(*net.UDPConn)
	af := &Anyfrom{
		UDPConn:       uConn,
		deadlineTimer: nil,
		ttl:           ttl,
		gotGSOError:   false,
		gso:           isGSOSupported(uConn),
	}

	if ttl > 0 {
		af.deadlineTimer = time.AfterFunc(ttl, func() {
			if loaded := p.pool.CompareAndDelete(lAddr, af); loaded {
				af.Close()
			}
		})
	}

	p.pool.Store(lAddr, af)
	return af, true, nil
}
