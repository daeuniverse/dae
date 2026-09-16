/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net"
	"net/netip"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/outbound/pool"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

const (
	// defaultUDPIngressBatchSize is the recvmmsg batch width per read loop.
	// Each slot has a small owned buffer and a reusable overflow area, bounded
	// to about 2 MiB per listener rather than 64 KiB per in-flight packet.
	defaultUDPIngressBatchSize = 32
	udpIngressOobSize          = 120

	// Tproxy delivers ordinary UDP payloads with the original destination in
	// OOB data, not MTU-sized frames. This covers all non-jumbo UDP datagrams;
	// MSG_TRUNC still rejects anything that exceeds the receive capacity.
	udpIngressMaxDatagramSize = 65535
)

func udpIngressMessageComplete(n, oobn, flags, capacity, oobCapacity int) bool {
	return flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) == 0 &&
		n >= 0 && n <= capacity && oobn >= 0 && oobn <= oobCapacity
}

type udpIngressSinglePacketConn interface {
	ReadMsgUDPAddrPort([]byte, []byte) (int, int, int, netip.AddrPort, error)
}

type udpIngressSingleReader struct {
	pc  udpIngressSinglePacketConn
	buf [udpIngressMaxDatagramSize]byte
}

// Read uses one reusable receive area. Only the actual payload size is pooled
// for asynchronous forwarding. OOB remains caller-owned and must be consumed
// before the next read; nil with no error means this datagram was dropped.
func (r *udpIngressSingleReader) Read(oob []byte) (pool.PB, netip.AddrPort, int, error) {
	n, oobn, flags, src, err := r.pc.ReadMsgUDPAddrPort(r.buf[:], oob)
	if err != nil {
		return nil, netip.AddrPort{}, 0, err
	}
	if !udpIngressMessageComplete(n, oobn, flags, len(r.buf), len(oob)) {
		return nil, netip.AddrPort{}, 0, nil
	}
	buf := pool.Get(n)
	copy(buf, r.buf[:n])
	return buf, src, oobn, nil
}

type udpIngressBatchSlot struct {
	buf      pool.PB
	buffers  [][]byte
	overflow []byte
	oob      [udpIngressOobSize]byte
}

type udpIngressBatchPacketConn interface {
	ReadBatch([]ipv6.Message, int) (int, error)
}

type udpIngressBatchReader struct {
	pc    udpIngressBatchPacketConn
	slots []udpIngressBatchSlot
	msgs  []ipv6.Message
}

func newUDPIngressBatchReader(conn *net.UDPConn, batchSize int) *udpIngressBatchReader {
	if conn == nil {
		return nil
	}
	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || addr == nil {
		return nil
	}
	if batchSize <= 0 {
		batchSize = defaultUDPIngressBatchSize
	}
	var pc udpIngressBatchPacketConn
	if addr.AddrPort().Addr().Is4() {
		pc = ipv4.NewPacketConn(conn)
	} else {
		pc = ipv6.NewPacketConn(conn)
	}
	r := &udpIngressBatchReader{
		pc:    pc,
		slots: make([]udpIngressBatchSlot, batchSize),
		msgs:  make([]ipv6.Message, batchSize),
	}
	for i := range r.slots {
		r.slots[i].buffers = make([][]byte, 2)
		r.msgs[i].Buffers = r.slots[i].buffers
		r.msgs[i].OOB = r.slots[i].oob[:]
	}
	return r
}

func (r *udpIngressBatchReader) Close() {
	if r == nil {
		return
	}
	for i := range r.slots {
		slot := &r.slots[i]
		if slot.buf != nil {
			slot.buf.Put()
			slot.buf = nil
			slot.buffers[0] = nil
		}
		slot.overflow = nil
		slot.buffers[1] = nil
	}
}

func (r *udpIngressBatchReader) ReadBatch() (int, error) {
	for i := range r.slots {
		slot := &r.slots[i]
		if slot.buf == nil {
			slot.buf = pool.GetFullCap(consts.EthernetMtu)
		}
		if slot.overflow == nil {
			slot.overflow = make([]byte, udpIngressMaxDatagramSize)
		}
		// Scatter reads keep the common small-packet ownership transfer free
		// of extra copies. The overflow storage never leaves this reader.
		slot.buffers[0] = slot.buf
		slot.buffers[1] = slot.overflow[:udpIngressMaxDatagramSize-len(slot.buf)]
		msg := &r.msgs[i]
		msg.Buffers = slot.buffers
		msg.OOB = slot.oob[:]
		msg.Addr = nil
		msg.N = 0
		msg.NN = 0
		msg.Flags = 0
	}
	return r.pc.ReadBatch(r.msgs, 0)
}

// Take transfers exclusive packet ownership to the caller. OOB borrows the
// slot's storage and must be consumed before the next ReadBatch or Close.
func (r *udpIngressBatchReader) Take(i int) (pktBuf pool.PB, src netip.AddrPort, oob []byte, ok bool) {
	if r == nil || i < 0 || i >= len(r.msgs) {
		return nil, netip.AddrPort{}, nil, false
	}
	slot := &r.slots[i]
	if slot.buf == nil {
		return nil, netip.AddrPort{}, nil, false
	}
	defer func() {
		slot.buf = nil
		slot.buffers[0] = nil
	}()

	msg := &r.msgs[i]
	udpAddr, addrOk := msg.Addr.(*net.UDPAddr)
	if !addrOk || udpAddr == nil ||
		!udpIngressMessageComplete(msg.N, msg.NN, msg.Flags, udpIngressMaxDatagramSize, len(slot.oob)) {
		slot.buf.Put()
		return nil, netip.AddrPort{}, nil, false
	}

	if msg.N <= len(slot.buf) {
		pktBuf = slot.buf[:msg.N]
	} else {
		pktBuf = pool.Get(msg.N)
		n := copy(pktBuf, slot.buf)
		copy(pktBuf[n:], slot.overflow[:msg.N-n])
		slot.buf.Put()
	}
	src = udpAddr.AddrPort()
	oob = slot.oob[:msg.NN]
	return pktBuf, src, oob, true
}
