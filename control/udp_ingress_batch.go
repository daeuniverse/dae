/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net"
	"net/netip"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/outbound/pool"
	"golang.org/x/net/ipv4"
)

const (
	defaultUdpIngressBatchSize = 8
	udpIngressOobSize          = 120
)

type udpIngressBatchSlot struct {
	buf     pool.PB
	buffers [][]byte
	oob     [udpIngressOobSize]byte
}

type udpIngressBatchReader struct {
	pc    *ipv4.PacketConn
	slots []udpIngressBatchSlot
	msgs  []ipv4.Message
}

func newUdpIngressBatchReader(conn *net.UDPConn, batchSize int) *udpIngressBatchReader {
	if batchSize <= 0 {
		batchSize = defaultUdpIngressBatchSize
	}
	r := &udpIngressBatchReader{
		pc:    ipv4.NewPacketConn(conn),
		slots: make([]udpIngressBatchSlot, batchSize),
		msgs:  make([]ipv4.Message, batchSize),
	}
	for i := range r.slots {
		r.slots[i].buffers = make([][]byte, 1)
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
		if r.slots[i].buf != nil {
			r.slots[i].buf.Put()
			r.slots[i].buf = nil
			r.slots[i].buffers[0] = nil
		}
	}
}

func (r *udpIngressBatchReader) ReadBatch() (int, error) {
	for i := range r.slots {
		slot := &r.slots[i]
		if slot.buf == nil {
			slot.buf = pool.GetFullCap(consts.EthernetMtu)
		}
		slot.buffers[0] = slot.buf
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

	udpAddr, addrOk := r.msgs[i].Addr.(*net.UDPAddr)
	if !addrOk || udpAddr == nil {
		slot.buf.Put()
		return nil, netip.AddrPort{}, nil, false
	}

	pktBuf = slot.buf[:r.msgs[i].N]
	src = udpAddr.AddrPort()
	oob = slot.oob[:r.msgs[i].NN]
	return pktBuf, src, oob, true
}
