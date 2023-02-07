/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2023, mzz2017 <mzz@tuta.io>
 */

package control

import (
	"encoding/binary"
	"fmt"
	"github.com/v2rayA/dae/common"
	"github.com/v2rayA/dae/common/consts"
	internal "github.com/v2rayA/dae/pkg/ebpf_internal"
	"golang.org/x/sys/unix"
	"net/netip"
	"syscall"
)

func (c *ControlPlaneCore) RetrieveOutboundIndex(src, dst netip.AddrPort, l4proto uint8) (outboundIndex consts.OutboundIndex, tuples *bpfTuples, err error) {
	srcIp6 := src.Addr().As16()
	dstIp6 := dst.Addr().As16()

	tuples = &bpfTuples{
		Src: bpfIpPort{
			Ip:   common.Ipv6ByteSliceToUint32Array(srcIp6[:]),
			Port: internal.Htons(src.Port()),
		},
		Dst: bpfIpPort{
			Ip:   common.Ipv6ByteSliceToUint32Array(dstIp6[:]),
			Port: internal.Htons(dst.Port()),
		},
		L4proto: l4proto,
	}

	var _outboundIndex uint32
	if err := c.bpf.RoutingTuplesMap.Lookup(tuples, &_outboundIndex); err != nil {
		return 0, nil, fmt.Errorf("reading map: key [%v, %v, %v]: %w", src.String(), l4proto, dst.String(), err)
	}
	if _outboundIndex > uint32(consts.OutboundLogicalMax) {
		return 0, nil, fmt.Errorf("bad outbound index")
	}
	return consts.OutboundIndex(_outboundIndex), tuples, nil
}

func RetrieveOriginalDest(oob []byte) netip.AddrPort {
	msgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return netip.AddrPort{}
	}
	for _, msg := range msgs {
		if msg.Header.Level == syscall.SOL_IP && msg.Header.Type == syscall.IP_RECVORIGDSTADDR {
			ip := msg.Data[4:8]
			port := binary.BigEndian.Uint16(msg.Data[2:4])
			return netip.AddrPortFrom(netip.AddrFrom4(*(*[4]byte)(ip)), port)
		} else if msg.Header.Level == syscall.SOL_IPV6 && msg.Header.Type == unix.IPV6_RECVORIGDSTADDR {
			ip := msg.Data[8:24]
			port := binary.BigEndian.Uint16(msg.Data[2:4])
			return netip.AddrPortFrom(netip.AddrFrom4(*(*[4]byte)(ip)), port)
		}
	}
	return netip.AddrPort{}
}
