/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2023, v2rayA Organization <team@v2raya.org>
 */

package control

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/mzz2017/softwind/netproxy"
	"github.com/v2rayA/dae/common"
	"github.com/v2rayA/dae/common/consts"
	"golang.org/x/sys/unix"
	"net/netip"
	"os"
	"syscall"
)

func (c *ControlPlane) Route(src, dst netip.AddrPort, domain string, l4proto consts.L4ProtoType, routingResult *bpfRoutingResult) (outboundIndex consts.OutboundIndex, mark uint32, err error) {
	var ipVersion consts.IpVersionType
	if dst.Addr().Is4() || dst.Addr().Is4In6() {
		ipVersion = consts.IpVersion_4
	} else {
		ipVersion = consts.IpVersion_6
	}
	bSrc := src.Addr().As16()
	bDst := dst.Addr().As16()
	if outboundIndex, mark, err = c.routingMatcher.Match(
		bSrc[:],
		bDst[:],
		src.Port(),
		dst.Port(),
		ipVersion,
		l4proto,
		domain,
		routingResult.Pname,
		append([]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, routingResult.Mac[:]...),
	); err != nil {
		return 0, 0, err
	}
	return outboundIndex, mark, nil
}

func (c *ControlPlaneCore) RetrieveRoutingResult(src, dst netip.AddrPort, l4proto uint8) (result *bpfRoutingResult, err error) {
	srcIp6 := src.Addr().As16()
	dstIp6 := dst.Addr().As16()

	tuples := &bpfTuples{
		Sip:     struct{ U6Addr8 [16]uint8 }{U6Addr8: srcIp6},
		Sport:   common.Htons(src.Port()),
		Dip:     struct{ U6Addr8 [16]uint8 }{U6Addr8: dstIp6},
		Dport:   common.Htons(dst.Port()),
		L4proto: l4proto,
	}

	var routingResult bpfRoutingResult
	if err := c.bpf.RoutingTuplesMap.Lookup(tuples, &routingResult); err != nil {
		return nil, fmt.Errorf("reading map: key [%v, %v, %v]: %w", src.String(), l4proto, dst.String(), err)
	}
	return &routingResult, nil
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
			return netip.AddrPortFrom(netip.AddrFrom16(*(*[16]byte)(ip)), port)
		}
	}
	return netip.AddrPort{}
}

func checkIpforward(ifname string, ipversion consts.IpVersionStr) error {
	path := fmt.Sprintf("/proc/sys/net/ipv%v/conf/%v/forwarding", ipversion, ifname)
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if bytes.Equal(bytes.TrimSpace(b), []byte("1")) {
		return nil
	}
	return fmt.Errorf("ipforward on %v is off: %v; see https://github.com/v2rayA/dae#enable-ip-forwarding", ifname, path)
}

func CheckIpforward(ifname string) error {
	if err := checkIpforward(ifname, consts.IpVersionStr_4); err != nil {
		return err
	}
	if err := checkIpforward(ifname, consts.IpVersionStr_6); err != nil {
		return err
	}
	return nil
}

func MagicNetwork(network string, mark uint32) string {
	if mark == 0 {
		return network
	} else {
		return netproxy.MagicNetwork{
			Network: network,
			Mark:    mark,
		}.Encode()
	}
}

func ProcessName2String(pname []uint8) string {
	return string(bytes.TrimRight(pname[:], string([]byte{0})))
}

func Mac2String(mac []uint8) string {
	ori := []byte(hex.EncodeToString(mac))
	// Insert ":".
	b := make([]byte, len(ori)/2*3-1)
	for i, j := 0, 0; i < len(ori); i, j = i+2, j+3 {
		copy(b[j:j+2], ori[i:i+2])
		if j+2 < len(b) {
			b[j+2] = ':'
		}
	}
	return string(b)
}
