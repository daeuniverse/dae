/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2023, v2rayA Organization <team@v2raya.org>
 */

package control

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/mzz2017/softwind/netproxy"
	"github.com/v2rayA/dae/common/consts"
	internal "github.com/v2rayA/dae/pkg/ebpf_internal"
	"golang.org/x/sys/unix"
	"net/netip"
	"os"
	"syscall"
)

func (c *ControlPlaneCore) RetrieveRoutingResult(src, dst netip.AddrPort, l4proto uint8) (result *bpfRoutingResult, err error) {
	srcIp6 := src.Addr().As16()
	dstIp6 := dst.Addr().As16()

	tuples := &bpfTuples{
		Sip:     struct{ U6Addr8 [16]uint8 }{U6Addr8: srcIp6},
		Sport:   internal.Htons(src.Port()),
		Dip:     struct{ U6Addr8 [16]uint8 }{U6Addr8: dstIp6},
		Dport:   internal.Htons(dst.Port()),
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

func GetNetwork(network string, mark uint32) string {
	if mark == 0 {
		return network
	} else {
		return netproxy.MagicNetwork{
			Network: network,
			Mark:    mark,
		}.Encode()
	}
}
