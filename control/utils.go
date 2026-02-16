/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"syscall"
	"unsafe"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"golang.org/x/sys/unix"
)

func (c *ControlPlane) Route(src, dst netip.AddrPort, domain string, l4proto consts.L4ProtoType, routingResult *bpfRoutingResult) (outboundIndex consts.OutboundIndex, mark uint32, must bool, err error) {
	var ipVersion consts.IpVersionType
	if dst.Addr().Is4() || dst.Addr().Is4In6() {
		ipVersion = consts.IpVersion_4
	} else {
		ipVersion = consts.IpVersion_6
	}
	var mac16 [16]uint8
	copy(mac16[10:], routingResult.Mac[:])
	bSrc := src.Addr().As16()
	bDst := dst.Addr().As16()
	if outboundIndex, mark, must, err = c.routingMatcher.Match(
		bSrc,
		bDst,
		src.Port(),
		dst.Port(),
		ipVersion,
		l4proto,
		domain,
		routingResult.Pname,
		routingResult.Dscp,
		mac16,
	); err != nil {
		return 0, 0, false, err
	}

	return outboundIndex, mark, false, nil
}

func (c *controlPlaneCore) RetrieveRoutingResult(src, dst netip.AddrPort, l4proto uint8) (result *bpfRoutingResult, err error) {
	srcIp6 := src.Addr().As16()
	dstIp6 := dst.Addr().As16()

	tuples := &bpfTuplesKey{
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
	ptrSize := int(unsafe.Sizeof(uintptr(0)))
	hdrLen := ptrSize + 8 // sizeof(size_t) + sizeof(int) + sizeof(int)
	if len(oob) < hdrLen {
		return netip.AddrPort{}
	}

	for len(oob) >= hdrLen {
		cmsgLen, ok := parseNativeUintptr(oob[:ptrSize])
		if !ok || cmsgLen < hdrLen || cmsgLen > len(oob) {
			return netip.AddrPort{}
		}

		level := int(int32(binary.NativeEndian.Uint32(oob[ptrSize : ptrSize+4])))
		typ := int(int32(binary.NativeEndian.Uint32(oob[ptrSize+4 : ptrSize+8])))
		data := oob[hdrLen:cmsgLen]

		switch {
		case level == syscall.SOL_IP && typ == syscall.IP_RECVORIGDSTADDR:
			if len(data) >= unix.SizeofSockaddrInet4 {
				port := binary.BigEndian.Uint16(data[2:4])
				var ip [4]byte
				copy(ip[:], data[4:8])
				return netip.AddrPortFrom(netip.AddrFrom4(ip), port)
			}
		case level == syscall.SOL_IPV6 && typ == unix.IPV6_RECVORIGDSTADDR:
			if len(data) >= unix.SizeofSockaddrInet6 {
				port := binary.BigEndian.Uint16(data[2:4])
				var ip [16]byte
				copy(ip[:], data[8:24])
				return netip.AddrPortFrom(netip.AddrFrom16(ip), port)
			}
		}

		next := cmsgAlign(cmsgLen, ptrSize)
		if next <= 0 || next > len(oob) {
			break
		}
		oob = oob[next:]
	}

	return netip.AddrPort{}
}

func parseNativeUintptr(b []byte) (int, bool) {
	switch len(b) {
	case 8:
		v := binary.NativeEndian.Uint64(b)
		if v > uint64(^uint(0)>>1) {
			return 0, false
		}
		return int(v), true
	case 4:
		v := binary.NativeEndian.Uint32(b)
		if uint64(v) > uint64(^uint(0)>>1) {
			return 0, false
		}
		return int(v), true
	default:
		return 0, false
	}
}

func cmsgAlign(length int, ptrSize int) int {
	if length <= 0 {
		return 0
	}
	return (length + ptrSize - 1) & ^(ptrSize - 1)
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
	return fmt.Errorf("ipforward on %v is off: %v; see docs of dae for help", ifname, path)
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

func setForwarding(ifname string, ipversion consts.IpVersionStr, val string) error {
	path := fmt.Sprintf("/proc/sys/net/ipv%v/conf/%v/forwarding", ipversion, ifname)
	err := os.WriteFile(path, []byte(val), 0644)
	if err != nil {
		return err
	}
	return nil
}

func SetIpv4forward(val string) error {
	err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte(val), 0644)
	if err != nil {
		return err
	}
	return nil
}

func SetForwarding(ifname string, val string) {
	_ = setForwarding(ifname, consts.IpVersionStr_4, val)
	_ = setForwarding(ifname, consts.IpVersionStr_6, val)
}

func checkSendRedirects(ifname string, ipversion consts.IpVersionStr) error {
	path := fmt.Sprintf("/proc/sys/net/ipv%v/conf/%v/send_redirects", ipversion, ifname)
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if bytes.Equal(bytes.TrimSpace(b), []byte("0")) {
		return nil
	}
	return fmt.Errorf("send_directs on %v is on: %v; see docs of dae for help", ifname, path)
}

func CheckSendRedirects(ifname string) error {
	if err := checkSendRedirects(ifname, consts.IpVersionStr_4); err != nil {
		return err
	}
	return nil
}

func setSendRedirects(ifname string, ipversion consts.IpVersionStr, val string) error {
	path := fmt.Sprintf("/proc/sys/net/ipv%v/conf/%v/send_redirects", ipversion, ifname)
	err := os.WriteFile(path, []byte(val), 0644)
	if err != nil {
		return err
	}
	return nil
}

func SetSendRedirects(ifname string, val string) {
	_ = setSendRedirects(ifname, consts.IpVersionStr_4, val)
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
