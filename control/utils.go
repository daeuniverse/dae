/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	stderrors "errors"
	"fmt"
	"net/netip"
	"os"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"golang.org/x/sys/unix"
)

// Route resolves a routing input with the userspace matcher. An empty domain
// means no domain is known for this invocation.
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
	outboundIndex, mark, must, err = c.routingMatcher.Match(
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
	)
	return
}

func bpfTuplesKeyFromAddrPorts(src, dst netip.AddrPort, l4proto uint8) bpfTuplesKey {
	src = common.ConvergeAddrPort(src)
	dst = common.ConvergeAddrPort(dst)

	var key bpfTuplesKey
	key.Sip.U6Addr8 = src.Addr().As16()
	key.Dip.U6Addr8 = dst.Addr().As16()
	key.Sport = common.Htons(src.Port())
	key.Dport = common.Htons(dst.Port())
	key.L4proto = l4proto
	return key
}

func (c *controlPlaneCore) RetrieveRoutingResult(src, dst netip.AddrPort, l4proto uint8) (result *bpfRoutingResult, err error) {
	tuples := bpfTuplesKeyFromAddrPorts(src, dst, l4proto)

	if c == nil || c.bpf.Load() == nil {
		return nil, ebpf.ErrKeyNotExist
	}

	routingResult, err := c.retrieveEmbeddedRoutingResult(&tuples, l4proto)
	if err == nil {
		return routingResult, nil
	}
	if !stderrors.Is(err, ebpf.ErrKeyNotExist) {
		return nil, err
	}

	return c.retrieveRoutingHandoffResult(&tuples)
}

func (c *controlPlaneCore) retrieveEmbeddedRoutingResult(tuples *bpfTuplesKey, l4proto uint8) (*bpfRoutingResult, error) {
	bpf := c.bpf.Load()
	var routingResult bpfRoutingResult

	switch l4proto {
	case unix.IPPROTO_TCP:
		if bpf.ConnStateMap == nil {
			return nil, ebpf.ErrKeyNotExist
		}
		var connState bpfConnState
		if err := bpf.ConnStateMap.Lookup(tuples, &connState); err != nil {
			if stderrors.Is(err, ebpf.ErrKeyNotExist) {
				return nil, ebpf.ErrKeyNotExist
			}
			return nil, fmt.Errorf("reading conn_state_map: %w", err)
		}
		if connState.Meta.Data.HasRouting == 0 {
			return nil, ebpf.ErrKeyNotExist
		}
		routingResult = routingResultFromConnState(
			connState.Meta.Data.Mark,
			connState.Meta.Data.Must,
			connState.Meta.Data.Outbound,
			connState.Mac,
			connState.Meta.Data.Dscp,
			connState.Pname,
			connState.Pid,
			connState.RoutingEpochSlot,
			connState.DatapathGeneration,
		)
	case unix.IPPROTO_UDP:
		if bpf.ConnStateMap == nil {
			return nil, ebpf.ErrKeyNotExist
		}
		var connState bpfConnState
		if err := bpf.ConnStateMap.Lookup(tuples, &connState); err != nil {
			if stderrors.Is(err, ebpf.ErrKeyNotExist) {
				return nil, ebpf.ErrKeyNotExist
			}
			return nil, fmt.Errorf("reading conn_state_map: %w", err)
		}
		if connState.Meta.Data.HasRouting == 0 {
			return nil, ebpf.ErrKeyNotExist
		}
		routingResult = routingResultFromConnState(
			connState.Meta.Data.Mark,
			connState.Meta.Data.Must,
			connState.Meta.Data.Outbound,
			connState.Mac,
			connState.Meta.Data.Dscp,
			connState.Pname,
			connState.Pid,
			connState.RoutingEpochSlot,
			connState.DatapathGeneration,
		)
	default:
		return nil, ebpf.ErrKeyNotExist
	}

	return &routingResult, nil
}

func routingResultFromConnState(mark uint32, must uint8, outbound uint8, mac [6]uint8, dscp uint8, pname [16]uint8, pid uint32, routingEpochSlot uint8, datapathGeneration uint16) bpfRoutingResult {
	var routingResult bpfRoutingResult
	routingResult.Mark = mark
	routingResult.Must = must
	routingResult.Outbound = outbound
	routingResult.Mac = mac
	routingResult.Dscp = dscp
	routingResult.Pname = pname
	routingResult.Pid = pid
	routingResult.RoutingEpochSlot = canonicalBpfRoutingEpochSlot(routingEpochSlot)
	routingResult.DatapathGeneration = datapathGeneration
	return routingResult
}

func (c *controlPlaneCore) retrieveRoutingHandoffResult(tuples *bpfTuplesKey) (*bpfRoutingResult, error) {
	if c == nil {
		return nil, ebpf.ErrKeyNotExist
	}
	bpf := c.bpf.Load()
	if bpf == nil || bpf.RoutingHandoffMap == nil {
		return nil, ebpf.ErrKeyNotExist
	}

	var entry bpfRoutingHandoffEntry
	if err := bpf.RoutingHandoffMap.Lookup(tuples, &entry); err != nil {
		if stderrors.Is(err, ebpf.ErrKeyNotExist) {
			return nil, ebpf.ErrKeyNotExist
		}
		return nil, fmt.Errorf("reading routing_handoff_map: %w", err)
	}

	now, err := monotonicNowNano()
	if err != nil {
		return nil, fmt.Errorf("reading monotonic clock for routing handoff: %w", err)
	}
	if routingHandoffExpired(now, entry.LastSeenNs) {
		if deleteErr := bpf.RoutingHandoffMap.Delete(tuples); deleteErr != nil &&
			!stderrors.Is(deleteErr, ebpf.ErrKeyNotExist) {
			return nil, fmt.Errorf("deleting expired routing_handoff_map entry: %w", deleteErr)
		}
		return nil, ebpf.ErrKeyNotExist
	}

	routingResult := routingResultFromConnState(
		entry.Result.Mark,
		entry.Result.Must,
		entry.Result.Outbound,
		entry.Result.Mac,
		entry.Result.Dscp,
		entry.Result.Pname,
		entry.Result.Pid,
		entry.Result.RoutingEpochSlot,
		entry.Result.DatapathGeneration,
	)
	return &routingResult, nil
}

func routingHandoffExpired(nowNano, lastSeenNs uint64) bool {
	if lastSeenNs == 0 {
		return true
	}
	timeoutNano := uint64(routingHandoffTimeout.Nanoseconds())
	if nowNano <= lastSeenNs {
		return false
	}
	return nowNano-lastSeenNs > timeoutNano
}

func monotonicNowNano() (uint64, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0, err
	}
	return uint64(ts.Nano()), nil
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
	return os.WriteFile(path, []byte(val), 0644)
}

func SetIpv4forward(val string) error {
	return os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte(val), 0644)
}

func SetForwarding(ifname string, val string) {
	_ = setForwarding(ifname, consts.IpVersionStr_4, val)
	_ = setForwarding(ifname, consts.IpVersionStr_6, val)
}

// procSysNet is the sysctl tree the kernel-parameter helpers read and write. It
// is a variable rather than a literal so tests can point it at a fixture tree:
// /proc/sys/net is only writable as root, so the write/check pair below would
// otherwise have to ship without an executable contract.
var procSysNet = "/proc/sys/net"

// sendRedirectsSysctls returns the sysctl nodes that together decide whether the
// kernel sends an ICMP redirect out of ifname.
//
// The decision is OR-ed, not AND-ed, and that is the whole point of listing more
// than one node. ip_forward() hands the packet to ip_rt_send_redirect() when
// IN_DEV_TX_REDIRECTS(in_dev) is set, and include/linux/inetdevice.h defines it
// as IN_DEV_ORCONF, i.e.
//
//	IPV4_DEVCONF_ALL_RO(net, SEND_REDIRECTS) || IN_DEV_CONF_GET(in_dev, SEND_REDIRECTS)
//
// Documentation/networking/ip-sysctl.rst states the same in words: redirects for
// an interface are enabled if at least one of conf/{all,interface}/send_redirects
// is TRUE. So the two nodes are alternatives and both have to be 0 to stop them;
// touching only conf/<ifname> is inert while conf/all keeps the kernel default of
// 1, which is a state where the kernel still offers downstream clients a direct
// path around dae.
//
// IPv4 only: there is no IPv6 send_redirects node to mirror this onto.
func sendRedirectsSysctls(ifname string, ipversion consts.IpVersionStr) []string {
	return []string{
		fmt.Sprintf("%v/ipv%v/conf/%v/send_redirects", procSysNet, ipversion, ifname),
		fmt.Sprintf("%v/ipv%v/conf/all/send_redirects", procSysNet, ipversion),
	}
}

// checkSendRedirects fails unless every node that can enable redirects for
// ifname is off. Reading only the per-interface node would inspect the value dae
// itself just wrote and never look at conf/all, so the check could not fail
// while redirects were still being sent.
func checkSendRedirects(ifname string, ipversion consts.IpVersionStr) error {
	for _, path := range sendRedirectsSysctls(ifname, ipversion) {
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !bytes.Equal(bytes.TrimSpace(b), []byte("0")) {
			return fmt.Errorf("send_redirects is on for %v: %v; see docs of dae for help", ifname, path)
		}
	}
	return nil
}

func CheckSendRedirects(ifname string) error {
	if err := checkSendRedirects(ifname, consts.IpVersionStr_4); err != nil {
		return err
	}
	return nil
}

// setSendRedirects writes val to every node that decides redirection for ifname,
// so that one call actually takes effect; see sendRedirectsSysctls for why the
// per-interface node alone is not enough. Every node is attempted even if an
// earlier write fails, and the first error is returned.
func setSendRedirects(ifname string, ipversion consts.IpVersionStr, val string) error {
	var firstErr error
	for _, path := range sendRedirectsSysctls(ifname, ipversion) {
		if err := os.WriteFile(path, []byte(val), 0644); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func SetSendRedirects(ifname string, val string) {
	_ = setSendRedirects(ifname, consts.IpVersionStr_4, val)
}

func ProcessName2String(pname []uint8) string {
	return string(bytes.TrimRight(pname, string([]byte{0})))
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
