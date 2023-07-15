/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2023, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"time"
	"unsafe"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	ob "github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/component/sniffing"
	internal "github.com/daeuniverse/dae/pkg/ebpf_internal"
	dnsmessage "github.com/miekg/dns"
	"github.com/mzz2017/softwind/pkg/zeroalloc/buffer"
	"github.com/sirupsen/logrus"
)

const (
	DefaultNatTimeout = 3 * time.Minute
	DnsNatTimeout     = 17 * time.Second // RFC 5452
	MaxRetry          = 2
)

type DialOption struct {
	Target   string
	Dialer   *dialer.Dialer
	Outbound *ob.DialerGroup
	Network  string
}

func ChooseNatTimeout(data []byte, sniffDns bool) (dmsg *dnsmessage.Msg, timeout time.Duration) {
	if sniffDns {
		var dnsmsg dnsmessage.Msg
		if err := dnsmsg.Unpack(data); err == nil {
			//log.Printf("DEBUG: lookup %v", dnsmsg.Question[0].Name)
			return &dnsmsg, DnsNatTimeout
		}
	}
	return nil, DefaultNatTimeout
}

func ParseAddrHdr(data []byte) (hdr *bpfDstRoutingResult, dataOffset int, err error) {
	dataOffset = int(unsafe.Sizeof(bpfDstRoutingResult{}))
	if len(data) < dataOffset {
		return nil, 0, fmt.Errorf("data is too short to parse AddrHdr")
	}
	_hdr := *(*bpfDstRoutingResult)(unsafe.Pointer(&data[0]))
	if _hdr.Recognize != consts.Recognize {
		return nil, 0, fmt.Errorf("bad recognize")
	}
	_hdr.Port = common.Ntohs(_hdr.Port)
	return &_hdr, dataOffset, nil
}

func sendPktWithHdrWithFlag(data []byte, realFrom netip.AddrPort, lConn *net.UDPConn, to netip.AddrPort, lanWanFlag consts.LanWanFlag) error {
	realFrom16 := realFrom.Addr().As16()
	hdr := bpfDstRoutingResult{
		Ip:   common.Ipv6ByteSliceToUint32Array(realFrom16[:]),
		Port: common.Htons(realFrom.Port()),
		RoutingResult: bpfRoutingResult{
			Outbound: uint8(lanWanFlag), // Pass some message to the kernel program.
		},
	}
	// Do not put this 'buf' because it has been taken by buffer.
	b := buffer.NewBuffer(int(unsafe.Sizeof(hdr)) + len(data))
	defer b.Put()
	// Use internal.NativeEndian due to already big endian.
	if err := binary.Write(b, internal.NativeEndian, hdr); err != nil {
		return err
	}
	b.Write(data)
	//logrus.Debugln("sendPktWithHdrWithFlag: from", realFrom, "to", to)
	if ipversion := consts.IpVersionFromAddr(to.Addr()); consts.IpVersionFromAddr(lConn.LocalAddr().(*net.UDPAddr).AddrPort().Addr()) != ipversion {
		// ip versions unmatched.
		if ipversion == consts.IpVersionStr_4 {
			// 4 to 6
			to = netip.AddrPortFrom(netip.AddrFrom16(to.Addr().As16()), to.Port())
		} else {
			// Shouldn't happen.
			return fmt.Errorf("unmatched ipversions")
		}
	}
	_, err := lConn.WriteToUDPAddrPort(b.Bytes(), to)
	return err
}

// sendPkt uses bind first, and fallback to send hdr if addr is in use.
func sendPkt(data []byte, from netip.AddrPort, realTo, to netip.AddrPort, lConn *net.UDPConn, lanWanFlag consts.LanWanFlag) (err error) {

	if lanWanFlag == consts.LanWanFlag_IsWan {
		return sendPktWithHdrWithFlag(data, from, lConn, to, lanWanFlag)
	}

	d := net.Dialer{Control: func(network, address string, c syscall.RawConn) error {
		return dialer.BindControl(c, from)
	}}
	var conn net.Conn
	conn, err = d.Dial("udp", realTo.String())
	if err != nil {
		if errors.Is(err, syscall.EADDRINUSE) {
			// Port collision, use traditional method.
			return sendPktWithHdrWithFlag(data, from, lConn, to, lanWanFlag)
		}
		return err
	}
	defer conn.Close()
	uConn := conn.(*net.UDPConn)
	_, err = uConn.Write(data)
	return err
}

func (c *ControlPlane) handlePkt(lConn *net.UDPConn, data []byte, src, pktDst, realDst netip.AddrPort, routingResult *bpfRoutingResult) (err error) {
	var lanWanFlag consts.LanWanFlag
	var realSrc netip.AddrPort
	var domain string
	useAssign := pktDst == realDst // Use sk_assign instead of modify target ip/port.
	if useAssign {
		lanWanFlag = consts.LanWanFlag_IsLan
		realSrc = src
	} else {
		lanWanFlag = consts.LanWanFlag_IsWan
		// From localhost, so dst IP is src IP.
		realSrc = netip.AddrPortFrom(pktDst.Addr(), src.Port())
	}

	// To keep consistency with kernel program, we only sniff DNS request sent to 53.
	dnsMessage, natTimeout := ChooseNatTimeout(data, realDst.Port() == 53)
	// We should cache DNS records and set record TTL to 0, in order to monitor the dns req and resp in real time.
	isDns := dnsMessage != nil
	if !isDns {
		// Sniff Quic, ...
		sniffer := sniffing.NewPacketSniffer(data)
		defer sniffer.Close()
		domain, err = sniffer.SniffUdp()
		if err != nil && !sniffing.IsSniffingError(err) {
			return err
		}
	}
	if routingResult.Must > 0 {
		isDns = false // Regard as plain traffic.
	}
	if routingResult.Mark == 0 {
		routingResult.Mark = c.soMarkFromDae
	}
	if isDns {
		return c.dnsController.Handle_(dnsMessage, &udpRequest{
			lanWanFlag:    lanWanFlag,
			realSrc:       realSrc,
			realDst:       realDst,
			src:           src,
			lConn:         lConn,
			routingResult: routingResult,
		})
	}

	// Dial and send.
	// TODO: Rewritten domain should not use full-cone (such as VMess Packet Addr).
	// 		Maybe we should set up a mapping for UDP: Dialer + Target Domain => Remote Resolved IP.
	//		However, games may not use QUIC for communication, thus we cannot use domain to dial, which is fine.

	// Get udp endpoint.
	var ue *UdpEndpoint
	retry := 0
	networkType := &dialer.NetworkType{
		L4Proto:   consts.L4ProtoStr_UDP,
		IpVersion: consts.IpVersionFromAddr(realDst.Addr()),
		IsDns:     true, // UDP relies on DNS check result.
	}
	// Get outbound.
	outboundIndex := consts.OutboundIndex(routingResult.Outbound)
	dialTarget, shouldReroute, dialIp := c.ChooseDialTarget(outboundIndex, realDst, domain)
getNew:
	if retry > MaxRetry {
		c.log.WithFields(logrus.Fields{
			"src":     RefineSourceToShow(realSrc, realDst.Addr(), lanWanFlag),
			"network": networkType.String(),
			"dialer":  ue.Dialer.Property().Name,
			"retry":   retry,
		}).Warnln("Touch max retry limit.")
		return fmt.Errorf("touch max retry limit")
	}
	ue, isNew, err := DefaultUdpEndpointPool.GetOrCreate(realSrc, &UdpEndpointOptions{
		// Handler handles response packets and send it to the client.
		Handler: func(data []byte, from netip.AddrPort) (err error) {
			// Do not return conn-unrelated err in this func.
			return sendPkt(data, from, realSrc, src, lConn, lanWanFlag)
		},
		NatTimeout: natTimeout,
		GetDialOption: func() (option *DialOption, err error) {
			if shouldReroute {
				outboundIndex = consts.OutboundControlPlaneRouting
			}

			switch outboundIndex {
			case consts.OutboundDirect:
			case consts.OutboundControlPlaneRouting:
				if isDns {
					// Routing of DNS packets are managed by DNS controller.
					break
				}

				if outboundIndex, routingResult.Mark, _, err = c.Route(realSrc, realDst, domain, consts.L4ProtoType_TCP, routingResult); err != nil {
					return nil, err
				}
				routingResult.Outbound = uint8(outboundIndex)
				if c.log.IsLevelEnabled(logrus.TraceLevel) {
					c.log.Tracef("outbound: %v => %v",
						consts.OutboundControlPlaneRouting.String(),
						outboundIndex.String(),
					)
				}
				// Reset dialTarget.
				dialTarget, _, dialIp = c.ChooseDialTarget(outboundIndex, realDst, domain)
			default:
			}

			if int(outboundIndex) >= len(c.outbounds) {
				if len(c.outbounds) == int(consts.OutboundUserDefinedMin) {
					return nil, fmt.Errorf("traffic was dropped due to no-load configuration")
				}
				return nil, fmt.Errorf("outbound %v out of range [0, %v]", outboundIndex, len(c.outbounds)-1)
			}
			outbound := c.outbounds[outboundIndex]

			// Select dialer from outbound (dialer group).
			strictIpVersion := dialIp
			dialerForNew, _, err := outbound.Select(networkType, strictIpVersion)
			if err != nil {
				return nil, fmt.Errorf("failed to select dialer from group %v (%v, dns?:%v,from: %v): %w", outbound.Name, networkType.StringWithoutDns(), isDns, realSrc.String(), err)
			}
			return &DialOption{
				Target:   dialTarget,
				Dialer:   dialerForNew,
				Outbound: outbound,
				Network:  common.MagicNetwork("udp", routingResult.Mark),
			}, nil
		},
	})
	if err != nil {
		return fmt.Errorf("failed to GetOrCreate: %w", err)
	}

	// If the udp endpoint has been not alive, remove it from pool and get a new one.
	if !isNew && ue.Outbound.GetSelectionPolicy() != consts.DialerSelectionPolicy_Fixed && !ue.Dialer.MustGetAlive(networkType) {

		if c.log.IsLevelEnabled(logrus.DebugLevel) {
			c.log.WithFields(logrus.Fields{
				"src":     RefineSourceToShow(realSrc, realDst.Addr(), lanWanFlag),
				"network": networkType.String(),
				"dialer":  ue.Dialer.Property().Name,
				"retry":   retry,
			}).Debugln("Old udp endpoint was not alive and removed.")
		}
		_ = DefaultUdpEndpointPool.Remove(realSrc, ue)
		retry++
		goto getNew
	}

	_, err = ue.WriteTo(data, dialTarget)
	if err != nil {
		if c.log.IsLevelEnabled(logrus.DebugLevel) {
			c.log.WithFields(logrus.Fields{
				"to":      realDst.String(),
				"domain":  domain,
				"pid":     routingResult.Pid,
				"pname":   ProcessName2String(routingResult.Pname[:]),
				"mac":     Mac2String(routingResult.Mac[:]),
				"from":    realSrc.String(),
				"network": networkType.StringWithoutDns(),
				"err":     err.Error(),
				"retry":   retry,
			}).Debugln("Failed to write UDP packet request. Try to remove old UDP endpoint and retry.")
		}
		_ = DefaultUdpEndpointPool.Remove(realSrc, ue)
		retry++
		goto getNew
	}

	// Print log.
	// Only print routing for new connection to avoid the log exploded (Quic and BT).
	if isNew && c.log.IsLevelEnabled(logrus.InfoLevel) || c.log.IsLevelEnabled(logrus.DebugLevel) {
		fields := logrus.Fields{
			"network":  networkType.StringWithoutDns(),
			"outbound": ue.Outbound.Name,
			"policy":   ue.Outbound.GetSelectionPolicy(),
			"dialer":   ue.Dialer.Property().Name,
			"domain":   domain,
			"ip":       RefineAddrPortToShow(realDst),
			"pid":      routingResult.Pid,
			"pname":    ProcessName2String(routingResult.Pname[:]),
			"mac":      Mac2String(routingResult.Mac[:]),
		}
		c.log.WithFields(fields).Infof("%v <-> %v", RefineSourceToShow(realSrc, realDst.Addr(), lanWanFlag), dialTarget)
	}

	return nil
}
