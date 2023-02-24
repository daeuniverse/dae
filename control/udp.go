/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2023, v2rayA Organization <team@v2raya.org>
 */

package control

import (
	"encoding/gob"
	"errors"
	"fmt"
	"github.com/mzz2017/softwind/pkg/zeroalloc/buffer"
	"github.com/mzz2017/softwind/pool"
	"github.com/sirupsen/logrus"
	"github.com/v2rayA/dae/common"
	"github.com/v2rayA/dae/common/consts"
	"github.com/v2rayA/dae/component/outbound/dialer"
	"github.com/v2rayA/dae/component/sniffing"
	"golang.org/x/net/dns/dnsmessage"
	"net"
	"net/netip"
	"syscall"
	"time"
	"unsafe"
)

const (
	DefaultNatTimeout = 3 * time.Minute
	DnsNatTimeout     = 17 * time.Second // RFC 5452
	MaxRetry          = 2
)

var (
	UnspecifiedAddr4 = netip.AddrFrom4([4]byte{})
	UnspecifiedAddr6 = netip.AddrFrom16([16]byte{})
)

func ChooseNatTimeout(data []byte, sniffDns bool) (dmsg *dnsmessage.Message, timeout time.Duration) {
	var dnsmsg dnsmessage.Message
	if err := dnsmsg.Unpack(data); err == nil {
		//log.Printf("DEBUG: lookup %v", dnsmsg.Questions[0].Name)
		return &dnsmsg, DnsNatTimeout
	}
	return nil, DefaultNatTimeout
}

func ParseAddrHdr(data []byte) (hdr *bpfDstRoutingResult, dataOffset int, err error) {
	dataOffset = int(unsafe.Sizeof(bpfDstRoutingResult{}))
	if len(data) < dataOffset {
		return nil, 0, fmt.Errorf("data is too short to parse AddrHdr")
	}
	_hdr := *(*bpfDstRoutingResult)(unsafe.Pointer(&data[0]))
	_hdr.Port = common.Ntohs(_hdr.Port)
	return &_hdr, dataOffset, nil
}

func sendPktWithHdrWithFlag(data []byte, mark uint32, from netip.AddrPort, lConn *net.UDPConn, to netip.AddrPort, lanWanFlag consts.LanWanFlag) error {
	hdr := bpfDstRoutingResult{
		Ip:   common.Ipv6ByteSliceToUint32Array(from.Addr().AsSlice()),
		Port: common.Htons(from.Port()),
		RoutingResult: bpfRoutingResult{
			Outbound: uint8(lanWanFlag), // Pass some message to the kernel program.
		},
	}
	buf := pool.Get(int(unsafe.Sizeof(hdr)) + len(data))
	defer pool.Put(buf)
	b := buffer.NewBufferFrom(buf)
	defer b.Put()
	if err := gob.NewEncoder(b).Encode(&hdr); err != nil {
		return err
	}
	copy(buf[int(unsafe.Sizeof(hdr)):], data)
	//log.Println("from", from, "to", to)
	_, err := lConn.WriteToUDPAddrPort(buf, to)
	return err
}

// sendPkt uses bind first, and fallback to send hdr if addr is in use.
func sendPkt(data []byte, from netip.AddrPort, realTo, to netip.AddrPort, lConn *net.UDPConn, lanWanFlag consts.LanWanFlag) (err error) {
	d := net.Dialer{Control: func(network, address string, c syscall.RawConn) error {
		return dialer.BindControl(c, from)
	}}
	var conn net.Conn
	conn, err = d.Dial("udp", realTo.String())
	if err != nil {
		if errors.Is(err, syscall.EADDRINUSE) {
			// Port collision, use traditional method.
			return sendPktWithHdrWithFlag(data, 0, from, lConn, to, lanWanFlag)
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
		// Sniff Quic
		sniffer := sniffing.NewPacketSniffer(data)
		domain, err = sniffer.SniffQuic()
		if err != nil && !sniffing.IsSniffingError(err) {
			sniffer.Close()
			return err
		}
		sniffer.Close()
	}

	// Get outbound.
	outboundIndex := consts.OutboundIndex(routingResult.Outbound)
	switch outboundIndex {
	case consts.OutboundDirect:
	case consts.OutboundMustDirect:
		outboundIndex = consts.OutboundDirect
		isDns = false // Regard as plain traffic.
	case consts.OutboundControlPlaneRouting:
		if isDns {
			// Routing of DNS packets are managed by DNS controller.
			break
		}

		if outboundIndex, routingResult.Mark, err = c.Route(realSrc, realDst, domain, consts.L4ProtoType_TCP, routingResult); err != nil {
			return err
		}
		routingResult.Outbound = uint8(outboundIndex)
		if c.log.IsLevelEnabled(logrus.TraceLevel) {
			c.log.Tracef("outbound: %v => %v",
				consts.OutboundControlPlaneRouting.String(),
				outboundIndex.String(),
			)
		}
	default:
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

	if int(outboundIndex) >= len(c.outbounds) {
		return fmt.Errorf("outbound %v out of range [0, %v]", outboundIndex, len(c.outbounds)-1)
	}
	outbound := c.outbounds[outboundIndex]

	// Select dialer from outbound (dialer group).
	networkType := &dialer.NetworkType{
		L4Proto:   consts.L4ProtoStr_UDP,
		IpVersion: consts.IpVersionFromAddr(realDst.Addr()),
		IsDns:     true, // UDP relies on DNS check result.
	}
	dialerForNew, _, err := outbound.Select(networkType)
	if err != nil {
		return fmt.Errorf("failed to select dialer from group %v (%v, dns?:%v,from: %v): %w", outbound.Name, networkType.StringWithoutDns(), isDns, realSrc.String(), err)
	}

	// Dial and send.
	// TODO: Rewritten domain should not use full-cone (such as VMess Packet Addr).
	// 		Maybe we should set up a mapping for UDP: Dialer + Target Domain => Remote Resolved IP.
	//		However, games may not use QUIC for communication, thus we cannot use domain to dial, which is fine.
	dialTarget := c.ChooseDialTarget(outboundIndex, realDst, domain)

	// Get udp endpoint.
	var ue *UdpEndpoint
	retry := 0
getNew:
	if retry > MaxRetry {
		return fmt.Errorf("touch max retry limit")
	}
	ue, isNew, err := DefaultUdpEndpointPool.GetOrCreate(realSrc, &UdpEndpointOptions{
		// Handler handles response packets and send it to the client.
		Handler: func(data []byte, from netip.AddrPort) (err error) {
			// Do not return conn-unrelated err in this func.
			return sendPkt(data, from, realSrc, src, lConn, lanWanFlag)
		},
		NatTimeout: natTimeout,
		Dialer:     dialerForNew,
		Network:    MagicNetwork("udp", routingResult.Mark),
		Target:     dialTarget,
	})
	if err != nil {
		return fmt.Errorf("failed to GetOrCreate (policy: %v): %w", outbound.GetSelectionPolicy(), err)
	}

	// If the udp endpoint has been not alive, remove it from pool and get a new one.
	if !isNew && outbound.GetSelectionPolicy() != consts.DialerSelectionPolicy_Fixed && !ue.Dialer.MustGetAlive(networkType) {

		if c.log.IsLevelEnabled(logrus.DebugLevel) {
			c.log.WithFields(logrus.Fields{
				"src":     RefineSourceToShow(realSrc, realDst.Addr(), lanWanFlag),
				"network": networkType.String(),
				"dialer":  ue.Dialer.Name(),
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
	if isNew {
		if c.log.IsLevelEnabled(logrus.InfoLevel) {
			fields := logrus.Fields{
				"network":  networkType.StringWithoutDns(),
				"outbound": outbound.Name,
				"policy":   outbound.GetSelectionPolicy(),
				"dialer":   ue.Dialer.Name(),
				"domain":   domain,
				"pid":      routingResult.Pid,
				"pname":    ProcessName2String(routingResult.Pname[:]),
				"mac":      Mac2String(routingResult.Mac[:]),
			}
			c.log.WithFields(fields).Infof("%v <-> %v", RefineSourceToShow(realSrc, realDst.Addr(), lanWanFlag), RefineAddrPortToShow(realDst))
		}
	}

	return nil
}
