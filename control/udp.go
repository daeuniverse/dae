/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2023, v2rayA Organization <team@v2raya.org>
 */

package control

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/mzz2017/softwind/pool"
	"github.com/sirupsen/logrus"
	"github.com/v2rayA/dae/common"
	"github.com/v2rayA/dae/common/consts"
	"github.com/v2rayA/dae/component/outbound/dialer"
	"github.com/v2rayA/dae/component/sniffing"
	"golang.org/x/net/dns/dnsmessage"
	"io"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"time"
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

type AddrHdr struct {
	Dest     netip.AddrPort
	Outbound uint8
	Mark     uint32
}

func ParseAddrHdr(data []byte) (hdr *AddrHdr, dataOffset int, err error) {
	ipSize := 16
	dataOffset = consts.AddrHdrSize
	if len(data) < dataOffset {
		return nil, 0, fmt.Errorf("data is too short to parse AddrHdr")
	}
	destAddr, _ := netip.AddrFromSlice(data[:ipSize])
	port := binary.BigEndian.Uint16(data[ipSize:])
	outbound := data[ipSize+2]
	mark := binary.BigEndian.Uint32(data[ipSize+4:])
	return &AddrHdr{
		Dest:     netip.AddrPortFrom(destAddr, port),
		Outbound: outbound,
		Mark:     mark,
	}, dataOffset, nil
}

func (hdr *AddrHdr) ToBytesFromPool() []byte {
	ipSize := 16
	buf := pool.GetZero(consts.AddrHdrSize) // byte align to a multiple of 4
	ip := hdr.Dest.Addr().As16()
	copy(buf, ip[:])
	binary.BigEndian.PutUint16(buf[ipSize:], hdr.Dest.Port())
	buf[ipSize+2] = hdr.Outbound
	binary.BigEndian.PutUint32(buf[ipSize+4:], hdr.Mark)
	return buf
}

func sendPktWithHdrWithFlag(data []byte, mark uint32, from netip.AddrPort, lConn *net.UDPConn, to netip.AddrPort, lanWanFlag consts.LanWanFlag) error {
	hdr := AddrHdr{
		Dest:     from,
		Mark:     mark,
		Outbound: uint8(lanWanFlag), // Pass some message to the kernel program.
	}
	bHdr := hdr.ToBytesFromPool()
	defer pool.Put(bHdr)
	buf := pool.Get(len(bHdr) + len(data))
	defer pool.Put(buf)
	copy(buf, bHdr)
	copy(buf[len(bHdr):], data)
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

func (c *ControlPlane) WriteToUDP(lanWanFlag consts.LanWanFlag, lConn *net.UDPConn, realTo, to netip.AddrPort, isDNS bool, dummyFrom *netip.AddrPort, validateRushAnsFunc func(from netip.AddrPort) bool) UdpHandler {
	return func(data []byte, from netip.AddrPort) (err error) {
		// Do not return conn-unrelated err in this func.

		if isDNS {
			validateRushAns := validateRushAnsFunc(from)
			data, err = c.DnsRespHandler(data, validateRushAns)
			if err != nil {
				if validateRushAns && errors.Is(err, SuspectedRushAnswerError) {
					// Reject DNS rush-answer.
					c.log.WithFields(logrus.Fields{
						"from": from,
					}).Tracef("DNS rush-answer rejected")
					return err
				}
				if c.log.IsLevelEnabled(logrus.DebugLevel) {
					c.log.Debugf("DnsRespHandler: %v", err)
				}
				if data == nil {
					return nil
				}
			}
		}
		if dummyFrom != nil {
			from = *dummyFrom
		}
		return sendPkt(data, from, realTo, to, lConn, lanWanFlag)
	}
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

	mustDirect := false
	outboundIndex := consts.OutboundIndex(routingResult.Outbound)
	switch outboundIndex {
	case consts.OutboundDirect:
	case consts.OutboundMustDirect:
		mustDirect = true
		fallthrough
	case consts.OutboundControlPlaneDirect:
		if c.log.IsLevelEnabled(logrus.TraceLevel) {
			c.log.Tracef("outbound: %v => %v",
				outboundIndex.String(),
				consts.OutboundDirect.String(),
			)
		}
		outboundIndex = consts.OutboundDirect
	default:
	}
	if int(outboundIndex) >= len(c.outbounds) {
		return fmt.Errorf("outbound %v out of range [0, %v]", outboundIndex, len(c.outbounds)-1)
	}
	outbound := c.outbounds[outboundIndex]
	// To keep consistency with kernel program, we only sniff DNS request sent to 53.
	dnsMessage, natTimeout := ChooseNatTimeout(data, realDst.Port() == 53)
	// We should cache DNS records and set record TTL to 0, in order to monitor the dns req and resp in real time.
	isDns := dnsMessage != nil
	var dummyFrom *netip.AddrPort
	destToSend := realDst
	if isDns {
		if resp := c.LookupDnsRespCache_(dnsMessage); resp != nil {
			// Send cache to client directly.
			if err = sendPkt(resp, destToSend, realSrc, src, lConn, lanWanFlag); err != nil {
				return fmt.Errorf("failed to write cached DNS resp: %w", err)
			}
			if c.log.IsLevelEnabled(logrus.DebugLevel) && len(dnsMessage.Questions) > 0 {
				q := dnsMessage.Questions[0]
				c.log.Tracef("UDP(DNS) %v <-[%v]-> Cache: %v %v",
					RefineSourceToShow(realSrc, realDst.Addr(), lanWanFlag), outbound.Name, strings.ToLower(q.Name.String()), q.Type,
				)
			}
			return nil
		}

		// Flip dns question to reduce dns pollution.
		FlipDnsQuestionCase(dnsMessage)
		// Make sure there is additional record OPT in the request to filter DNS rush-answer in the response process.
		// Because rush-answer has no resp OPT. We can distinguish them from multiple responses.
		// Note that additional record OPT may not be supported by home router either.
		_, _ = EnsureAdditionalOpt(dnsMessage, true)

		// Re-pack DNS packet.
		if data, err = dnsMessage.Pack(); err != nil {
			return fmt.Errorf("pack flipped dns packet: %w", err)
		}
	} else {
		// Sniff Quic
		sniffer := sniffing.NewPacketSniffer(data)
		domain, err = sniffer.SniffQuic()
		if err != nil && !sniffing.IsSniffingError(err) {
			sniffer.Close()
			return err
		}
		sniffer.Close()
	}

	l4proto := consts.L4ProtoStr_UDP
	ipversion := consts.IpVersionFromAddr(realDst.Addr())
	var dialerForNew *dialer.Dialer

	// For DNS request, modify realDst to dns upstream.
	// NOTICE: We might modify l4proto and ipversion.
	dnsUpstream, err := c.dnsUpstream.GetUpstream()
	if err != nil {
		return err
	}
	if isDns && dnsUpstream != nil && !mustDirect {
		// Modify dns target to upstream.
		// NOTICE: Routing was calculated in advance by the eBPF program.

		/// Choose the best l4proto+ipversion dialer, and change taregt DNS to the best ipversion DNS upstream for DNS request.
		// Get available ipversions and l4protos for DNS upstream.
		ipversions, l4protos := dnsUpstream.SupportedNetworks()
		var (
			bestDialer  *dialer.Dialer
			bestLatency time.Duration
			bestTarget  netip.AddrPort
		)
		if c.log.IsLevelEnabled(logrus.TraceLevel) {
			c.log.WithFields(logrus.Fields{
				"ipversions": ipversions,
				"l4protos":   l4protos,
				"src":        realSrc.String(),
			}).Traceln("Choose DNS path")
		}
		// Get the min latency path.
		networkType := dialer.NetworkType{
			IsDns: isDns,
		}
		for _, ver := range ipversions {
			for _, proto := range l4protos {
				networkType.L4Proto = proto
				networkType.IpVersion = ver
				d, latency, err := outbound.Select(&networkType)
				if err != nil {
					continue
				}
				if c.log.IsLevelEnabled(logrus.TraceLevel) {
					c.log.WithFields(logrus.Fields{
						"name":     d.Name(),
						"latency":  latency,
						"network":  networkType.String(),
						"outbound": outbound.Name,
					}).Traceln("Choice")
				}
				if bestDialer == nil || latency < bestLatency {
					bestDialer = d
					bestLatency = latency
					l4proto = proto
					ipversion = ver
				}
			}
		}
		switch ipversion {
		case consts.IpVersionStr_4:
			bestTarget = netip.AddrPortFrom(dnsUpstream.Ip4, dnsUpstream.Port)
		case consts.IpVersionStr_6:
			bestTarget = netip.AddrPortFrom(dnsUpstream.Ip6, dnsUpstream.Port)
		}
		dialerForNew = bestDialer
		dummyFrom = &realDst
		destToSend = bestTarget
		if c.log.IsLevelEnabled(logrus.TraceLevel) {
			c.log.WithFields(logrus.Fields{
				"Original": RefineAddrPortToShow(realDst),
				"New":      destToSend,
				"Network":  string(l4proto) + string(ipversion),
			}).Traceln("Modify DNS target")
		}
	}
	networkType := &dialer.NetworkType{
		L4Proto:   l4proto,
		IpVersion: ipversion,
		IsDns:     true,
	}
	if dialerForNew == nil {
		dialerForNew, _, err = outbound.Select(networkType)
		if err != nil {
			return fmt.Errorf("failed to select dialer from group %v (%v, dns?:%v,from: %v): %w", outbound.Name, networkType.StringWithoutDns(), isDns, realSrc.String(), err)
		}
	}

	var isNew bool
	var realDialer *dialer.Dialer

	udpHandler := c.WriteToUDP(lanWanFlag, lConn, realSrc, src, isDns, dummyFrom, func(from netip.AddrPort) bool {
		// We only validate rush-ans when outbound is direct and pkt does not send to a home device.
		// Because additional record OPT may not be supported by home router.
		// So se should trust home devices even if they make rush-answer (or looks like).
		return outboundIndex == consts.OutboundDirect && !common.ConvergeIp(from.Addr()).IsPrivate()
	})
	// Dial and send.
	// TODO: Rewritten domain should not use full-cone (such as VMess Packet Addr).
	// 		Maybe we should set up a mapping for UDP: Dialer + Target Domain => Remote Resolved IP.
	destToSend = netip.AddrPortFrom(common.ConvergeIp(destToSend.Addr()), destToSend.Port())
	tgtToSend := c.ChooseDialTarget(outboundIndex, destToSend, domain)
	switch l4proto {
	case consts.L4ProtoStr_UDP:
		// Get udp endpoint.
		var ue *UdpEndpoint
		retry := 0
	getNew:
		if retry > MaxRetry {
			return fmt.Errorf("touch max retry limit")
		}

		ue, isNew, err = DefaultUdpEndpointPool.GetOrCreate(realSrc, &UdpEndpointOptions{
			Handler:    udpHandler,
			NatTimeout: natTimeout,
			Dialer:     dialerForNew,
			Network:    GetNetwork("udp", routingResult.Mark),
			Target:     tgtToSend,
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
		// This is real dialer.
		realDialer = ue.Dialer

		_, err = ue.WriteTo(data, tgtToSend)
		if err != nil {
			if c.log.IsLevelEnabled(logrus.DebugLevel) {
				c.log.WithFields(logrus.Fields{
					"to":      destToSend.String(),
					"domain":  domain,
					"from":    realSrc.String(),
					"network": networkType.String(),
					"err":     err.Error(),
					"retry":   retry,
				}).Debugln("Failed to write UDP packet request. Try to remove old UDP endpoint and retry.")
			}
			_ = DefaultUdpEndpointPool.Remove(realSrc, ue)
			retry++
			goto getNew
		}
	case consts.L4ProtoStr_TCP:
		// MUST be DNS.
		if !isDns {
			return fmt.Errorf("UDP to TCP only support DNS request")
		}
		isNew = true
		realDialer = dialerForNew

		// We can block because we are in a coroutine.

		conn, err := dialerForNew.Dial(GetNetwork("tcp", routingResult.Mark), tgtToSend)
		if err != nil {
			return fmt.Errorf("failed to dial proxy to tcp: %w", err)
		}
		defer conn.Close()

		_ = conn.SetDeadline(time.Now().Add(natTimeout))
		// We should write two byte length in the front of TCP DNS request.
		bReq := pool.Get(2 + len(data))
		defer pool.Put(bReq)
		binary.BigEndian.PutUint16(bReq, uint16(len(data)))
		copy(bReq[2:], data)
		_, err = conn.Write(bReq)
		if err != nil {
			return fmt.Errorf("failed to write DNS req: %w", err)
		}

		// Read two byte length.
		if _, err = io.ReadFull(conn, bReq[:2]); err != nil {
			return fmt.Errorf("failed to read DNS resp payload length: %w", err)
		}
		respLen := int(binary.BigEndian.Uint16(bReq))
		// Try to reuse the buf.
		var buf []byte
		if len(bReq) < respLen {
			buf = pool.Get(respLen)
			defer pool.Put(buf)
		} else {
			buf = bReq
		}
		var n int
		if n, err = io.ReadFull(conn, buf[:respLen]); err != nil {
			return fmt.Errorf("failed to read DNS resp payload: %w", err)
		}
		if err = udpHandler(buf[:n], destToSend); err != nil {
			return fmt.Errorf("failed to write DNS resp to client: %w", err)
		}
	}

	// Print log.
	if isNew || isDns {
		// Only print routing for new connection to avoid the log exploded (Quic and BT).
		if isDns && c.log.IsLevelEnabled(logrus.DebugLevel) && len(dnsMessage.Questions) > 0 {
			q := dnsMessage.Questions[0]
			c.log.WithFields(logrus.Fields{
				"network":  string(l4proto) + string(ipversion) + "(DNS)",
				"outbound": outbound.Name,
				"policy":   outbound.GetSelectionPolicy(),
				"dialer":   realDialer.Name(),
				"qname":    strings.ToLower(q.Name.String()),
				"qtype":    q.Type,
			}).Infof("%v <-> %v",
				RefineSourceToShow(realSrc, realDst.Addr(), lanWanFlag), RefineAddrPortToShow(destToSend),
			)
		} else if c.log.IsLevelEnabled(logrus.InfoLevel) {
			c.log.WithFields(logrus.Fields{
				"network":  string(l4proto) + string(ipversion),
				"outbound": outbound.Name,
				"policy":   outbound.GetSelectionPolicy(),
				"dialer":   realDialer.Name(),
				"domain":   domain,
			}).Infof("%v <-> %v",
				RefineSourceToShow(realSrc, realDst.Addr(), lanWanFlag), RefineAddrPortToShow(destToSend),
			)
		}
	}

	return nil
}
