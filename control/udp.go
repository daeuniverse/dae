/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2022, v2rayA Organization <team@v2raya.org>
 */

package control

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/mzz2017/softwind/pool"
	"github.com/sirupsen/logrus"
	"github.com/v2rayA/dae/common/consts"
	"github.com/v2rayA/dae/component/outbound/dialer"
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
)

func ChooseNatTimeout(data []byte) (dmsg *dnsmessage.Message, timeout time.Duration) {
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
	return &AddrHdr{
		Dest:     netip.AddrPortFrom(destAddr, port),
		Outbound: outbound,
	}, dataOffset, nil
}

func (hdr *AddrHdr) ToBytesFromPool() []byte {
	ipSize := 16
	buf := pool.GetZero(consts.AddrHdrSize) // byte align to a multiple of 4
	ip := hdr.Dest.Addr().As16()
	copy(buf, ip[:])
	binary.BigEndian.PutUint16(buf[ipSize:], hdr.Dest.Port())
	buf[ipSize+2] = hdr.Outbound
	return buf
}

func sendPktWithHdr(data []byte, from netip.AddrPort, lConn *net.UDPConn, to netip.AddrPort) error {
	hdr := AddrHdr{
		Dest:     from,
		Outbound: 0, // Do not care.
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

func sendPktBind(data []byte, from netip.AddrPort, to netip.AddrPort) error {
	d := net.Dialer{Control: func(network, address string, c syscall.RawConn) error {
		return dialer.BindControl(c, from)
	}}
	conn, err := d.Dial("udp", to.String())
	if err != nil {
		return err
	}
	uConn := conn.(*net.UDPConn)
	_, err = uConn.Write(data)
	return err
}

func (c *ControlPlane) WriteToUDP(to netip.AddrPort, isDNS bool, dummyFrom *netip.AddrPort, validateRushAnsFunc func(from netip.AddrPort) bool) UdpHandler {
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
				c.log.Debugf("DnsRespHandler: %v", err)
				if data == nil {
					return nil
				}
			}
		}
		if dummyFrom != nil {
			from = *dummyFrom
		}

		return sendPktBind(data, from, to)
	}
}

func (c *ControlPlane) handlePkt(data []byte, src, dst netip.AddrPort, outboundIndex consts.OutboundIndex) (err error) {
	switch outboundIndex {
	case consts.OutboundDirect:
	case consts.OutboundControlPlaneDirect:
		outboundIndex = consts.OutboundDirect

		c.log.Tracef("outbound: %v => %v",
			consts.OutboundControlPlaneDirect.String(),
			outboundIndex.String(),
		)
	default:
	}
	if int(outboundIndex) >= len(c.outbounds) {
		return fmt.Errorf("outbound %v out of range", outboundIndex)
	}
	outbound := c.outbounds[outboundIndex]
	dnsMessage, natTimeout := ChooseNatTimeout(data)
	// We should cache DNS records and set record TTL to 0, in order to monitor the dns req and resp in real time.
	isDns := dnsMessage != nil
	var dummyFrom *netip.AddrPort
	destToSend := dst
	if isDns {
		if resp := c.LookupDnsRespCache(dnsMessage); resp != nil {
			// Send cache to client directly.
			if err = sendPktBind(resp, destToSend, src); err != nil {
				return fmt.Errorf("failed to write cached DNS resp: %w", err)
			}
			if c.log.IsLevelEnabled(logrus.DebugLevel) && len(dnsMessage.Questions) > 0 {
				q := dnsMessage.Questions[0]
				c.log.Tracef("UDP(DNS) %v <-[%v]-> Cache: %v %v",
					RefineSourceToShow(src, destToSend.Addr()), outbound.Name, strings.ToLower(q.Name.String()), q.Type,
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
	}

	l4proto := consts.L4ProtoStr_UDP
	ipversion := consts.IpVersionFromAddr(dst.Addr())
	var dialerForNew *dialer.Dialer

	// For DNS request, modify dst to dns upstream.
	// NOTICE: We might modify l4proto and ipversion.
	dnsUpstream, err := c.dnsUpstream.GetUpstream()
	if err != nil {
		return err
	}
	if isDns && dnsUpstream != nil {
		// Modify dns target to upstream.
		// NOTICE: Routing was calculated in advance by the eBPF program.

		/// Choose the best l4proto and ipversion.
		// Get available ipversions and l4protos for DNS upstream.
		ipversions, l4protos := dnsUpstream.SupportedNetworks()
		var (
			bestDialer  *dialer.Dialer
			bestLatency time.Duration
			bestTarget  netip.AddrPort
		)
		c.log.WithFields(logrus.Fields{
			"ipversions": ipversions,
			"l4protos":   l4protos,
		}).Traceln("Choose DNS path")
		// Get the min latency path.
		for _, ver := range ipversions {
			for _, proto := range l4protos {
				d, latency, err := outbound.Select(proto, ver)
				if err != nil {
					continue
				}
				c.log.WithFields(logrus.Fields{
					"name":     d.Name(),
					"latency":  latency,
					"ver":      ver,
					"proto":    proto,
					"outbound": outbound.Name,
				}).Traceln("Choice")
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
		dummyFrom = &dst
		destToSend = bestTarget
		c.log.WithFields(logrus.Fields{
			"Original": RefineAddrPortToShow(dst),
			"New":      destToSend,
			"Network":  string(l4proto) + string(ipversion),
		}).Traceln("Modify DNS target")
	}
	if dialerForNew == nil {
		dialerForNew, _, err = outbound.Select(l4proto, ipversion)
		if err != nil {
			return fmt.Errorf("failed to select dialer from group %v: %w", outbound.Name, err)
		}
	}

	var isNew bool
	var realDialer *dialer.Dialer

	udpHandler := c.WriteToUDP(src, isDns, dummyFrom, func(from netip.AddrPort) bool {
		// We only validate rush-ans when outbound is direct and pkt does not send to a home device.
		// Because additional record OPT may not be supported by home router.
		// So se should trust home devices even if they make rush-answer (or looks like).
		return outboundIndex == consts.OutboundDirect && !from.Addr().IsPrivate()
	})

	// Dial and send.
	switch l4proto {
	case consts.L4ProtoStr_UDP:
		// Get udp endpoint.
		var ue *UdpEndpoint
	getNew:
		ue, isNew, err = DefaultUdpEndpointPool.GetOrCreate(src, &UdpEndpointOptions{
			Handler:    udpHandler,
			NatTimeout: natTimeout,
			DialerFunc: func() (*dialer.Dialer, error) {
				return dialerForNew, nil
			},
			Target: destToSend,
		})
		if err != nil {
			return fmt.Errorf("failed to GetOrCreate: %w", err)
		}
		// If the udp endpoint has been not alive, remove it from pool and get a new one.
		if !isNew && !ue.Dialer.MustGetAlive(l4proto, ipversion) {
			c.log.WithFields(logrus.Fields{
				"src":     src.String(),
				"network": string(l4proto) + string(ipversion),
				"dialer":  ue.Dialer.Name(),
			}).Debugln("Old udp endpoint is not alive and removed")
			_ = DefaultUdpEndpointPool.Remove(src, ue)
			goto getNew
		}
		// This is real dialer.
		realDialer = ue.Dialer

		//log.Printf("WriteToUDPAddrPort->%v", destToSend)
		_, err = ue.WriteToUDPAddrPort(data, destToSend)
		if err != nil {
			return fmt.Errorf("failed to write UDP packet req: %w", err)
		}
	case consts.L4ProtoStr_TCP:
		// MUST be DNS.
		if !isDns {
			return fmt.Errorf("UDP to TCP only support DNS request")
		}
		realDialer = dialerForNew

		// We can block because we are in a coroutine.

		conn, err := dialerForNew.Dial("tcp", destToSend.String())
		if err != nil {
			return fmt.Errorf("failed to dial proxy to tcp: %w", err)
		}
		defer conn.Close()

		_ = conn.SetDeadline(time.Now().Add(natTimeout))
		// We should write two byte length in the front of TCP DNS request.
		bLen := pool.Get(2)
		defer pool.Put(bLen)
		binary.BigEndian.PutUint16(bLen, uint16(len(data)))
		_, err = conn.Write(bLen)
		if err != nil {
			return fmt.Errorf("failed to write DNS req length: %w", err)
		}
		if _, err = conn.Write(data); err != nil {
			return fmt.Errorf("failed to write DNS req payload: %w", err)
		}

		// Read two byte length.
		if _, err = io.ReadFull(conn, bLen); err != nil {
			return fmt.Errorf("failed to read DNS resp payload length: %w", err)
		}
		buf := pool.Get(int(binary.BigEndian.Uint16(bLen)))
		defer pool.Put(buf)
		if _, err = io.ReadFull(conn, buf); err != nil {
			return fmt.Errorf("failed to read DNS resp payload: %w", err)
		}
		if err = udpHandler(buf, destToSend); err != nil {
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
				"dialer":   realDialer.Name(),
				"qname":    strings.ToLower(q.Name.String()),
				"qtype":    q.Type,
			}).Infof("%v <-> %v",
				RefineSourceToShow(src, destToSend.Addr()), RefineAddrPortToShow(destToSend),
			)
		} else {
			// TODO: Set-up ip to domain mapping and show domain if possible.
			c.log.WithFields(logrus.Fields{
				"network":  string(l4proto) + string(ipversion),
				"outbound": outbound.Name,
				"dialer":   realDialer.Name(),
			}).Infof("%v <-> %v",
				RefineSourceToShow(src, destToSend.Addr()), RefineAddrPortToShow(destToSend),
			)
		}
	}

	return nil
}
