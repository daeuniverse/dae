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

func (c *ControlPlane) RelayToUDP(to netip.AddrPort, isDNS bool, dummyFrom *netip.AddrPort, validateRushAns bool) UdpHandler {
	return func(data []byte, from netip.AddrPort) (err error) {
		// Do not return conn-unrelated err in this func.

		if isDNS {
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

		// Need to make a DNS request.
		if c.dnsUpstream.IsValid() {
			c.log.Tracef("Modify dns target %v to upstream: %v", RefineAddrPortToShow(destToSend), c.dnsUpstream)
			// Modify dns target to upstream.
			// NOTICE: Routing was calculated in advance by the eBPF program.
			dummyFrom = &dst
			destToSend = c.dnsUpstream
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

	// We only validate rush-ans when outbound is direct and pkt does not send to a home device.
	// Because additional record OPT may not be supported by home router.
	// So se should trust home devices even if they make rush-answer (or looks like).
	validateRushAns := outboundIndex == consts.OutboundDirect && !destToSend.Addr().IsPrivate()
	ue, err := DefaultUdpEndpointPool.GetOrCreate(src, &UdpEndpointOptions{
		Handler:    c.RelayToUDP(src, isDns, dummyFrom, validateRushAns),
		NatTimeout: natTimeout,
		DialerFunc: func() (*dialer.Dialer, error) {
			newDialer, err := outbound.Select()
			if err != nil {
				return nil, fmt.Errorf("failed to select dialer from group %v: %w", outbound.Name, err)
			}
			return newDialer, nil
		},
		Target: destToSend,
	})
	if err != nil {
		return fmt.Errorf("failed to GetOrCreate: %w", err)
	}
	// This is real dialer.
	d := ue.Dialer

	if isDns && c.log.IsLevelEnabled(logrus.DebugLevel) && len(dnsMessage.Questions) > 0 {
		q := dnsMessage.Questions[0]
		c.log.WithFields(logrus.Fields{
			"l4proto":  "UDP(DNS)",
			"outbound": outbound.Name,
			"dialer":   d.Name(),
			"qname":    strings.ToLower(q.Name.String()),
			"qtype":    q.Type,
		}).Infof("%v <-> %v",
			RefineSourceToShow(src, destToSend.Addr()), RefineAddrPortToShow(destToSend),
		)
	} else {
		// TODO: Set-up ip to domain mapping and show domain if possible.
		c.log.WithFields(logrus.Fields{
			"l4proto":  "UDP",
			"outbound": outbound.Name,
			"dialer":   d.Name(),
		}).Infof("%v <-> %v",
			RefineSourceToShow(src, destToSend.Addr()), RefineAddrPortToShow(destToSend),
		)
	}
	//log.Printf("WriteToUDPAddrPort->%v", destToSend)
	_, err = ue.WriteToUDPAddrPort(data, destToSend)
	if err != nil {
		return fmt.Errorf("failed to write UDP packet req: %w", err)
	}
	return nil
}
