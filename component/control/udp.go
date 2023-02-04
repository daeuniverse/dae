/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2022, v2rayA Organization <team@v2raya.org>
 */

package control

import (
	"encoding/binary"
	"fmt"
	"github.com/mzz2017/softwind/pool"
	"github.com/sirupsen/logrus"
	"github.com/v2rayA/dae/common/consts"
	"golang.org/x/net/dns/dnsmessage"
	"net"
	"net/netip"
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

func (c *ControlPlane) RelayToUDP(lConn *net.UDPConn, to netip.AddrPort, isDNS bool, dummyFrom *netip.AddrPort) UdpHandler {
	return func(data []byte, from netip.AddrPort) (err error) {
		if isDNS {
			data, err = c.DnsRespHandler(data)
			if err != nil {
				c.log.Debugf("DnsRespHandler: %v", err)
			}
		}
		if dummyFrom != nil {
			from = *dummyFrom
		}
		return sendPktWithHdr(data, from, lConn, to)
	}
}

func (c *ControlPlane) handlePkt(data []byte, lConn *net.UDPConn, lAddrPort netip.AddrPort, addrHdr *AddrHdr) (err error) {
	switch consts.OutboundIndex(addrHdr.Outbound) {
	case consts.OutboundDirect:
	case consts.OutboundControlPlaneDirect:
		addrHdr.Outbound = uint8(consts.OutboundDirect)

		c.log.Debugf("outbound: %v => %v",
			consts.OutboundControlPlaneDirect.String(),
			consts.OutboundIndex(addrHdr.Outbound).String(),
		)
	default:
	}
	if int(addrHdr.Outbound) >= len(c.outbounds) {
		return fmt.Errorf("outbound %v out of range", addrHdr.Outbound)
	}
	outbound := c.outbounds[addrHdr.Outbound]
	dnsMessage, natTimeout := ChooseNatTimeout(data)
	// We should cache DNS records and set record TTL to 0, in order to monitor the dns req and resp in real time.
	isDns := dnsMessage != nil
	var dummyFrom *netip.AddrPort
	dest := addrHdr.Dest
	if isDns {
		if resp := c.LookupDnsRespCache(dnsMessage); resp != nil {
			if err = sendPktWithHdr(resp, dest, lConn, lAddrPort); err != nil {
				return fmt.Errorf("failed to write cached DNS resp: %w", err)
			}
			if c.log.IsLevelEnabled(logrus.DebugLevel) && len(dnsMessage.Questions) > 0 {
				q := dnsMessage.Questions[0]
				c.log.Debugf("UDP(DNS) %v <-[%v]-> Cache: %v %v",
					RefineSourceToShow(lAddrPort, dest.Addr()), outbound.Name, q.Name, q.Type,
				)
			}
			return nil
		} else {
			c.log.Debugf("Modify dns target %v to upstream: %v", RefineAddrPortToShow(dest), c.dnsUpstream)
			// Modify dns target to upstream.
			// NOTICE: Routing was calculated in advance by the eBPF program.
			dummyFrom = &addrHdr.Dest
			dest = c.dnsUpstream

			if c.log.IsLevelEnabled(logrus.DebugLevel) && len(dnsMessage.Questions) > 0 {
				q := dnsMessage.Questions[0]
				c.log.Debugf("UDP(DNS) %v <-[%v]-> %v: %v %v",
					RefineSourceToShow(lAddrPort, addrHdr.Dest.Addr()), outbound.Name, RefineAddrPortToShow(dest), q.Name, q.Type,
				)
			}
		}
	} else {
		// TODO: Set-up ip to domain mapping and show domain if possible.
		c.log.WithFields(logrus.Fields{
			"l4proto":  "UDP",
			"outbound": outbound.Name,
		}).Infof("%v <-> %v",
			RefineSourceToShow(lAddrPort, dest.Addr()), RefineAddrPortToShow(dest),
		)
	}
	ue, err := DefaultUdpEndpointPool.GetOrCreate(lAddrPort, &UdpEndpointOptions{
		Handler:    c.RelayToUDP(lConn, lAddrPort, isDns, dummyFrom),
		NatTimeout: natTimeout,
		Dialer:     outbound,
		Target:     dest,
	})
	if err != nil {
		return fmt.Errorf("failed to GetOrCreate: %w", err)
	}
	//log.Printf("WriteToUDPAddrPort->%v", dest)
	_, err = ue.WriteToUDPAddrPort(data, dest)
	if err != nil {
		return fmt.Errorf("failed to write UDP packet req: %w", err)
	}
	return nil
}
