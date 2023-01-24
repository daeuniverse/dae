/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2022, mzz2017 (mzz@tuta.io). All rights reserved.
 */

package control

import (
	"encoding/binary"
	"fmt"
	"github.com/v2rayA/dae/common/consts"
	"github.com/v2rayA/dae/pkg/pool"
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

func (c *ControlPlane) RelayToUDP(lConn *net.UDPConn, to netip.AddrPort, isDNS bool) UdpHandler {
	return func(data []byte, from netip.AddrPort) (err error) {
		if isDNS {
			data, err = c.DnsRespHandler(data)
			if err != nil {
				c.log.Warnf("DnsRespHandler: %v", err)
			}
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
	outbound := c.outbounds[addrHdr.Outbound]
	dnsMessage, natTimeout := ChooseNatTimeout(data)
	// We should cache DNS records and set record TTL to 0, in order to monitor the dns req and resp in real time.
	isDns := dnsMessage != nil
	if isDns {
		if resp := c.LookupDnsRespCache(dnsMessage); resp != nil {
			if err = sendPktWithHdr(resp, addrHdr.Dest, lConn, lAddrPort); err != nil {
				return fmt.Errorf("failed to write cached DNS resp: %w", err)
			}
			q := dnsMessage.Questions[0]
			c.log.Debugf("UDP(DNS) %v <-[%v]-> Cache: %v %v",
				lAddrPort.String(), outbound.Name, q.Name, q.Type,
			)
			return nil
		} else {
			q := dnsMessage.Questions[0]
			c.log.Debugf("UDP(DNS) %v <-[%v]-> %v: %v %v",
				lAddrPort.String(), outbound.Name, addrHdr.Dest.String(), q.Name, q.Type,
			)
		}
	} else {
		// TODO: Set-up ip to domain mapping and show domain if possible.
		c.log.Infof("UDP %v <-[%v]-> %v",
			lAddrPort.String(), outbound.Name, addrHdr.Dest.String(),
		)
	}
	ue, err := DefaultUdpEndpointPool.GetOrCreate(lAddrPort, &UdpEndpointOptions{
		Handler:    c.RelayToUDP(lConn, lAddrPort, isDns),
		NatTimeout: natTimeout,
		Dialer:     outbound,
		Target:     addrHdr.Dest,
	})
	if err != nil {
		return fmt.Errorf("failed to GetOrCreate: %w", err)
	}
	//log.Printf("WriteToUDPAddrPort->%v", dest)
	_, err = ue.WriteToUDPAddrPort(data, addrHdr.Dest)
	if err != nil {
		return fmt.Errorf("failed to write UDP packet req: %w", err)
	}
	return nil
}
