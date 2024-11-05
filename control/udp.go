/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2024, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"fmt"
	"net"
	"net/netip"

	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	ob "github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/component/sniffing"
	"github.com/daeuniverse/outbound/pool"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

var (
	DefaultNatTimeout = 3 * time.Minute
)

const (
	DnsNatTimeout  = 17 * time.Second // RFC 5452
	AnyfromTimeout = 5 * time.Second  // Do not cache too long.
	MaxRetry       = 2
)

type DialOption struct {
	Target        string
	Dialer        *dialer.Dialer
	Outbound      *ob.DialerGroup
	Network       string
	SniffedDomain string
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

// sendPkt uses bind first, and fallback to send hdr if addr is in use.
func sendPkt(log *logrus.Logger, data []byte, from netip.AddrPort, realTo, to netip.AddrPort, lConn *net.UDPConn) (err error) {
	uConn, _, err := DefaultAnyfromPool.GetOrCreate(from.String(), AnyfromTimeout)
	if err != nil {
		return
	}
	_, err = uConn.WriteToUDPAddrPort(data, realTo)
	return err
}

func (c *ControlPlane) handlePkt(lConn *net.UDPConn, data []byte, src, pktDst, realDst netip.AddrPort, routingResult *bpfRoutingResult, skipSniffing bool) (err error) {
	var realSrc netip.AddrPort
	var domain string
	realSrc = src
	ue, ueExists := DefaultUdpEndpointPool.Get(realSrc)
	if ueExists && ue.SniffedDomain != "" {
		// It is quic ...
		// Fast path.
		domain := ue.SniffedDomain
		dialTarget := realDst.String()

		if c.log.IsLevelEnabled(logrus.TraceLevel) {
			fields := logrus.Fields{
				"network":  "udp(fp)",
				"outbound": ue.Outbound.Name,
				"policy":   ue.Outbound.GetSelectionPolicy(),
				"dialer":   ue.Dialer.Property().Name,
				"sniffed":  domain,
				"ip":       RefineAddrPortToShow(realDst),
				"pid":      routingResult.Pid,
				"dscp":     routingResult.Dscp,
				"pname":    ProcessName2String(routingResult.Pname[:]),
				"mac":      Mac2String(routingResult.Mac[:]),
			}
			c.log.WithFields(fields).Tracef("%v <-> %v", RefineSourceToShow(realSrc, realDst.Addr()), dialTarget)
		}

		_, err = ue.WriteTo(data, dialTarget)
		if err != nil {
			return err
		}
		return nil
	}

	// To keep consistency with kernel program, we only sniff DNS request sent to 53.
	dnsMessage, natTimeout := ChooseNatTimeout(data, realDst.Port() == 53)
	// We should cache DNS records and set record TTL to 0, in order to monitor the dns req and resp in real time.
	isDns := dnsMessage != nil
	if !isDns && !skipSniffing && !ueExists {
		// Sniff Quic, ...
		key := PacketSnifferKey{
			LAddr: realSrc,
			RAddr: realDst,
		}
		_sniffer, _ := DefaultPacketSnifferSessionMgr.GetOrCreate(key, nil)
		_sniffer.Mu.Lock()
		// Re-get sniffer from pool to confirm the transaction is not done.
		sniffer := DefaultPacketSnifferSessionMgr.Get(key)
		if _sniffer == sniffer {
			sniffer.AppendData(data)
			domain, err = sniffer.SniffUdp()
			if err != nil && !sniffing.IsSniffingError(err) {
				sniffer.Mu.Unlock()
				return err
			}
			if sniffer.NeedMore() {
				sniffer.Mu.Unlock()
				return nil
			}
			if err != nil {
				logrus.WithError(err).
					WithField("from", realSrc).
					WithField("to", realDst).
					Trace("sniffUdp")
			}
			defer DefaultPacketSnifferSessionMgr.Remove(key, sniffer)
			// Re-handlePkt after self func.
			toRehandle := sniffer.Data()[1 : len(sniffer.Data())-1] // Skip the first empty and the last (self).
			sniffer.Mu.Unlock()
			if len(toRehandle) > 0 {
				defer func() {
					if err == nil {
						for _, d := range toRehandle {
							dCopy := pool.Get(len(d))
							copy(dCopy, d)
							go c.handlePkt(lConn, dCopy, src, pktDst, realDst, routingResult, true)
						}
					}
				}()
			}
		} else {
			_sniffer.Mu.Unlock()
			// sniffer may be nil.
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
	retry := 0
	networkType := &dialer.NetworkType{
		L4Proto:   consts.L4ProtoStr_UDP,
		IpVersion: consts.IpVersionFromAddr(realDst.Addr()),
		IsDns:     false,
	}
	// Get outbound.
	outboundIndex := consts.OutboundIndex(routingResult.Outbound)
	var (
		dialTarget    string
		shouldReroute bool
		dialIp        bool
	)
	_, shouldReroute, _ = c.ChooseDialTarget(outboundIndex, realDst, domain)
	// Do not overwrite target.
	// This fixes a problem that quic connection to google servers.
	// Reproduce:
	// docker run --rm --name curl-http3 ymuski/curl-http3 curl --http3 -o /dev/null -v -L https://i.ytimg.com
	dialTarget = realDst.String()
	dialIp = true
getNew:
	if retry > MaxRetry {
		c.log.WithFields(logrus.Fields{
			"src":     RefineSourceToShow(realSrc, realDst.Addr()),
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
			return sendPkt(c.log, data, from, realSrc, src, lConn)
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
				// Do not overwrite target.
				// This fixes quic problem from google.
				// Reproduce:
				// docker run --rm --name curl-http3 ymuski/curl-http3 curl --http3 -o /dev/null -v -L https://i.ytimg.com
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
				Target:        dialTarget,
				Dialer:        dialerForNew,
				Outbound:      outbound,
				Network:       common.MagicNetwork("udp", routingResult.Mark, c.mptcp),
				SniffedDomain: domain,
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
				"src":     RefineSourceToShow(realSrc, realDst.Addr()),
				"network": networkType.String(),
				"dialer":  ue.Dialer.Property().Name,
				"retry":   retry,
			}).Debugln("Old udp endpoint was not alive and removed.")
		}
		_ = DefaultUdpEndpointPool.Remove(realSrc, ue)
		retry++
		goto getNew
	}
	if domain == "" {
		// It is used for showing.
		domain = ue.SniffedDomain
	}

	_, err = ue.WriteTo(data, dialTarget)
	if err != nil {
		if c.log.IsLevelEnabled(logrus.DebugLevel) {
			c.log.WithFields(logrus.Fields{
				"to":      realDst.String(),
				"domain":  domain,
				"pid":     routingResult.Pid,
				"dscp":    routingResult.Dscp,
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
	if (isNew && c.log.IsLevelEnabled(logrus.InfoLevel)) || c.log.IsLevelEnabled(logrus.DebugLevel) {
		fields := logrus.Fields{
			"network":  networkType.StringWithoutDns(),
			"outbound": ue.Outbound.Name,
			"policy":   ue.Outbound.GetSelectionPolicy(),
			"dialer":   ue.Dialer.Property().Name,
			"sniffed":  domain,
			"ip":       RefineAddrPortToShow(realDst),
			"pid":      routingResult.Pid,
			"dscp":     routingResult.Dscp,
			"pname":    ProcessName2String(routingResult.Pname[:]),
			"mac":      Mac2String(routingResult.Mac[:]),
		}
		logger := c.log.WithFields(fields).Infof
		if !isNew && c.log.IsLevelEnabled(logrus.DebugLevel) {
			logger = c.log.WithFields(fields).Debugf
		}
		logger("%v <-> %v", RefineSourceToShow(realSrc, realDst.Addr()), dialTarget)
	}

	return nil
}
