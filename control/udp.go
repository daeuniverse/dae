/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

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
	// DefaultNatTimeout is the default NAT timeout for UDP connections.
	// Reduced from 3 minutes to 30 seconds for faster resource cleanup.
	// Most DNS queries complete within seconds, and long-lived connections
	// (like QUIC) can use longer timeouts via QuicNatTimeout.
	DefaultNatTimeout = 30 * time.Second
	// QuicNatTimeout is 2 minutes for QUIC long-lived connections.
	QuicNatTimeout = 2 * time.Minute

	udpNoAliveDialerLogLimiter sync.Map // map[udpNoAliveDialerLogKey]int64(unix nano)
)

const (
	DnsNatTimeout  = 17 * time.Second // RFC 5452
	AnyfromTimeout = 5 * time.Second  // Do not cache too long.
	MaxRetry       = 2

	noAliveDialerLogInterval = 10 * time.Second
)

type udpNoAliveDialerLogKey struct {
	outbound             string
	origNetworkType      string
	selectionNetworkType string
	strictIpVersion      bool
}

func allowNoAliveDialerLog(key udpNoAliveDialerLogKey, now time.Time) bool {
	nowNano := now.UnixNano()
	for {
		prev, ok := udpNoAliveDialerLogLimiter.Load(key)
		if !ok {
			if _, loaded := udpNoAliveDialerLogLimiter.LoadOrStore(key, nowNano); !loaded {
				return true
			}
			continue
		}

		last, ok := prev.(int64)
		if !ok {
			udpNoAliveDialerLogLimiter.Store(key, nowNano)
			return true
		}
		if nowNano-last < int64(noAliveDialerLogInterval) {
			return false
		}
		if udpNoAliveDialerLogLimiter.CompareAndSwap(key, last, nowNano) {
			return true
		}
	}
}

func (c *ControlPlane) logNoAliveDialerLimited(
	outbound string,
	policy consts.DialerSelectionPolicy,
	origNetworkType string,
	selectionNetworkType string,
	src netip.AddrPort,
	dst netip.AddrPort,
	domain string,
	strictIpVersion bool,
) {
	key := udpNoAliveDialerLogKey{
		outbound:             outbound,
		origNetworkType:      origNetworkType,
		selectionNetworkType: selectionNetworkType,
		strictIpVersion:      strictIpVersion,
	}
	if !allowNoAliveDialerLog(key, time.Now()) {
		return
	}

	c.log.WithFields(logrus.Fields{
		"outbound":               outbound,
		"policy":                 policy,
		"orig_network_type":      origNetworkType,
		"selection_network_type": selectionNetworkType,
		"strict_ip_version":      strictIpVersion,
		"from":                   src.String(),
		"to":                     dst.String(),
		"sniffed":                domain,
		"interval":               noAliveDialerLogInterval.String(),
	}).Warn("no alive dialer for UDP selection (rate-limited)")
}

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
		if err := dnsmsg.Unpack(data); err == nil && !dnsmsg.Response && dnsmsg.Rcode == dnsmessage.RcodeSuccess {
			//log.Printf("DEBUG: lookup %v", dnsmsg.Question[0].Name)
			return &dnsmsg, DnsNatTimeout
		}
	}
	return nil, DefaultNatTimeout
}

func normalizeSendPktAddrFamily(from, realTo netip.AddrPort) (bindAddr, writeAddr netip.AddrPort) {
	bindAddr = from
	writeAddr = realTo

	// Normalize IPv4-mapped source to pure IPv4 so socket family selection
	// matches transparent bind semantics on Linux.
	if bindAddr.Addr().Is4In6() {
		bindAddr = netip.AddrPortFrom(bindAddr.Addr().Unmap(), bindAddr.Port())
	}

	// Case 1: IPv6 socket writing to IPv4 target.
	if writeAddr.Addr().Is4() && bindAddr.Addr().Is6() {
		writeAddr = netip.AddrPortFrom(
			netip.AddrFrom16(writeAddr.Addr().As16()),
			writeAddr.Port(),
		)
	}

	// Case 2: IPv4 socket writing to IPv4-mapped IPv6 target should unmap
	// write address back to IPv4 to avoid "non-IPv4 address" errors.
	if bindAddr.Addr().Is4() && writeAddr.Addr().Is4In6() {
		writeAddr = netip.AddrPortFrom(writeAddr.Addr().Unmap(), writeAddr.Port())
	}

	// Case 3: IPv4 wildcard with IPv6 target must become IPv6 wildcard.
	// This guarantees net.ListenPacket("udp") creates an AF_INET6 socket.
	if bindAddr.Addr().Is4() && bindAddr.Addr().IsUnspecified() && writeAddr.Addr().Is6() {
		bindAddr = netip.AddrPortFrom(netip.IPv6Unspecified(), bindAddr.Port())
	}

	return bindAddr, writeAddr
}

func isUnsupportedTransparentUDPPair(bindAddr, writeAddr netip.AddrPort) bool {
	// Transparent UDP cannot preserve a concrete IPv4 source while emitting a
	// pure IPv6 packet. The address-family pair is unsupported by kernel socket
	// semantics and should fail fast with a clear error.
	return bindAddr.Addr().Is4() && writeAddr.Addr().Is6()
}

// sendPkt uses bind first, and fallback to send hdr if addr is in use.
// The from parameter is the remote server's address (used as local bind for responses).
// The realTo parameter is the client's address (destination for the response).
func sendPkt(log *logrus.Logger, data []byte, from netip.AddrPort, realTo, to netip.AddrPort, lConn *net.UDPConn) (err error) {
	// Proxy chain support: Use original 'from' address as bindAddr to ensure
	// each server response gets its own UDP socket. This prevents response mixing
	// when multiple IPv6 servers would otherwise share [::]:port (wildcard binding).
	//
	// Cross-family handling ensures socket type matches write address family:
	// - IPv6->IPv4: Convert writeAddr to IPv4-mapped IPv6 for dual-stack socket
	// - IPv4->IPv4-mapped IPv6: Unmap writeAddr to IPv4 for IPv4 socket writes
	// - 0.0.0.0->IPv6: Convert bindAddr to [::] to force AF_INET6 wildcard socket
	bindAddr, writeAddr := normalizeSendPktAddrFamily(from, realTo)
	if isUnsupportedTransparentUDPPair(bindAddr, writeAddr) {
		return fmt.Errorf("unsupported transparent UDP address family pair: bind=%v write=%v", bindAddr, writeAddr)
	}

	uConn, _, err := DefaultAnyfromPool.GetOrCreate(bindAddr, AnyfromTimeout)
	if err != nil {
		return
	}
	_, err = uConn.WriteToUDPAddrPort(data, writeAddr)
	return err
}

func (c *ControlPlane) handlePkt(lConn *net.UDPConn, data []byte, src, pktDst, realDst netip.AddrPort, routingResult *bpfRoutingResult, skipSniffing bool) (err error) {
	var realSrc netip.AddrPort
	var domain string
	var ueKey UdpEndpointKey
	realSrc = src

	// Non-DNS traffic: QUIC uses Symmetric NAT (key includes Dst).
	ueKey = UdpEndpointKey{Src: realSrc}
	ue, ueExists := DefaultUdpEndpointPool.Get(ueKey)
	if !ueExists {
		ueKey.Dst = realDst
		ue, ueExists = DefaultUdpEndpointPool.Get(ueKey)
	}
	if ueExists {
		if ue.SniffedDomain == "" && sniffing.IsLikelyQuicInitialPacket(data) {
			// Chrome reuses UDP sockets; remove domain-less endpoint for new QUIC Initial.
			if c.log.IsLevelEnabled(logrus.DebugLevel) {
				c.log.WithField("src", realSrc).Debug("Removed trapped domain-less UdpEndpoint for new QUIC Initial packet")
			}
			_ = DefaultUdpEndpointPool.Remove(ueKey, ue)
			ueExists = false
		} else if ue.SniffedDomain != "" {
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
	}

	// To keep consistency with kernel program, we only sniff DNS request sent to 53.
	natTimeout := DefaultNatTimeout
	if !skipSniffing && !ueExists {
		key := PacketSnifferKey{
			LAddr: realSrc,
			RAddr: realDst,
		}

		// Fast reject for obvious non-QUIC UDP packets when no existing sniff session.
		if DefaultPacketSnifferSessionMgr.Get(key) == nil && !sniffing.IsLikelyQuicInitialPacket(data) {
			goto afterSniffing
		}

		// Sniff Quic, ...
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
				if logrus.IsLevelEnabled(logrus.TraceLevel) {
					logrus.WithError(err).
						WithField("from", realSrc).
						WithField("to", realDst).
						Trace("sniffUdp")
				}
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
							go func(data pool.PB) {
								defer data.Put()
								c.handlePkt(lConn, data, src, pktDst, realDst, routingResult, true)
							}(dCopy)
						}
					}
				}()
			}
		} else {
			_sniffer.Mu.Unlock()
			// sniffer may be nil.
		}
	}

afterSniffing:
	if routingResult.Mark == 0 {
		routingResult.Mark = c.soMarkFromDae
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

	if domain != "" {
		natTimeout = QuicNatTimeout
	}

	// QUIC (domain != "") uses Symmetric NAT.
	ueKey = UdpEndpointKey{Src: realSrc}
	if domain != "" {
		ueKey.Dst = realDst
	}

	ue, isNew, err := DefaultUdpEndpointPool.GetOrCreate(ueKey, &UdpEndpointOptions{
		// Handler handles response packets and send it to the client.
		Handler: func(data []byte, from netip.AddrPort) (err error) {
			// Do not return conn-unrelated err in this func.
			return sendPkt(c.log, data, from, realSrc, src, lConn)
		},
		NatTimeout: natTimeout,
		Log:        c.log,
		GetDialOption: func(ctx context.Context) (option *DialOption, err error) {
			if shouldReroute {
				outboundIndex = consts.OutboundControlPlaneRouting
			}

			switch outboundIndex {
			case consts.OutboundDirect:
			case consts.OutboundControlPlaneRouting:
				if outboundIndex, routingResult.Mark, _, err = c.Route(realSrc, realDst, domain, consts.L4ProtoType_UDP, routingResult); err != nil {
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
			// Ensure dialer's address family matches client's to prevent
			// "non-IPv4/IPv6 address" errors when writing responses.
			// Example: IPv6 client accessing IPv4 target should use IPv6 dialer.
			selectionNetworkType := networkType
			if clientIpVersion := consts.IpVersionFromAddr(realSrc.Addr()); clientIpVersion != networkType.IpVersion {
				selectionNetworkType = &dialer.NetworkType{
					L4Proto:   networkType.L4Proto,
					IpVersion: clientIpVersion,
					IsDns:     networkType.IsDns,
				}
			}
			strictIpVersion := dialIp
			dialerForNew, _, err := outbound.Select(selectionNetworkType, strictIpVersion)
			if err != nil {
				origType := networkType.StringWithoutDns()
				selectedType := selectionNetworkType.StringWithoutDns()
				if errors.Is(err, ob.ErrNoAliveDialer) {
					c.logNoAliveDialerLimited(
						outbound.Name,
						outbound.GetSelectionPolicy(),
						origType,
						selectedType,
						realSrc,
						realDst,
						domain,
						strictIpVersion,
					)
					return nil, err
				}
				return nil, fmt.Errorf(
					"failed to select dialer from group %v (orig:%v, selected:%v, from:%v): %w",
					outbound.Name,
					origType,
					selectedType,
					realSrc.String(),
					err,
				)
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
		if errors.Is(err, ob.ErrNoAliveDialer) {
			// Already emitted a rate-limited diagnostic log above.
			return nil
		}
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
		_ = DefaultUdpEndpointPool.Remove(ueKey, ue)
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
		_ = DefaultUdpEndpointPool.Remove(ueKey, ue)
		retry++
		goto getNew
	}

	// Print log.
	// Only print routing for new connection to avoid the log exploded (Quic and BT).
	if (isNew && c.log.IsLevelEnabled(logrus.InfoLevel)) || c.log.IsLevelEnabled(logrus.DebugLevel) {
		entry := c.log.WithFields(logrus.Fields{
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
		})
		// Build entry once; select level without a second WithFields allocation.
		logger := entry.Infof
		if !isNew && c.log.IsLevelEnabled(logrus.DebugLevel) {
			logger = entry.Debugf
		}
		logger("%v <-> %v", RefineSourceToShow(realSrc, realDst.Addr()), dialTarget)
	}

	return nil
}
