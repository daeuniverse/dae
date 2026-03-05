/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	stderrors "errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"time"

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
// afp, if non-nil, provides a pre-cached Anyfrom socket for the hot path;
// on a successful pool fallback, *afp is updated so future calls skip the lookup.
func sendPkt(log *logrus.Logger, data []byte, from netip.AddrPort, realTo netip.AddrPort, afp **Anyfrom) (err error) {
	bindAddr, writeAddr := normalizeSendPktAddrFamily(from, realTo)
	if isUnsupportedTransparentUDPPair(bindAddr, writeAddr) {
		return fmt.Errorf("unsupported transparent UDP address family pair: bind=%v write=%v", bindAddr, writeAddr)
	}

	if afp != nil && *afp != nil {
		if _, err = (*afp).WriteToUDPAddrPort(data, writeAddr); err == nil {
			return nil
		}
		// cached socket is stale; fall through to fresh pool lookup
	}

	uConn, _, err := DefaultAnyfromPool.GetOrCreate(bindAddr, AnyfromTimeout)
	if err != nil {
		return
	}
	if _, err = uConn.WriteToUDPAddrPort(data, writeAddr); err != nil {
		return err
	}
	// Update caller's cached socket so future calls skip the pool lookup.
	if afp != nil {
		*afp = uConn
	}
	return nil
}

func (c *ControlPlane) handlePkt(lConn *net.UDPConn, data []byte, src, pktDst, realDst netip.AddrPort, routingResult *bpfRoutingResult, skipSniffing bool) (err error) {
	var realSrc netip.AddrPort
	var domain string
	var ueKey UdpEndpointKey
	realSrc = src

	var ue *UdpEndpoint
	var ueExists bool

	// Priority:
	// 1. Symmetric NAT (Src+Dst) for session isolation (QUIC/BT).
	// 2. Full-Cone NAT (Src) only for non-QUIC compatibility.
	isQuicLongHeader := sniffing.IsLikelyQuicLongHeaderPacket(data)
	isQuicInitial := isQuicLongHeader && sniffing.IsLikelyQuicInitialPacket(data)
	ueKey = UdpEndpointKey{Src: realSrc, Dst: realDst}
	ue, ueExists = DefaultUdpEndpointPool.Get(ueKey)
	if !ueExists && !isQuicLongHeader {
		ueKey = UdpEndpointKey{Src: realSrc}
		ue, ueExists = DefaultUdpEndpointPool.Get(ueKey)
	}
	if ueExists {
		if ue.SniffedDomain == "" && isQuicInitial {
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
		if DefaultPacketSnifferSessionMgr.Get(key) == nil && !isQuicInitial {
			goto afterSniffing
		}

		// Sniff Quic, ...
		_sniffer, _ := DefaultPacketSnifferSessionMgr.GetOrCreate(key, nil)
		_sniffer.Mu.Lock()
		// Re-get sniffer from pool to confirm the transaction is not done.
		sniffer := DefaultPacketSnifferSessionMgr.Get(key)
		if _sniffer == sniffer {
			now := time.Now()
			if sniffer.ShouldBypassSniff(now) {
				sniffer.Mu.Unlock()
				goto afterSniffing
			}
			sniffer.AppendData(data)
			domain, err = sniffer.SniffUdp()
			if err != nil {
				// Sniffing failure should not drop the packet.
				// Whether it's a sniffing error or unexpected error,
				// we continue to process the packet with IP-based routing.
				if !sniffing.IsSniffingError(err) {
					// Log unexpected errors for debugging but don't drop packet
					if logrus.IsLevelEnabled(logrus.DebugLevel) {
						logrus.WithError(err).
							WithField("from", realSrc).
							WithField("to", realDst).
							Debug("UDP sniffing encountered unexpected error but continue processing")
					}
				}
			}
			if sniffer.NeedMore() {
				sniffer.RecordSniffNoSni(now)
				sniffer.Mu.Unlock()
				return nil
			}
			if err != nil || domain == "" {
				sniffer.RecordSniffNoSni(now)
			} else {
				sniffer.RecordSniffSuccess()
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
	// Keep UDP target pinned to original destination IP to avoid QUIC session issues.
	dialTarget := realDst.String()
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

	if domain != "" || isQuicLongHeader {
		natTimeout = QuicNatTimeout
	}

	// QUIC (domain != "") or likely QUIC long-header packets use Symmetric NAT.
	ueKey = UdpEndpointKey{Src: realSrc}
	if domain != "" || isQuicLongHeader {
		ueKey.Dst = realDst
	}

	ue, isNew, err := DefaultUdpEndpointPool.GetOrCreate(ueKey, &UdpEndpointOptions{
		// Handler handles response packets and send it to the client.
		Handler: func(ue *UdpEndpoint, data []byte, from netip.AddrPort) (err error) {
			// Do not return conn-unrelated err in this func.
			return sendPkt(c.log, data, from, realSrc, &ue.respConn)
		},
		NatTimeout: natTimeout,
		Log:        c.log,
		GetDialOption: func(ctx context.Context) (option *DialOption, err error) {
			dialParam := &proxyDialParam{
				Outbound:    consts.OutboundIndex(routingResult.Outbound),
				Domain:      domain,
				Mac:         routingResult.Mac,
				Dscp:        routingResult.Dscp,
				ProcessName: routingResult.Pname,
				Src:         realSrc,
				Dest:        realDst,
				Mark:        routingResult.Mark,
				Network:     "udp",
			}

			res, err := c.chooseProxyDialer(ctx, dialParam)
			if err != nil {
				if res != nil && res.Outbound != nil && stderrors.Is(err, ob.ErrNoAliveDialer) {
					c.logNoAliveDialerLimited(
						res.Outbound.Name,
						res.Outbound.GetSelectionPolicy(),
						res.OrigNetworkType,
						res.SelectionNetworkType,
						realSrc,
						realDst,
						domain,
						res.IsDialIp,
					)
					return nil, err
				}
				return nil, err
			}

			return &DialOption{
				// Keep fixed-IP target even if chooseProxyDialer selected a domain target.
				Target:        dialTarget,
				Dialer:        res.Dialer,
				Outbound:      res.Outbound,
				Network:       res.Network,
				SniffedDomain: res.SniffedDomain,
			}, nil
		},
	})
	if err != nil {
		if stderrors.Is(err, ob.ErrNoAliveDialer) {
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
