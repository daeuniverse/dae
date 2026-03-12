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
	connectionErrorLogLimiter  sync.Map // map[connectionErrorLogKey]int64(unix nano)
)

const (
	DnsNatTimeout  = 17 * time.Second // RFC 5452
	AnyfromTimeout = 5 * time.Second  // Do not cache too long.
	MaxRetry       = 2

	noAliveDialerLogInterval = 10 * time.Second
	connectionErrorLogInterval = 5 * time.Second
)

type udpNoAliveDialerLogKey struct {
	outbound             string
	origNetworkType      string
	selectionNetworkType string
	strictIpVersion      bool
}

type connectionErrorLogKey struct {
	outbound    string
	networkType string
	dst         string
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

func allowConnectionErrorLog(key connectionErrorLogKey, now time.Time) bool {
	nowNano := now.UnixNano()
	for {
		prev, ok := connectionErrorLogLimiter.Load(key)
		if !ok {
			if _, loaded := connectionErrorLogLimiter.LoadOrStore(key, nowNano); !loaded {
				return true
			}
			continue
		}

		last, ok := prev.(int64)
		if !ok {
			connectionErrorLogLimiter.Store(key, nowNano)
			return true
		}
		if nowNano-last < int64(connectionErrorLogInterval) {
			return false
		}
		if connectionErrorLogLimiter.CompareAndSwap(key, last, nowNano) {
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
		"orig_network_type":      origNetworkType,
		"selection_network_type": selectionNetworkType,
		"src":                    src.String(),
		"to":                     dst.String(),
		"sniffed":                domain,
		"interval":               noAliveDialerLogInterval.String(),
	}).Warn("no alive dialer for selection (rate-limited)")
}

func (c *ControlPlane) logConnectionErrorLimited(
	outbound string,
	networkType string,
	dst netip.AddrPort,
	err error,
) {
	key := connectionErrorLogKey{
		outbound:    outbound,
		networkType: networkType,
		dst:         dst.String(),
	}
	if !allowConnectionErrorLog(key, time.Now()) {
		return
	}

	c.log.WithFields(logrus.Fields{
		"outbound":  outbound,
		"network":   networkType,
		"to":        dst.String(),
		"err":       err.Error(),
		"interval":  connectionErrorLogInterval.String(),
	}).Warn("connection error (rate-limited)")
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

	// Step 1: Handle address family mismatches by alignment.
	// Transparent sockets require the socket family, bind address family, and destination address
	// family to match (all AF_INET or all AF_INET6).
	// On dual-stack systems, we MUST align to AF_INET6 using IPv4-mapped addresses when families
	// differ, because AF_INET sockets physically cannot handle AF_INET6 addresses.

	// 1. If both are IPv4-compatible, unmap both to pure IPv4 for maximum compatibility
	// and to allow using AF_INET sockets.
	if (bindAddr.Addr().Is4() || bindAddr.Addr().Is4In6()) && (writeAddr.Addr().Is4() || writeAddr.Addr().Is4In6()) {
		if bindAddr.Addr().Is4In6() {
			bindAddr = netip.AddrPortFrom(bindAddr.Addr().Unmap(), bindAddr.Port())
		}
		if writeAddr.Addr().Is4In6() {
			writeAddr = netip.AddrPortFrom(writeAddr.Addr().Unmap(), writeAddr.Port())
		}
	} else {
		// 2. If one is pure IPv6, both MUST be represented as AF_INET6 (possibly mapped).
		// CRITICAL: We must also convert ANY IPv4 bind address (including concrete ones)
		// to an IPv6 wildcard or mapped address to ensure the listener (AnyfromPool)
		// creates an AF_INET6 socket. Pure AF_INET sockets will return "non-IPv4 address"
		// error if we try to write to a v6 target.
		if bindAddr.Addr().Is4() && writeAddr.Addr().Is6() {
			// Promote bind to v6 wildcard to ENSURE AnyfromPool creates a dual-stack socket.
			// Use the same port.
			bindAddr = netip.AddrPortFrom(netip.IPv6Unspecified(), bindAddr.Port())
		} else if bindAddr.Addr().Is6() && writeAddr.Addr().Is4() {
			// Align target to v6
			writeAddr = netip.AddrPortFrom(netip.AddrFrom16(writeAddr.Addr().As16()), writeAddr.Port())
		}
	}

	// Step 2: Handle remaining wildcard adjustments.
	// (Redundant but safe) ensure IPv4 wildcard with IPv6 target is IPv6 wildcard.
	if bindAddr.Addr().Is4() && bindAddr.Addr().IsUnspecified() && writeAddr.Addr().Is6() {
		bindAddr = netip.AddrPortFrom(netip.IPv6Unspecified(), bindAddr.Port())
	}
	// IPv6 wildcard (including mapped) with pure IPv4 target should become pure IPv4 wildcard
	// ONLY if both are IPv4-compatible (handled in Step 1).
	// If the socket is already IPv6, we should keep it IPv6.
	if bindAddr.Addr().Is6() && bindAddr.Addr().IsUnspecified() && writeAddr.Addr().Is4() && bindAddr.Addr().Is4In6() {
		bindAddr = netip.AddrPortFrom(netip.IPv4Unspecified(), bindAddr.Port())
		writeAddr = netip.AddrPortFrom(writeAddr.Addr().Unmap(), writeAddr.Port())
	}

	return bindAddr, writeAddr
}

func isUnsupportedTransparentUDPPair(bindAddr, writeAddr netip.AddrPort) bool {
	// Transparent UDP cannot preserve a concrete IPv4 source while emitting a
	// pure IPv6 packet. The address-family pair is unsupported by kernel socket
	// semantics and should fail fast with a clear error.
	//
	// Also check the reverse: IPv6 source with IPv4 destination (after unmapping).
	if bindAddr.Addr().Is4() && writeAddr.Addr().Is6() && !writeAddr.Addr().Is4In6() {
		return true
	}
	// IPv6 bind with IPv4 write is also unsupported (writeAddr was unmapped from IPv4-mapped IPv6)
	if bindAddr.Addr().Is6() && writeAddr.Addr().Is4() {
		return true
	}
	return false
}

// sendPkt sends a UDP packet to the destination.
// Parameters:
//   - log: logger for debug output
//   - data: packet data to send
//   - from: source address of the packet (for logging/metadata only)
//   - realTo: destination address where the packet should be sent
//   - afp: optional cached Anyfrom socket for Symmetric NAT sessions
func sendPkt(log *logrus.Logger, data []byte, from netip.AddrPort, realTo netip.AddrPort, afp **Anyfrom) (err error) {
	// Transparent UDP replies must preserve the original destination as the
	// packet source. The ingress listener socket cannot safely do that for
	// redirected local DNS traffic, so all reply paths resolve a transparent
	// Anyfrom socket bound to the desired source address instead of writing
	// directly on the listener.
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

func (c *ControlPlane) handlePkt(lConn *net.UDPConn, data []byte, src, pktDst, realDst netip.AddrPort, routingResult *bpfRoutingResult, flowDecision UdpFlowDecision, skipSniffing bool) (err error) {
	var realSrc netip.AddrPort
	var domain string
	var ueKey UdpEndpointKey
	realSrc = src

	var ue *UdpEndpoint
	var ueExists bool
	var replayPackets []pool.PB
	defer func() {
		for _, pkt := range replayPackets {
			pkt.Put()
		}
	}()

	// Priority:
	// 1. Symmetric NAT (Src+Dst) for session isolation (QUIC/BT).
	// 2. Full-Cone NAT (Src) only for non-QUIC-initial compatibility.
	isQuicInitial := flowDecision.IsQuicInitial
	ueKey = flowDecision.SymmetricNatEndpointKey()
	ue, ueExists = DefaultUdpEndpointPool.Get(ueKey)
	if !ueExists && !flowDecision.PreferSymmetricNat() {
		ueKey = flowDecision.FullConeNatEndpointKey()
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
			domain = ue.SniffedDomain
			dialTarget := realDst.String()

			// Update NAT timeout for QUIC connections to ensure proper timeout
			// based on the actual forwarding state (QUIC needs longer timeout)
			ue.UpdateNatTimeout(QuicNatTimeout)

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
			if err == nil {
				return nil
			}
			if c.log.IsLevelEnabled(logrus.DebugLevel) {
				c.log.WithFields(logrus.Fields{
					"to":      realDst.String(),
					"domain":  domain,
					"pid":     routingResult.Pid,
					"dscp":    routingResult.Dscp,
					"pname":   ProcessName2String(routingResult.Pname[:]),
					"mac":     Mac2String(routingResult.Mac[:]),
					"from":    realSrc.String(),
					"network": "udp(fp)",
					"err":     err.Error(),
				}).Debugln("Failed to write UDP fast-path packet. Remove stale endpoint and rebuild.")
			}
			_ = DefaultUdpEndpointPool.Remove(ueKey, ue)
			ue = nil
			ueExists = false
		}
	}

	// To keep consistency with kernel program, we only sniff DNS request sent to 53.
	natTimeout := DefaultNatTimeout
	if domain == "" && !skipSniffing && !ueExists {
		// Fast path: only QUIC Initial packets should enter sniffing.
		// Normal UDP traffic should be forwarded immediately without blocking.
		if !isQuicInitial {
			// Not a QUIC Initial packet - skip sniffing entirely.
			// Even if there's an existing sniffer session, non-QUIC packets
			// should not be delayed by the sniffing process.
			goto afterSniffing
		}

		// Create sniffer key with DCID for QUIC connections.
		// Each DCID is like a different bus - passengers (packets) wait
		// for their specific bus to depart (complete sniffing).
		key := NewPacketSnifferKey(realSrc, realDst, data)

		// Check if this DCID has failed sniffing before.
		// Failed DCIDs bypass sniffing entirely and use IP routing directly.
		// This prevents blocking when a previous sniffing attempt timed out.
		if IsQuicDcidFailed(key) {
			goto afterSniffing
		}

		// Get or create sniffer for this DCID.
		_sniffer, _ := DefaultPacketSnifferSessionMgr.GetOrCreate(key, nil)
		_sniffer.Mu.Lock()
		sniffer := DefaultPacketSnifferSessionMgr.Get(key)
		if _sniffer == sniffer {
			now := time.Now()

			// Check if we've hit the bypass threshold for this DCID.
			// After consecutive failures, fall back to IP routing to avoid
			// indefinitely blocking QUIC connections waiting for sniffing completion.
			if sniffer.ShouldBypassSniff(now) {
				// Mark this DCID as failed - subsequent packets will bypass sniffing.
				MarkQuicDcidFailed(key)
				sniffer.Mu.Unlock()
				goto afterSniffing
			}

			sniffer.AppendData(data)
			domain, err = sniffer.SniffUdp()
			if err != nil {
				// Check for decrypt failures (malformed packets).
				// If decryption repeatedly fails, the packets are not valid QUIC
				// and retrying is pointless. Give up quickly.
				if stderrors.Is(err, sniffing.ErrNotApplicable) {
					sniffer.consecutiveDecryptFailures++
					if sniffer.consecutiveDecryptFailures >= consecutiveDecryptFailuresThreshold {
						// Too many decrypt failures - mark DCID as failed.
						if c.log.IsLevelEnabled(logrus.DebugLevel) {
							c.log.WithFields(logrus.Fields{
								"src":      realSrc.String(),
								"dst":      realDst.String(),
								"failures": sniffer.consecutiveDecryptFailures,
							}).Debug("QUIC decrypt failed repeatedly, marking DCID as failed")
						}
						MarkQuicDcidFailed(key)
						sniffer.Mu.Unlock()
						goto afterSniffing
					}
				} else {
					// Reset decrypt failure counter on non-decrypt errors.
					sniffer.consecutiveDecryptFailures = 0
				}

				// Log unexpected errors for debugging but don't drop packet.
				if !sniffing.IsSniffingError(err) {
					if logrus.IsLevelEnabled(logrus.DebugLevel) {
						logrus.WithError(err).
							WithField("from", realSrc).
							WithField("to", realDst).
							Debug("UDP sniffing encountered unexpected error but continue processing")
					}
				}
			}

			if sniffer.NeedMore() {
				// We don't record No SNI streak for NeedMore because handshakes naturally span multiple packets.
				sniffer.Mu.Unlock()
				return nil
			}

			if (err != nil && !stderrors.Is(err, sniffing.ErrNeedMore)) || domain == "" {
				sniffer.RecordSniffNoSni(now)
			} else if domain != "" {
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
			// Flush previously buffered packets on the same endpoint path before the
			// current packet so QUIC sniff completion preserves original ingress order.
			toReplay := sniffer.Data()[1 : len(sniffer.Data())-1] // Skip the first empty and the last (self).
			if len(toReplay) > 0 {
				replayPackets = make([]pool.PB, 0, len(toReplay))
				for _, d := range toReplay {
					dCopy := pool.Get(len(d))
					copy(dCopy, d)
					replayPackets = append(replayPackets, dCopy)
				}
			}
			sniffer.Mu.Unlock()
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
	// foundUeKey captures the endpoint key that the initial Get succeeded with.
	// When the target key at dial time equals foundUeKey, we can reuse ue directly
	// and skip the redundant GetOrCreate sync.Map lookup (common path: non-QUIC
	// existing endpoint, zero domain upgrade).
	foundUeKey := ueKey
	payloads := make([][]byte, 0, len(replayPackets)+1)
	for _, pkt := range replayPackets {
		payloads = append(payloads, pkt)
	}
	payloads = append(payloads, data)
	packetIndex := 0
	retry := 0
	var isNew bool
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

	// Determine NAT timeout based on connection type
	if domain != "" || flowDecision.IsLikelyQuicData {
		// QUIC connections get 2 minutes
		natTimeout = QuicNatTimeout
	} else {
		// Non-QUIC UDP uses default timeout
		natTimeout = DefaultNatTimeout
	}

	// QUIC (domain != "") or likely QUIC Initial packets use Symmetric NAT.
	ueKey = flowDecision.EndpointKeyForDial(domain)

	// Fast path: reuse the endpoint already loaded by the initial Get when the
	// target key is unchanged (non-QUIC existing flow, no domain upgrade).
	// On any retry the endpoint was removed, so we always call GetOrCreate.
	if retry == 0 && ueExists && ueKey == foundUeKey {
		// Update NAT timeout based on current forwarding state
		// This allows the timeout to adapt to changes (e.g., domain sniffed, policy change)
		ue.UpdateNatTimeout(natTimeout)
		isNew = false
	} else {
		ue, isNew, err = DefaultUdpEndpointPool.GetOrCreate(ueKey, &UdpEndpointOptions{
			// Handler handles response packets and send it to the client.
			Handler: func(ue *UdpEndpoint, data []byte, from netip.AddrPort) (err error) {
				// Do not return conn-unrelated err in this func.
				return sendPkt(c.log, data, from, realSrc, ue.responseConnCacheSlot())
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
			// Log connection errors with rate limiting to prevent log spam,
			// but still propagate the error to maintain error semantics.
			c.logConnectionErrorLimited(
				fmt.Sprintf("%d", routingResult.Outbound),
				networkType.String(),
				realDst,
				err,
			)
			return fmt.Errorf("failed to GetOrCreate: %w", err)
		}
	}

	// If the udp endpoint has been not alive, remove it from pool and get a new one.
	if !isNew && ue.Outbound.GetSelectionPolicy() != consts.DialerSelectionPolicy_Fixed && !ue.Dialer.MustGetAlive(networkType) {

		// Optimization: For QUIC/WebRTC, do not aggressively remove endpoint on hot path
		// just because one health check failed. Let the idle timeout or explicit write error
		// handle it to prevent flapping. Only remove if this was a DNS-type endpoint which
		// is more sensitive to staleness.
		if domain == "" {
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
	}
	if domain == "" {
		// It is used for showing.
		domain = ue.SniffedDomain
	}

	for packetIndex < len(payloads) {
		_, err = ue.WriteTo(payloads[packetIndex], dialTarget)
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
					"packet":  packetIndex,
				}).Debugln("Failed to write UDP packet request. Try to remove old UDP endpoint and retry.")
			}
			_ = DefaultUdpEndpointPool.Remove(ueKey, ue)
			retry++
			goto getNew
		}
		packetIndex++
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
