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
	"github.com/daeuniverse/dae/common/errors"
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
	connectionErrorLogLimiter  sync.Map // map[string]int64(unix nano)
)

const (
	DnsNatTimeout  = 17 * time.Second // RFC 5452
	AnyfromTimeout = 5 * time.Second  // Do not cache too long.
	MaxRetry       = 2

	noAliveDialerLogInterval   = 10 * time.Second
	connectionErrorLogInterval = 5 * time.Second
)

// ResetUdpLogLimiters clears all rate limiters for UDP logging.
// Called on reload to allow fresh logging after configuration changes.
func ResetUdpLogLimiters() {
	udpNoAliveDialerLogLimiter.Range(func(key, value any) bool {
		udpNoAliveDialerLogLimiter.Delete(key)
		return true
	})
	connectionErrorLogLimiter.Range(func(key, value any) bool {
		connectionErrorLogLimiter.Delete(key)
		return true
	})
}

func udpEndpointNetworkType(ue *UdpEndpoint) dialer.NetworkType {
	return dialer.NetworkType{
		L4Proto:   consts.L4ProtoStr_UDP,
		IpVersion: consts.IpVersionFromAddr(ue.lAddr.Addr()),
		IsDns:     false,
	}
}

func (c *ControlPlane) checkUdpEndpointHealth(ue *UdpEndpoint, ueKey UdpEndpointKey, isFastPath bool) bool {
	if ue == nil || ue.Dialer == nil {
		return false
	}
	if ue.Outbound != nil && ue.Outbound.GetSelectionPolicy() == consts.DialerSelectionPolicy_Fixed {
		return true
	}
	networkType := udpEndpointNetworkType(ue)

	// Short-circuit: lightweight check MustGetAlive first.
	// Don't proactively drop existing healthy connections in fast-path.
	if !ue.Dialer.MustGetAlive(&networkType) {
		if c.log.IsLevelEnabled(logrus.DebugLevel) {
			path := "UDP"
			if isFastPath {
				path = "fast-path UDP"
			}
			c.log.WithFields(logrus.Fields{
				"dialer": ue.Dialer.Property().Name,
				"alive":  ue.Dialer.MustGetAlive(&networkType),
			}).Debugf("Re-selecting outbound for existing %s endpoint due to dialer health.", path)
		}
		_ = DefaultUdpEndpointPool.Remove(ueKey, ue)
		return false
	}
	return true
}

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

func allowConnectionErrorLog(key string, now time.Time) bool {
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
	outbound *ob.DialerGroup,
	policy consts.DialerSelectionPolicy,
	origNetworkType string,
	selectionNetworkType *dialer.NetworkType,
	src netip.AddrPort,
	dst netip.AddrPort,
	domain string,
	strictIpVersion bool,
) {
	key := udpNoAliveDialerLogKey{
		outbound:             outbound.Name,
		origNetworkType:      origNetworkType,
		selectionNetworkType: selectionNetworkType.String(),
		strictIpVersion:      strictIpVersion,
	}
	if !allowNoAliveDialerLog(key, time.Now()) {
		return
	}

	total := len(outbound.Dialers)
	alive := 0
	if a := outbound.MustGetAliveDialerSet(selectionNetworkType); a != nil {
		alive = a.Len()
	}

	c.log.WithFields(logrus.Fields{
		"outbound":               outbound.Name,
		"orig_network_type":      origNetworkType,
		"selection_network_type": selectionNetworkType.String(),
		"src":                    src.String(),
		"to":                     dst.String(),
		"sniffed":                domain,
		"interval":               noAliveDialerLogInterval.String(),
		"total":                  total,
		"alive":                  alive,
	}).Warn("no alive dialer for selection (rate-limited)")

	// Aggressively re-probe all dialers when ErrNoAliveDialer is detected.
	// Without this, recovery depends solely on the periodic check_interval timer.
	// Since ErrNoAliveDialer drops every packet, traffic never succeeds and
	// ReportAvailableTraffic is never called — the system is stuck until the next
	// scheduled health check cycle. By triggering NotifyCheck here (rate-limited
	// to once per noAliveDialerLogInterval), dead dialers are re-examined promptly
	// after the underlying issue clears, eliminating the need for a manual restart.
	for _, d := range outbound.Dialers {
		d.NotifyCheckForNetworkType(selectionNetworkType)
	}
}

type DialOption struct {
	Target        string
	Dialer        *dialer.Dialer
	Outbound      *ob.DialerGroup
	Network       string
	SniffedDomain string
	Excluded      *dialer.Dialer
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

	// Pre-compute address types once for performance (avoid repeated method calls).
	// This ensures idempotency - multiple calls with same inputs produce same output.
	fromAddr := from.Addr()
	toAddr := realTo.Addr()

	fromIs4 := fromAddr.Is4()
	fromIs4In6 := fromAddr.Is4In6()
	toIs4 := toAddr.Is4()
	toIs4In6 := toAddr.Is4In6()
	fromIs6 := fromAddr.Is6() && !fromIs4In6
	toIs6 := toAddr.Is6() && !toIs4In6

	// Optimization 1: When both addresses are IPv4-compatible (pure or mapped),
	// unmap to pure IPv4 for better performance. AF_INET sockets are faster
	// than AF_INET6 and have lower overhead.
	if (fromIs4 || fromIs4In6) && (toIs4 || toIs4In6) {
		if fromIs4In6 {
			bindAddr = netip.AddrPortFrom(fromAddr.Unmap(), from.Port())
		}
		if toIs4In6 {
			writeAddr = netip.AddrPortFrom(toAddr.Unmap(), realTo.Port())
		}
		// Both addresses are now pure IPv4 - no further conversion needed.
		return bindAddr, writeAddr
	}

	// Case 2: IPv4 bind with IPv6 target → IPv6 wildcard.
	// Using IPv6 wildcard [::] instead of IPv4-mapped ensures:
	// - AnyfromPool creates a proper dual-stack socket
	// - Multiple IPv4 servers can share the same pool entry
	// - Better compatibility with multi-server scenarios
	if (fromIs4 || fromIs4In6) && toIs6 {
		bindAddr = netip.AddrPortFrom(netip.IPv6Unspecified(), from.Port())
		return bindAddr, writeAddr
	}

	// Case 3: IPv6 bind with IPv4 target → IPv4-mapped writeAddr.
	// This allows the AF_INET6 socket to send to IPv4 destinations.
	if fromIs6 && (toIs4 || toIs4In6) {
		writeAddr = netip.AddrPortFrom(netip.AddrFrom16(toAddr.As16()), realTo.Port())
		return bindAddr, writeAddr
	}

	// Fast path: same-family or already optimal.
	// No conversion needed - return as-is.
	return bindAddr, writeAddr
}

// sendPkt sends a UDP packet to the destination.
// Parameters:
//   - log: logger for debug output
//   - data: packet data to send
//   - from: source address of the packet (for logging/metadata only)
//   - realTo: destination address where the packet should be sent
//   - afp: optional cached Anyfrom socket for Symmetric NAT sessions
func sendPkt(log *logrus.Logger, data []byte, from netip.AddrPort, realTo netip.AddrPort, afp **Anyfrom) (err error) {
	// Proxy chain support: Use original 'from' address as bindAddr to ensure
	// each server response gets its own UDP socket. This prevents response mixing
	// when multiple IPv6 servers would otherwise share [::]:port (wildcard binding).
	//
	// Cross-family handling ensures socket type matches write address family:
	// - IPv6->IPv4: Convert writeAddr to IPv4-mapped IPv6 for dual-stack socket
	// - IPv4->IPv6: Convert bindAddr to IPv4-mapped IPv6 to create IPv6 socket
	bindAddr, writeAddr := normalizeSendPktAddrFamily(from, realTo)

	// Try cached socket first (for Symmetric NAT sessions)
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
	_, err = uConn.WriteToUDPAddrPort(data, writeAddr)

	// Update caller's cached socket so future calls skip the pool lookup
	if afp != nil && err == nil {
		*afp = uConn
	}
	return err
}

func (c *ControlPlane) handlePkt(lConn *net.UDPConn, data []byte, src, pktDst, realDst netip.AddrPort, routingResult *bpfRoutingResult, flowDecision UdpFlowDecision, skipSniffing bool) (err error) {
	var realSrc netip.AddrPort
	var domain string
	var ueKey UdpEndpointKey
	realSrc = src

	// DNS Fast Path: Skip UdpEndpoint lookup for DNS traffic (port 53).
	// DNS is a stateless protocol and doesn't need the connection tracking
	// features that UdpEndpoint provides (designed for QUIC and other long-lived UDP).
	// This optimization eliminates a sync.Map.Load() operation for every DNS query.
	if realDst.Port() == 53 {
		// Potential DNS query - verify with DNS message parsing
		dnsMessage, _ := ChooseNatTimeout(data, true)
		if dnsMessage != nil {
			// Confirmed DNS request - take fast path
			if routingResult.Mark == 0 {
				routingResult.Mark = c.soMarkFromDae
			}
			req := &udpRequest{
				realSrc:       realSrc,
				realDst:       realDst,
				src:           src,
				lConn:         lConn,
				routingResult: routingResult,
			}
			if err := c.dnsController.Handle_(c.ctx, dnsMessage, req); err != nil {
				if stderrors.Is(err, ErrDNSQueryConcurrencyLimitExceeded) {
					return nil
				}
				// For DNS fast path, never leave client waiting on internal errors.
				// Respond with SERVFAIL so resolver can retry/fallback promptly.
				if sendErr := c.dnsController.sendDnsErrorResponse_(dnsMessage, dnsmessage.RcodeServerFailure, "ServeFail (dns fast path)", req, nil); sendErr != nil {
					return stderrors.Join(err, sendErr)
				}
				if c.log.IsLevelEnabled(logrus.DebugLevel) {
					c.log.WithError(err).Debug("DNS fast path failed; SERVFAIL sent")
				}
				return nil
			}
			return nil
		}
		// Not a valid DNS packet (port 53 but not DNS format) - fall through to normal UDP path
	}

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

			if !c.checkUdpEndpointHealth(ue, ueKey, true) {
				ue = nil
				ueExists = false
			} else {
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
					nt := udpEndpointNetworkType(ue)
					ue.Dialer.ReportAvailableTraffic(&nt)
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
		} else {
			// Non-fast-path existing endpoint. Check health.
			if !c.checkUdpEndpointHealth(ue, ueKey, false) {
				ue = nil
				ueExists = false
			}
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

			// Safe sniffing: wrap in a function to allow recover() from potential
			// sniffer panics (e.g., malformed packets or internal logic errors).
			func() {
				defer func() {
					if r := recover(); r != nil {
						if c.log.IsLevelEnabled(logrus.ErrorLevel) {
							c.log.WithFields(logrus.Fields{
								"src":   realSrc,
								"dst":   realDst,
								"panic": r,
							}).Error("UDP sniffing panicked; bypassing sniffing for this DCID")
						}
						MarkQuicDcidFailed(key)
						sniffer.Mu.Unlock()
					}
				}()

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
							return
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
					return
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
			}()
			if sniffer.NeedMore() {
				return nil
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
	var excludedDialer *dialer.Dialer
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
					Excluded:    excludedDialer,
				}

				res, err := c.chooseProxyDialer(ctx, dialParam)
				if err != nil {
					if res != nil && res.Outbound != nil && stderrors.Is(err, ob.ErrNoAliveDialer) {
						c.logNoAliveDialerLimited(
							res.Outbound,
							res.Outbound.GetSelectionPolicy(),
							res.OrigNetworkType,
							res.SelectionNetworkTypeObj,
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
					Excluded:      excludedDialer,
				}, nil
			},
		})
		if err != nil {
			if stderrors.Is(err, ob.ErrNoAliveDialer) {
				// Already emitted a rate-limited diagnostic log above.
				return nil
			}
			if allowConnectionErrorLog("handlePktGetOrCreate", time.Now()) {
				return fmt.Errorf("failed to GetOrCreate: %w", err)
			}
			return nil
		}
	}

	// If the udp endpoint has been not alive, remove it from pool and get a new one.
	if !isNew && ue.Outbound.GetSelectionPolicy() != consts.DialerSelectionPolicy_Fixed && !ue.Dialer.MustGetAlive(networkType) {

		// Optimization: For QUIC/WebRTC, do not aggressively remove endpoint on hot path
		// just because one health check failed. Let the idle timeout or explicit write error
		// handle it to prevent flapping. Only remove if this was a DNS-type endpoint which
		// is more sensitive to staleness.
		if c.log.IsLevelEnabled(logrus.DebugLevel) {
			c.log.WithFields(logrus.Fields{
				"src":     RefineSourceToShow(realSrc, realDst.Addr()),
				"network": networkType.String(),
				"dialer":  ue.Dialer.Property().Name,
				"retry":   retry,
			}).Debugln("Old udp endpoint was not alive and removed.")
		}
		// Exclude the dead dialer to force selection of a different one on retry.
		excludedDialer = ue.Dialer
		_ = DefaultUdpEndpointPool.Remove(ueKey, ue)
		retry++
		goto getNew
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
			nt := udpEndpointNetworkType(ue)
			if !errors.IsUDPEndpointNormalClose(err) {
				ue.Dialer.ReportUnavailable(&nt, fmt.Errorf("udp endpoint write failed: %w", err))
			}
			// Ensure the failed dialer is excluded in the immediate retry if it was a real failure.
			// For normal closures, we still remove the endpoint but don't penalize the dialer.
			if !errors.IsUDPEndpointNormalClose(err) {
				excludedDialer = ue.Dialer
			}
			_ = DefaultUdpEndpointPool.Remove(ueKey, ue)
			retry++
			goto getNew
		}
		packetIndex++
	}
	nt := udpEndpointNetworkType(ue)
	ue.Dialer.ReportAvailableTraffic(&nt)

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
