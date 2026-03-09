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
	"time"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	daerrors "github.com/daeuniverse/dae/common/errors"
	ob "github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/sniffing"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/sirupsen/logrus"
)

func buildTCPLinkLogFields(res *proxyDialResult, dialParam *proxyDialParam, dst netip.AddrPort, domain string, annotateOffload bool, offloaded bool, offloadReason string) logrus.Fields {
	fields := logrus.Fields{
		"network":  res.OrigNetworkType,
		"outbound": res.Outbound.Name,
		"policy":   res.Outbound.GetSelectionPolicy(),
		"dialer":   res.Dialer.Property().Name,
		"sniffed":  domain,
		"ip":       RefineAddrPortToShow(dst),
		"dscp":     dialParam.Dscp,
		"pname":    ProcessName2String(dialParam.ProcessName[:]),
		"mac":      Mac2String(dialParam.Mac[:]),
	}
	if !annotateOffload {
		return fields
	}
	fields["ebpf_offload"] = offloaded
	if !offloaded && offloadReason != "" {
		fields["ebpf_offload_reason"] = offloadReason
	}
	return fields
}

func (c *ControlPlane) handleConn(ctx context.Context, lConn net.Conn) (err error) {
	defer lConn.Close()

	// Get tuples and outbound first so we can decide whether sniffing is needed.
	// Converge IPv4-mapped IPv6 addresses before looking up eBPF routing tuples.
	src := common.ConvergeAddrPort(lConn.RemoteAddr().(*net.TCPAddr).AddrPort())
	dst := common.ConvergeAddrPort(lConn.LocalAddr().(*net.TCPAddr).AddrPort())
	routingResult, err := c.core.RetrieveRoutingResult(src, dst, consts.IPPROTO_TCP)
	if err != nil {
		if stderrors.Is(err, ebpf.ErrKeyNotExist) {
			// Graceful fallback: routing tuple might be unavailable due to race/window
			// during connection handoff. Continue with userspace routing instead of
			// aborting the TCP connection.
			routingResult = &bpfRoutingResult{
				Outbound: uint8(consts.OutboundControlPlaneRouting),
			}
			if c.log.IsLevelEnabled(logrus.DebugLevel) {
				c.log.WithFields(logrus.Fields{
					"src": src.String(),
					"dst": dst.String(),
				}).WithError(err).Debug("Routing tuple missing; fallback to userspace routing")
			}
		} else {
			return fmt.Errorf("failed to retrieve target info %v: %v", dst.String(), err)
		}
	}

	var (
		domain             string
		lRelayConn         netproxy.Conn = lConn
		tcpSniffAttempted  bool
		clientPayloadReady = true
	)
	if c.shouldTryTcpSniff(dst, routingResult) {
		tcpSniffAttempted = true
		cacheKey := newTcpSniffNegKey(dst, routingResult)
		now := time.Now()
		if c.shouldSkipTcpSniffByNegativeCache(cacheKey, now) {
			if c.log.IsLevelEnabled(logrus.TraceLevel) {
				c.log.WithFields(logrus.Fields{
					"src": src.String(),
					"dst": dst.String(),
				}).Trace("Skip TCP sniffing by negative cache")
			}
		} else {
			probeConn, prefetched, ready, probeErr := prefetchForTcpSniff(lConn, tcpSniffFirstPayloadWait, tcpSniffPrefetchBytes)
			if probeErr != nil {
				return probeErr
			}
			clientPayloadReady = ready
			if !ready {
				// No early payload; treat as non-sniffable to avoid stalling server-first/established flows.
				c.noteTcpSniffFailure(cacheKey, now)
				lRelayConn = probeConn
			} else if !isLikelyHttpOrTLSPrefix(prefetched) {
				// Fast reject for non HTTP/TLS prefixes.
				c.noteTcpSniffFailure(cacheKey, now)
				lRelayConn = probeConn
			} else {
				// ConnSniffer should be used later, so we cannot close it now.
				sniffer := sniffing.NewConnSniffer(probeConn, c.sniffingTimeout)
				defer sniffer.Close()
				lRelayConn = sniffer

				domain, err = sniffer.SniffTcp()
				if err != nil {
					// Best practice:
					// 1) Sniffing-domain errors (not applicable/need more/not found) are expected.
					// 2) Ignorable connection errors (EOF/reset/timeout) should not break relay.
					// 3) Other unexpected errors should fail fast instead of being silently hidden.
					if !sniffing.IsSniffingError(err) && !daerrors.IsIgnorableConnectionError(err) {
						return err
					}
					if !sniffing.IsSniffingError(err) {
						if c.log.IsLevelEnabled(logrus.DebugLevel) {
							c.log.WithError(err).WithFields(logrus.Fields{
								"src": src.String(),
								"dst": dst.String(),
							}).Debug("TCP sniffing encountered ignorable connection error; continue relay")
						}
					}
					// Non-sniffable or ignorable cases suppress repeated sniff attempts.
					c.noteTcpSniffFailure(cacheKey, now)
					domain = ""
				} else {
					// Any success means this flow signature is sniffable; clear suppression.
					c.clearTcpSniffNegative(cacheKey)
				}
			}
		}
	}

	dialParam := &proxyDialParam{
		Outbound:    consts.OutboundIndex(routingResult.Outbound),
		Domain:      domain,
		Mac:         routingResult.Mac,
		ProcessName: routingResult.Pname,
		Dscp:        routingResult.Dscp,
		Src:         src,
		Dest:        dst,
		Mark:        routingResult.Mark,
		Network:     "tcp",
	}
	// Dial and relay.
	rConn, res, err := c.routeDial(ctx, dialParam)
	if err != nil {
		if res != nil && res.Outbound != nil && stderrors.Is(err, ob.ErrNoAliveDialer) {
			c.logNoAliveDialerLimited(
				res.Outbound.Name,
				res.Outbound.GetSelectionPolicy(),
				res.OrigNetworkType,
				res.SelectionNetworkType,
				src,
				dst,
				domain,
				res.IsDialIp,
			)
			return nil
		}
		if res != nil && res.Outbound != nil && stderrors.Is(err, ErrFixedTcpDialConcurrencyLimitExceeded) {
			c.logFixedTcpDialLimitLimited(res, src, dst, domain)
			return nil
		}
		return fmt.Errorf("failed to dial %v: %w", dst, err)
	}
	defer rConn.Close()

	offloaded := false
	offloadReason := tcpRelayPrefetchOffloadSkipReason(tcpSniffAttempted, clientPayloadReady)
	var offloadErr error
	if offloadReason == "" {
		offloaded, offloadReason, offloadErr = c.tryOffloadTCPRelay(ctx, lRelayConn, rConn)
	}
	if offloadErr != nil {
		return fmt.Errorf("handleTCP offloaded relay error: %w", offloadErr)
	}
	annotateOffload := canAnnotateTCPRelayOffload(rConn)

	if c.log.IsLevelEnabled(logrus.DebugLevel) {
		c.log.WithFields(buildTCPLinkLogFields(res, dialParam, dst, domain, annotateOffload, offloaded, offloadReason)).Debugf("%v <-> %v", RefineSourceToShow(src, dst.Addr()), res.DialTarget)
	}

	if offloaded {
		return nil
	}

	if err = RelayTCP(lRelayConn, rConn); err != nil {
		if daerrors.IsIgnorableTCPRelayError(err) {
			return nil // ignore normal connection closure errors
		}
		return fmt.Errorf("handleTCP relay error: %w", err)
	}

	if c.log.IsLevelEnabled(logrus.DebugLevel) {
		c.log.WithFields(logrus.Fields{
			"src": src.String(),
			"dst": dst.String(),
		}).Debug("TCP relay completed")
	}

	return nil
}

type RouteDialParam struct {
	Outbound    consts.OutboundIndex
	Domain      string
	Mac         [6]uint8
	Dscp        uint8
	ProcessName [16]uint8
	Src         netip.AddrPort
	Dest        netip.AddrPort
	Mark        uint32
}

func (c *ControlPlane) RouteDialTcp(ctx context.Context, p *RouteDialParam) (conn netproxy.Conn, err error) {
	dialParam := &proxyDialParam{
		Outbound:    p.Outbound,
		Domain:      p.Domain,
		Mac:         p.Mac,
		Dscp:        p.Dscp,
		ProcessName: p.ProcessName,
		Src:         p.Src,
		Dest:        p.Dest,
		Mark:        p.Mark,
		Network:     "tcp",
	}
	conn, _, err = c.routeDial(ctx, dialParam)
	return conn, err
}

type WriteCloser interface {
	CloseWrite() error
}

// RelayTCP copies data bidirectionally between two connections.
// A relayCore orchestrates shared cancellation and force-close fallback.
func RelayTCP(lConn, rConn netproxy.Conn) (err error) {
	core := newRelayCore(lConn, rConn, defaultRelayCopyEngine{})
	return core.run(context.Background())
}
