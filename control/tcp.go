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
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/component/sniffing"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/sirupsen/logrus"
)

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
		domain     string
		lRelayConn netproxy.Conn = lConn
	)
	if c.shouldTryTcpSniff(dst, routingResult) {
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
					if !sniffing.IsSniffingError(err) {
						return err
					}
					// Non-sniffable/timeout traffic should not pay repeated sniff cost.
					c.noteTcpSniffFailure(cacheKey, now)
					domain = ""
				} else {
					// Any success means this flow signature is sniffable; clear suppression.
					c.clearTcpSniffNegative(cacheKey)
				}
			}
		}
	}

	routeParam := &RouteDialParam{
		Outbound:    consts.OutboundIndex(routingResult.Outbound),
		Domain:      domain,
		Mac:         routingResult.Mac,
		ProcessName: routingResult.Pname,
		Dscp:        routingResult.Dscp,
		Src:         src,
		Dest:        dst,
		Mark:        routingResult.Mark,
	}
	// Dial and relay.
	rConn, err := c.RouteDialTcp(ctx, routeParam)
	if err != nil {
		return fmt.Errorf("failed to dial %v: %w", dst, err)
	}
	defer rConn.Close()

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
	if ctx == nil {
		ctx = context.Background()
	}

	outboundIndex := p.Outbound
	domain := p.Domain
	src := p.Src
	dst := p.Dest
	mark := p.Mark

	dialTarget, shouldReroute, dialIp := c.ChooseDialTarget(outboundIndex, dst, domain)
	if shouldReroute {
		outboundIndex = consts.OutboundControlPlaneRouting
	}

	switch outboundIndex {
	case consts.OutboundDirect:
	case consts.OutboundControlPlaneRouting:
		routingResult := &bpfRoutingResult{
			Mark:     mark,
			Mac:      p.Mac,
			Outbound: uint8(p.Outbound),
			Pname:    p.ProcessName,
			Dscp:     p.Dscp,
		}
		var newMark uint32
		if outboundIndex, newMark, _, err = c.Route(src, dst, domain, consts.L4ProtoType_TCP, routingResult); err != nil {
			return nil, err
		}
		mark = newMark

		if c.log.IsLevelEnabled(logrus.TraceLevel) {
			c.log.Tracef("outbound: %v => %v",
				consts.OutboundControlPlaneRouting.String(),
				outboundIndex.String(),
			)
		}
		// Reset dialTarget.
		dialTarget, _, dialIp = c.ChooseDialTarget(outboundIndex, dst, domain)
	default:
	}
	if mark == 0 {
		mark = c.soMarkFromDae
	}
	// TODO: Set-up ip to domain mapping and show domain if possible.
	if int(outboundIndex) >= len(c.outbounds) {
		if len(c.outbounds) == int(consts.OutboundUserDefinedMin) {
			return nil, fmt.Errorf("traffic was dropped due to no-load configuration")
		}
		return nil, fmt.Errorf("outbound id from bpf is out of range: %v not in [0, %v]", outboundIndex, len(c.outbounds)-1)
	}
	outbound := c.outbounds[outboundIndex]
	networkType := &dialer.NetworkType{
		L4Proto:   consts.L4ProtoStr_TCP,
		IpVersion: consts.IpVersionFromAddr(dst.Addr()),
		IsDns:     false,
	}
	strictIpVersion := dialIp
	d, _, err := outbound.Select(networkType, strictIpVersion)
	if err != nil {
		return nil, fmt.Errorf("failed to select dialer from group %v (%v): %w", outbound.Name, networkType.String(), err)
	}

	if c.log.IsLevelEnabled(logrus.InfoLevel) {
		c.log.WithFields(logrus.Fields{
			"network":  networkType.String(),
			"outbound": outbound.Name,
			"policy":   outbound.GetSelectionPolicy(),
			"dialer":   d.Property().Name,
			"sniffed":  domain,
			"ip":       RefineAddrPortToShow(dst),
			"dscp":     p.Dscp,
			"pname":    ProcessName2String(p.ProcessName[:]),
			"mac":      Mac2String(p.Mac[:]),
		}).Infof("%v <-> %v", RefineSourceToShow(src, dst.Addr()), dialTarget)
	}
	// Apply a dedicated dial timeout while still inheriting caller cancellation
	// (for shutdown/reload). The caller context no longer carries a per-connection
	// deadline, so sniffing latency does not reduce the dial budget.
	dialCtx, cancel := context.WithTimeout(ctx, consts.DefaultDialTimeout)
	defer cancel()
	return d.DialContext(dialCtx, common.MagicNetwork("tcp", mark, c.mptcp), dialTarget)
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
