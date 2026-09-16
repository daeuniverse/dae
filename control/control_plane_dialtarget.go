/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/sirupsen/logrus"
)

func (c *ControlPlane) ActivateCheck() {
	for _, g := range c.outbounds {
		// Only activate health checks for outbounds referenced by routing rules.
		// This significantly reduces startup time when subscription has many nodes
		// but only a few groups are actually used in routing.
		if _, referenced := c.referencedOutbounds[g.Name]; !referenced {
			c.log.Debugf("Skip health check for unreferenced outbound: %v", g.Name)
			continue
		}
		for _, d := range g.Dialers {
			// We only activate check of nodes that have a group.
			d.ActivateCheck()
		}
	}
}

// OnHealthCheckSuccess is called when a dialer passes health check.
// This clears the failed QUIC DCID cache since network conditions may have improved.
func (c *ControlPlane) OnHealthCheckSuccess() {
	ClearFailedQuicDcids()
}

func (c *ControlPlane) ChooseDialTarget(outbound consts.OutboundIndex, dst netip.AddrPort, domain string) (dialTarget string, shouldReroute bool, dialIp bool) {
	dialMode := consts.DialMode_Ip

	if !outbound.IsReserved() && domain != "" {
		switch c.dialMode {
		case consts.DialMode_Domain:
			// Avoid blocking probe for literal IP / host:port values.
			if isIPLikeDomain(domain) {
				break
			}
			if c.dnsController.HasDnsKnowledge(c.dnsController.cacheKey(domain, common.AddrToDnsType(dst.Addr()))) {
				// Has A/AAAA records. It is a real domain.
				dialMode = consts.DialMode_Domain
				shouldReroute = true
			} else {
				if known, real := c.lookupRealDomainCache(domain); known {
					if real {
						dialMode = consts.DialMode_Domain
						shouldReroute = true
					}
				} else {
					// Unknown domain on first hit: warm it asynchronously to avoid
					// blocking connection setup on webpage first paint path.
					c.triggerRealDomainProbe(domain)
				}
			}
		case consts.DialMode_DomainCao:
			shouldReroute = true
			fallthrough
		case consts.DialMode_DomainPlus:
			dialMode = consts.DialMode_Domain
		}
	}

	switch dialMode {
	case consts.DialMode_Ip:
		dialTarget = dst.String()
		dialIp = true
	case consts.DialMode_Domain:
		if strings.HasPrefix(domain, "[") && strings.HasSuffix(domain, "]") {
			// Sniffed domain may be like `[2606:4700:20::681a:d1f]`. We should remove the brackets.
			domain = domain[1 : len(domain)-1]
		}
		if _, err := netip.ParseAddr(domain); err == nil {
			// domain is IPv4 or IPv6 (has colon)
			dialTarget = net.JoinHostPort(domain, strconv.Itoa(int(dst.Port())))
			dialIp = true

		} else if _, _, err := net.SplitHostPort(domain); err == nil {
			// domain is already domain:port
			dialTarget = domain
		} else {
			dialTarget = net.JoinHostPort(domain, strconv.Itoa(int(dst.Port())))
		}
		if c.log.IsLevelEnabled(logrus.DebugLevel) {
			c.log.WithFields(logrus.Fields{
				"from": dst.String(),
				"to":   dialTarget,
			}).Debugln("Rewrite dial target to domain")
		}
	}
	return dialTarget, shouldReroute, dialIp
}

func (c *ControlPlane) lookupRealDomainCache(domain string) (known bool, real bool) {
	// Read-mostly fast path.
	c.muRealDomainSet.RLock()
	_, hit := c.realDomainSet[domain]
	c.muRealDomainSet.RUnlock()
	if hit {
		return true, true
	}

	// Negative-cache fast path.
	now := time.Now()
	if v, ok := c.realDomainNegSet.Load(domain); ok {
		expiresAt, _ := v.(int64)
		if now.UnixNano() < expiresAt {
			return true, false
		}
		c.realDomainNegSet.Delete(domain)
	}
	return false, false
}

func (c *ControlPlane) resolveBootstrapIp46(ctx context.Context, host string, network string) (*netutils.Ip46, error, error) {
	if len(c.bootstrapResolvers) == 0 {
		err := fmt.Errorf("bootstrap resolver is not configured")
		return &netutils.Ip46{}, err, err
	}
	return c.resolveIp46WithBootstrapResolvers(ctx, host, network, false, resolveIp46ForBootstrap)
}

func (c *ControlPlane) triggerRealDomainProbe(domain string) {
	if domain == "" || isIPLikeDomain(domain) {
		return
	}
	if known, _ := c.lookupRealDomainCache(domain); known {
		return
	}
	go func() {
		_, _, _ = c.realDomainProbeS.Do(domain, func() (any, error) {
			return c.probeAndUpdateRealDomain(domain), nil
		})
	}()
}

func (c *ControlPlane) probeAndUpdateRealDomain(domain string) bool {
	if known, real := c.lookupRealDomainCache(domain); known {
		return real
	}

	now := time.Now()
	// Use ControlPlane's context for real domain probe to enable proper cancel propagation
	ctx, cancel := context.WithTimeout(c.ctx, realDomainProbeTimeout)
	defer cancel()

	if len(c.bootstrapResolvers) == 0 {
		// Fail closed when no bootstrap resolver is configured — and memoize
		// the failure in the negative cache, otherwise every connection to
		// every unknown domain respawns a goroutine+singleflight probe that
		// can never succeed.
		c.realDomainNegSet.Store(domain, time.Now().Add(realDomainNegativeCacheTTL).UnixNano())
		return false
	}

	ip46, err4, err6 := c.resolveIp46WithBootstrapResolvers(
		ctx,
		domain,
		common.MagicNetwork("udp", c.soMarkFromDae, c.mptcp),
		true,
		resolveIp46ForRealDomainProbe,
	)
	if err4 != nil && err6 != nil {
		// Probe failed for both families; avoid sticky false negatives.
		return false
	}
	if !ip46.Ip4.IsValid() && !ip46.Ip6.IsValid() {
		c.realDomainNegSet.Store(domain, now.Add(realDomainNegativeCacheTTL).UnixNano())
		return false
	}

	c.muRealDomainSet.Lock()
	c.rememberRealDomain(domain)
	c.muRealDomainSet.Unlock()
	c.realDomainNegSet.Delete(domain)
	return true
}

func (c *ControlPlane) resolveIp46WithBootstrapResolvers(
	ctx context.Context,
	host string,
	network string,
	race bool,
	resolve func(context.Context, netproxy.Dialer, netip.AddrPort, string, string, bool) (*netutils.Ip46, error, error),
) (*netutils.Ip46, error, error) {
	if len(c.bootstrapResolvers) == 0 {
		err := fmt.Errorf("bootstrap resolver is not configured")
		return &netutils.Ip46{}, err, err
	}

	var firstErr4 error
	var firstErr6 error
	var lastNoRecord *netutils.Ip46
	var lastNoRecordErr4 error
	var lastNoRecordErr6 error
	for _, resolver := range c.bootstrapResolvers {
		ip46, err4, err6 := resolve(ctx, c.directDialer, resolver, host, network, race)
		if ip46 == nil {
			ip46 = &netutils.Ip46{}
		}
		if ip46.Ip4.IsValid() || ip46.Ip6.IsValid() {
			return ip46, err4, err6
		}
		if err4 == nil || err6 == nil {
			lastNoRecord = ip46
			lastNoRecordErr4 = err4
			lastNoRecordErr6 = err6
			continue
		}
		if firstErr4 == nil {
			firstErr4 = err4
		}
		if firstErr6 == nil {
			firstErr6 = err6
		}
	}
	if lastNoRecord != nil {
		return lastNoRecord, lastNoRecordErr4, lastNoRecordErr6
	}
	if firstErr4 == nil {
		firstErr4 = fmt.Errorf("bootstrap resolver failed")
	}
	if firstErr6 == nil {
		firstErr6 = firstErr4
	}
	return &netutils.Ip46{}, firstErr4, firstErr6
}

func (c *ControlPlane) cleanupNegativeCaches(now time.Time) {
	nowNano := now.UnixNano()

	// 1. Cleanup real domain negative cache
	c.realDomainNegSet.Range(func(key, value any) bool {
		expiresAt, ok := value.(int64)
		if !ok || nowNano >= expiresAt {
			c.realDomainNegSet.Delete(key)
		}
		return true
	})

	// 2. Cleanup QUIC DCID negative cache
	c.failedQuicDcidCache.CleanupExpired(now)

	// 3. Cleanup TCP sniff negative cache
	c.cleanupTcpSniffNegative(now)
}
