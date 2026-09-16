/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"fmt"
	"time"

	"github.com/daeuniverse/dae/component/dns"
	dnsmessage "github.com/miekg/dns"
)

type dnsControllerRuntimeState struct {
	routing                 *dns.Dns
	lifecycleCtx            context.Context
	cacheAccessCallback     func(cache *DnsCache) (err error)
	cacheDeleteCallback     func(cacheKey string, cache *DnsCache) (err error)
	newCache                func(fqdn string, answers, ns, extra []dnsmessage.RR, deadline time.Time, originalDeadline time.Time) (cache *DnsCache, err error)
	routeProjectionEpoch    uint64
	routeProjectionHash     [32]byte
	projectCacheRoute       func(cache *DnsCache) []uint32
	bestDialerChooser       func(ctx context.Context, snapshot DnsRequestSnapshot, upstream *dns.Upstream) (*dialArgument, error)
	timeoutExceedCallback   func(dialArgument *dialArgument, err error)
	fixedDomainTtl          map[string]int
	qtypePrefer             uint16
	optimisticCacheEnabled  bool
	optimisticCacheTtl      int
	optimisticStaleReplyTtl int
	maxCacheSize            int
}

func normalizeDnsRuntimeBehavior(option *DnsControllerOption) (qtypePrefer uint16, optimisticCacheEnabled bool, optimisticCacheTtl int, optimisticStaleReplyTtl int, maxCacheSize int, err error) {
	if option == nil {
		option = &DnsControllerOption{}
	}
	qtypePrefer, err = parseIpVersionPreference(option.IpVersionPrefer)
	if err != nil {
		return 0, false, 0, 0, 0, err
	}
	optimisticCacheTtl = option.OptimisticCacheTtl
	optimisticStaleReplyTtl = option.OptimisticStaleReplyTtl
	maxCacheSize = option.MaxCacheSize
	if optimisticCacheTtl == 0 && maxCacheSize == 0 {
		optimisticCacheTtl = 60
	}
	return qtypePrefer, option.OptimisticCache, optimisticCacheTtl, optimisticStaleReplyTtl, maxCacheSize, nil
}

func (c *DnsController) currentQtypePrefer() uint16 {
	rt := c.runtime()
	if rt == nil {
		return 0
	}
	return rt.qtypePrefer
}

func (c *DnsController) currentOptimisticCacheConfig() (enabled bool, ttl int, staleReplyTtl int, maxCacheSize int) {
	rt := c.runtime()
	if rt == nil {
		return false, 0, 0, 0
	}
	return rt.optimisticCacheEnabled, rt.optimisticCacheTtl, rt.optimisticStaleReplyTtl, rt.maxCacheSize
}

// ReuseForReload updates the current facade to the replacement generation's
// runtime and returns a fresh facade that shares the same long-lived store.
// The shared store carries DNS cache, forwarders, janitors, async BPF workers,
// and the current runtime/config across reloads. The old control plane publishes
// the new facade as a handoff bridge so ActiveDnsController observes the
// replacement runtime without a nil window during reload retirement.
func (c *DnsController) ReuseForReload(option *DnsControllerOption, routing *dns.Dns) (*DnsController, error) {
	if c == nil {
		return nil, nil
	}
	c.ensureStoreForReload()
	previousRuntime := c.runtime()
	projectionUnchanged := previousRuntime != nil && option != nil &&
		option.RouteProjectionHash != ([32]byte{}) &&
		previousRuntime.routeProjectionHash == option.RouteProjectionHash
	if projectionUnchanged {
		// Projection epochs identify bitmap content, not control-plane lifetime.
		// Keeping the old epoch makes every existing cache wrapper valid for the
		// replacement runtime, avoiding an O(cache size) reload walk.
		adjustedOption := *option
		adjustedOption.RouteProjectionEpoch = previousRuntime.routeProjectionEpoch
		option = &adjustedOption
	}
	if err := c.TryUpdateRuntime(option, routing); err != nil {
		return nil, err
	}
	if !projectionUnchanged {
		c.reprojectCachedRoutes(c.runtime())
	}
	if err := c.ResetDnsForwarders(); err != nil && c.log != nil {
		c.log.WithError(err).Warn("failed to retire stale DNS forwarders during reload reuse")
	}
	return c.sharedStoreFacade(), nil
}

func parseIpVersionPreference(prefer int) (uint16, error) {
	switch prefer := IpVersionPrefer(prefer); prefer {
	case IpVersionPrefer_No:
		return 0, nil
	case IpVersionPrefer_4:
		return dnsmessage.TypeA, nil
	case IpVersionPrefer_6:
		return dnsmessage.TypeAAAA, nil
	default:
		return 0, fmt.Errorf("unknown preference: %v", prefer)
	}
}

func (c *DnsController) updateRuntime(option *DnsControllerOption, routing *dns.Dns) error {
	if c == nil {
		return nil
	}
	c.requireStore()
	if option == nil {
		option = &DnsControllerOption{}
	}
	qtypePrefer, optimisticCacheEnabled, optimisticCacheTtl, optimisticStaleReplyTtl, maxCacheSize, err := normalizeDnsRuntimeBehavior(option)
	if err != nil {
		return err
	}
	// c.log is deliberately NOT reassigned here: the controller is published
	// while request handlers and the janitor run, and an unlocked field write
	// would be a data race. Reloads never introduce a new logger instance
	// anyway — the daemon mutates the single shared logger in place (see
	// cmd/run_reload_worker.go logger.SetLogger), so the construction-time
	// pointer stays correct across generations.
	lifecycleCtx := option.LifecycleContext
	if lifecycleCtx == nil {
		lifecycleCtx = context.Background()
	}
	runtimeState := &dnsControllerRuntimeState{
		routing:                 routing,
		lifecycleCtx:            lifecycleCtx,
		cacheAccessCallback:     option.CacheAccessCallback,
		cacheDeleteCallback:     option.CacheDeleteCallback,
		newCache:                option.NewCache,
		routeProjectionEpoch:    option.RouteProjectionEpoch,
		routeProjectionHash:     option.RouteProjectionHash,
		projectCacheRoute:       option.ProjectCacheRoute,
		bestDialerChooser:       option.BestDialerChooser,
		timeoutExceedCallback:   option.TimeoutExceedCallback,
		fixedDomainTtl:          option.FixedDomainTtl,
		qtypePrefer:             qtypePrefer,
		optimisticCacheEnabled:  optimisticCacheEnabled,
		optimisticCacheTtl:      optimisticCacheTtl,
		optimisticStaleReplyTtl: optimisticStaleReplyTtl,
		maxCacheSize:            maxCacheSize,
	}
	c.runtimeMu.Lock()
	c.runtimeState.Store(runtimeState)
	c.runtimeMu.Unlock()
	if maxCacheSize > 0 && c.dnsCacheSize.Load() > int64(maxCacheSize) {
		c.cacheProjectionMu.Lock()
		c.trimDnsCacheToSizeLocked(maxCacheSize)
		c.cacheProjectionMu.Unlock()
	}
	return nil
}

func (c *DnsController) runtime() *dnsControllerRuntimeState {
	if c == nil || c.dnsControllerStore == nil {
		return nil
	}
	return c.runtimeState.Load()
}

// TryUpdateRuntime updates generation-local DNS runtime state and reports
// invalid behavior config via error.
func (c *DnsController) TryUpdateRuntime(option *DnsControllerOption, routing *dns.Dns) error {
	return c.updateRuntime(option, routing)
}
