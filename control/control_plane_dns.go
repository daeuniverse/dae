/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"fmt"
	"time"
)

func (c *ControlPlane) CloneDnsCache() map[string]*DnsCache {
	if c == nil {
		return nil
	}
	return c.cloneDnsCache()
}

// StreamDnsCacheForReload visits the current cache without building a second
// map or retaining another set of cache wrappers. Membership is stable for the
// duration of the visit; cache payloads are immutable after publication.
func (c *ControlPlane) StreamDnsCacheForReload(visit func(string, *DnsCache) error) error {
	if c == nil || visit == nil {
		return nil
	}
	controller := c.ActiveDnsController()
	if controller == nil || controller.dnsControllerStore == nil {
		return nil
	}
	controller.cacheProjectionMu.RLock()
	defer controller.cacheProjectionMu.RUnlock()

	var visitErr error
	controller.dnsCache.Range(func(key, value any) bool {
		cacheKey, keyOK := key.(string)
		cache, cacheOK := value.(*DnsCache)
		if !keyOK || !cacheOK || cache == nil {
			return true
		}
		visitErr = visit(cacheKey, cache)
		return visitErr == nil
	})
	return visitErr
}

// SetReloadDnsCacheSource installs the previous generation's cache snapshot
// source for a prepared shared-BPF reload. It is consumed at datapath commit.
func (c *ControlPlane) SetReloadDnsCacheSource(source func() map[string]*DnsCache) {
	if c == nil {
		return
	}
	c.dnsReloadCacheSourceMu.Lock()
	c.dnsReloadCacheSource = source
	c.dnsReloadCacheStreamSource = nil
	c.dnsReloadCacheStreamSourceHash = [32]byte{}
	c.dnsReloadCacheSourceMu.Unlock()
}

// SetReloadDnsCacheStreamSource installs a zero-copy cache visitor for a
// prepared routing-epoch cutover. sourceHash identifies the cached bitmaps.
func (c *ControlPlane) SetReloadDnsCacheStreamSource(
	source func(func(string, *DnsCache) error) error,
	sourceHash [32]byte,
) {
	if c == nil {
		return
	}
	c.dnsReloadCacheSourceMu.Lock()
	c.dnsReloadCacheSource = nil
	c.dnsReloadCacheStreamSource = source
	c.dnsReloadCacheStreamSourceHash = sourceHash
	c.dnsReloadCacheSourceMu.Unlock()
}

// ClearReloadDnsCacheSource releases the previous generation cache source.
func (c *ControlPlane) ClearReloadDnsCacheSource() {
	if c == nil {
		return
	}
	c.dnsReloadCacheSourceMu.Lock()
	c.dnsReloadCacheSource = nil
	c.dnsReloadCacheStreamSource = nil
	c.dnsReloadCacheStreamSourceHash = [32]byte{}
	c.dnsReloadCacheSourceMu.Unlock()
}

func (c *ControlPlane) cloneDnsReloadCacheForCutover() (map[string]*DnsCache, bool) {
	if c == nil || !c.sharedBpfReload || !c.preparedDatapathCommit {
		return nil, false
	}
	c.dnsReloadCacheSourceMu.Lock()
	defer c.dnsReloadCacheSourceMu.Unlock()
	if c.dnsReloadCacheSource == nil {
		return nil, false
	}
	return c.dnsReloadCacheSource(), true
}

func (c *ControlPlane) dnsReloadCacheStreamForCutover() (
	func(func(string, *DnsCache) error) error,
	[32]byte,
	bool,
) {
	if c == nil || !c.sharedBpfReload || !c.preparedDatapathCommit {
		return nil, [32]byte{}, false
	}
	c.dnsReloadCacheSourceMu.Lock()
	defer c.dnsReloadCacheSourceMu.Unlock()
	if c.dnsReloadCacheStreamSource == nil {
		return nil, [32]byte{}, false
	}
	return c.dnsReloadCacheStreamSource, c.dnsReloadCacheStreamSourceHash, true
}

func (c *ControlPlane) projectDnsReloadCacheStream(
	source func(func(string, *DnsCache) error) error,
	reuseBitmap bool,
) (int, error) {
	if c == nil || source == nil || c.core == nil {
		return 0, nil
	}
	start := time.Now()
	count := 0
	err := source(func(cacheKey string, cache *DnsCache) error {
		if cache == nil {
			return nil
		}
		bitmap := cache.DomainBitmap
		if !reuseBitmap || len(bitmap) != len(bpfDomainRouting{}.Bitmap) {
			if c.routingMatcher == nil || c.routingMatcher.domainMatcher == nil {
				return fmt.Errorf("project DNS reload cache without domain matcher")
			}
			bitmap = c.routingMatcher.domainMatcher.MatchDomainBitmap(cache.GetFqdn())
		}
		ownerKey := cache.RouteOwnerKey
		if ownerKey == "" {
			ownerKey = cacheKey
		}
		projected := DnsCache{
			RouteOwnerKey:        ownerKey,
			RouteProjectionEpoch: uint64(c.PolicyEpoch()),
			DomainBitmap:         bitmap,
			Answer:               cache.Answer,
		}
		if err := c.core.BatchUpdateDomainRouting(&projected); err != nil {
			return fmt.Errorf("project streamed DNS cache %q: %w", cacheKey, err)
		}
		count++
		return nil
	})
	if err != nil {
		return count, err
	}
	if count > 0 && c.log != nil {
		c.log.Infof("Projected %d DNS cache entries from previous control plane in %v", count, time.Since(start))
	}
	return count, nil
}

// refreshDnsReloadCacheForCutover replaces the early preparation snapshot
// with one taken immediately before the target routing epoch is published.
func (c *ControlPlane) refreshDnsReloadCacheForCutover() (bool, error) {
	streamSource, streamSourceHash, streamOK := c.dnsReloadCacheStreamForCutover()
	cache, cacheOK := c.cloneDnsReloadCacheForCutover()
	if !streamOK && !cacheOK {
		return false, nil
	}
	if c.core == nil {
		return false, fmt.Errorf("refresh DNS reload cache without control-plane core")
	}
	if err := c.core.clearDomainRoutingSlot(c.core.RoutingEpochSlot()); err != nil {
		return false, fmt.Errorf("clear target domain routing slot: %w", err)
	}
	if streamOK {
		// Release any preparation-time fallback before walking the authoritative
		// cache. The stream itself retains no map or wrapper copies.
		c.pendingDnsReloadCache = nil
		reuseBitmap := streamSourceHash != ([32]byte{}) && streamSourceHash == c.PolicyIdentity().Hash()
		if _, err := c.projectDnsReloadCacheStream(streamSource, reuseBitmap); err != nil {
			return false, err
		}
		return true, nil
	}
	c.pendingDnsReloadCache = cache
	return true, nil
}

func (c *ControlPlane) ActiveDnsController() *DnsController {
	if c == nil {
		return nil
	}
	return c.activeController(&c.dnsHandoffController)
}

func (c *ControlPlane) dnsRequestContext(ctx context.Context, controller *DnsController) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if c == nil || controller == nil || controller == c.dnsController {
		return ctx
	}
	if c.dnsHandoffController.Load() == controller {
		return controller.baseContext()
	}
	return ctx
}

// SharesActiveDnsControllerWith reports whether both control planes currently
// resolve DNS through the same active controller instance.
func (c *ControlPlane) SharesActiveDnsControllerWith(other *ControlPlane) bool {
	if c == nil || other == nil {
		return false
	}
	controller := c.ActiveDnsController()
	return controller != nil && controller == other.ActiveDnsController()
}

func (c *ControlPlane) clearDNSHandoffControllerIfMatch(controller *DnsController) (*DnsController, bool) {
	if c == nil {
		return nil, false
	}
	c.dnsHandoffMu.Lock()
	defer c.dnsHandoffMu.Unlock()

	current := c.dnsHandoffController.Load()
	if current != controller {
		return current, false
	}
	c.dnsHandoffController.Store(nil)
	return current, true
}

// takeDNSHandoffController detaches and returns the slotted handoff controller,
// if any. The slot only tracks the reference; the controller itself is owned by
// the caller that installed it, so detaching never closes it.
func (c *ControlPlane) takeDNSHandoffController() *DnsController {
	if c == nil {
		return nil
	}
	c.dnsHandoffMu.Lock()
	defer c.dnsHandoffMu.Unlock()

	controller := c.dnsHandoffController.Load()
	c.dnsHandoffController.Store(nil)
	return controller
}

// SetDNSHandoffController publishes the controller the next generation should
// take over. The previous slot value is not closed here: ownership stays with
// whoever installed it.
func (c *ControlPlane) SetDNSHandoffController(controller *DnsController) {
	if c == nil {
		return
	}
	c.dnsHandoffMu.Lock()
	defer c.dnsHandoffMu.Unlock()
	c.dnsHandoffController.Store(controller)
}
