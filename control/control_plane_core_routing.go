/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"errors"
	"fmt"
	"net/netip"
	"os"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// deleteTCFiltersByHandle removes every filter with the exact handle regardless
// of its priority. Older dae versions left priority unset on dae0 hooks, so the
// kernel assigned a different priority on each reload and template deletion
// with priority zero could not find the stale filter.
func deleteTCFiltersByHandle(link netlink.Link, parent, handle uint32) error {
	if link == nil {
		return fmt.Errorf("delete TC filter %#x: nil link", handle)
	}
	filters, err := listTCFilters(link, parent)
	if err != nil {
		if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ESRCH) || errors.Is(err, unix.ENODEV) {
			return nil
		}
		return err
	}
	var errs []error
	for _, filter := range filters {
		attrs := filter.Attrs()
		if attrs == nil || attrs.Handle != handle {
			continue
		}
		if err := deleteTCFilter(filter); err != nil &&
			!os.IsNotExist(err) &&
			!errors.Is(err, unix.ENOENT) &&
			!errors.Is(err, unix.ESRCH) &&
			!errors.Is(err, unix.ENODEV) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// extractIpsFromDnsCache returns the unique, valid non-unspecified IP addresses
// contained in the A/AAAA records of a DNS cache entry.
func extractIPsFromDnsCache(cache *DnsCache) []netip.Addr {
	if cache == nil || len(cache.Answer) == 0 {
		return nil
	}
	ips := make([]netip.Addr, 0, len(cache.Answer))
	for _, ans := range cache.Answer {
		ip, ok := dnsAnswerIP(ans)
		if !ok || ip.IsUnspecified() {
			continue
		}
		ips = append(ips, ip)
	}
	return ips
}

// BatchUpdateDomainRouting update bpf map domain_routing. Since one IP may have multiple domains, this function should
// be invoked every A/AAAA-record lookup.
func (c *controlPlaneCore) BatchUpdateDomainRouting(cache *DnsCache) error {
	if c == nil || cache == nil {
		return nil
	}
	snapshot, err := buildDomainRoutingOwnerSnapshot(cache)
	if err != nil {
		return err
	}
	bpf := c.PeekBpf()
	if bpf == nil {
		return nil
	}
	slot := c.RoutingEpochSlot()
	if !validRoutingEpochSlot(slot) {
		return fmt.Errorf("invalid domain routing epoch slot %d", slot)
	}
	c.domainRoutingProjectionMu[slot].RLock()
	defer c.domainRoutingProjectionMu[slot].RUnlock()
	tracker := c.domainRoutingTrackerForSlot(slot)
	if tracker == nil {
		return fmt.Errorf("domain routing tracker slot %d is unavailable", slot)
	}
	return tracker.syncOwnerForSlot(bpf.DomainRoutingMap, slot, cache.RouteOwnerKey, snapshot)
}

// BatchRemoveDomainRouting remove bpf map domain_routing.
func (c *controlPlaneCore) BatchRemoveDomainRouting(cache *DnsCache) error {
	if c == nil || cache == nil {
		return nil
	}
	bpf := c.PeekBpf()
	if bpf == nil {
		return nil
	}
	slot := c.RoutingEpochSlot()
	if !validRoutingEpochSlot(slot) {
		return fmt.Errorf("invalid domain routing epoch slot %d", slot)
	}
	c.domainRoutingProjectionMu[slot].RLock()
	defer c.domainRoutingProjectionMu[slot].RUnlock()
	tracker := c.domainRoutingTrackerForSlot(slot)
	if tracker == nil {
		return fmt.Errorf("domain routing tracker slot %d is unavailable", slot)
	}
	return tracker.syncOwnerForSlot(bpf.DomainRoutingMap, slot, cache.RouteOwnerKey, domainRoutingOwnerSnapshot{})
}

func (c *controlPlaneCore) RetainUdpConnStateTuples(keys []bpfTuplesKey) {
	if tracker := c.getUdpConnStateTracker(); tracker != nil {
		tracker.Retain(keys)
	}
}

func (c *controlPlaneCore) TransferRetainedUdpConnStateTuplesFrom(previous udpConnStateOwner, keys []bpfTuplesKey) {
	if c == nil || previous == nil || previous == c || len(keys) == 0 {
		return
	}

	previousCore, ok := previous.(*controlPlaneCore)
	if !ok || previousCore == nil {
		return
	}

	currentTracker := c.getUdpConnStateTracker()
	previousTracker := previousCore.getUdpConnStateTracker()
	if currentTracker == nil || previousTracker == nil || currentTracker == previousTracker {
		return
	}

	currentTracker.Retain(keys)
	previousTracker.Forget(keys)
}

func (c *controlPlaneCore) ReleaseUdpConnStateTuples(keys []bpfTuplesKey) error {
	if c == nil || len(keys) == 0 {
		return nil
	}
	tracker := c.getUdpConnStateTracker()
	if tracker == nil {
		bpf := c.PeekBpf()
		if bpf == nil || bpf.ConnStateMap == nil {
			return nil
		}
		_, err := BpfMapBatchDelete(bpf.ConnStateMap, keys)
		return err
	}
	releases := tracker.BeginRelease(keys)
	defer tracker.FinalizeRelease(releases)
	if len(releases) == 0 {
		return nil
	}
	bpf := c.PeekBpf()
	if bpf == nil || bpf.ConnStateMap == nil {
		return nil
	}
	deleteKeys := make([]bpfTuplesKey, 0, len(releases))
	for _, release := range releases {
		deleteKeys = append(deleteKeys, release.key)
	}
	_, err := BpfMapBatchDelete(bpf.ConnStateMap, deleteKeys)
	return err
}
