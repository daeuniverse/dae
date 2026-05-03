/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"fmt"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common"
)

type domainRoutingOwnerSnapshot struct {
	bitmap bpfDomainRouting
	ips    map[[4]uint32]struct{}
}

type domainRoutingIPState struct {
	owners map[string]bpfDomainRouting
	merged bpfDomainRouting
}

type domainRoutingTracker struct {
	mu     sync.Mutex
	owners map[string]domainRoutingOwnerSnapshot
	ips    map[[4]uint32]*domainRoutingIPState
}

func newDomainRoutingTracker() *domainRoutingTracker {
	return &domainRoutingTracker{
		owners: make(map[string]domainRoutingOwnerSnapshot),
		ips:    make(map[[4]uint32]*domainRoutingIPState),
	}
}

func cloneDomainRoutingIPSet(src map[[4]uint32]struct{}) map[[4]uint32]struct{} {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[[4]uint32]struct{}, len(src))
	for key := range src {
		dst[key] = struct{}{}
	}
	return dst
}

func isZeroDomainRoutingBitmap(bitmap bpfDomainRouting) bool {
	for _, word := range bitmap.Bitmap {
		if word != 0 {
			return false
		}
	}
	return true
}

func orDomainRoutingBitmap(dst *bpfDomainRouting, src bpfDomainRouting) {
	for i := range dst.Bitmap {
		dst.Bitmap[i] |= src.Bitmap[i]
	}
}

func mergeDomainRoutingOwnerBitmaps(owners map[string]bpfDomainRouting) bpfDomainRouting {
	var merged bpfDomainRouting
	for _, bitmap := range owners {
		orDomainRoutingBitmap(&merged, bitmap)
	}
	return merged
}

func buildDomainRoutingOwnerSnapshot(cache *DnsCache) (domainRoutingOwnerSnapshot, error) {
	if cache == nil {
		return domainRoutingOwnerSnapshot{}, nil
	}
	if len(cache.DomainBitmap) != len(bpfDomainRouting{}.Bitmap) {
		return domainRoutingOwnerSnapshot{}, fmt.Errorf("domain bitmap length not sync with kern program")
	}
	var snapshot domainRoutingOwnerSnapshot
	copy(snapshot.bitmap.Bitmap[:], cache.DomainBitmap)
	ips := extractIPsFromDnsCache(cache)
	if len(ips) == 0 {
		return snapshot, nil
	}
	snapshot.ips = make(map[[4]uint32]struct{}, len(ips))
	for _, ip := range ips {
		ip6 := ip.As16()
		snapshot.ips[common.Ipv6ByteSliceToUint32Array(ip6[:])] = struct{}{}
	}
	return snapshot, nil
}

func (t *domainRoutingTracker) desiredBitmapForKeyLocked(
	key [4]uint32,
	ownerKey string,
	snapshot domainRoutingOwnerSnapshot,
) (bitmap bpfDomainRouting, present bool) {
	if state := t.ips[key]; state != nil {
		for existingOwnerKey, existingBitmap := range state.owners {
			if existingOwnerKey == ownerKey {
				continue
			}
			orDomainRoutingBitmap(&bitmap, existingBitmap)
			present = true
		}
	}
	if len(snapshot.ips) > 0 && !isZeroDomainRoutingBitmap(snapshot.bitmap) {
		if _, ok := snapshot.ips[key]; ok {
			orDomainRoutingBitmap(&bitmap, snapshot.bitmap)
			present = true
		}
	}
	return bitmap, present
}

func (t *domainRoutingTracker) applyOwnerSnapshotLocked(ownerKey string, snapshot domainRoutingOwnerSnapshot) {
	if ownerKey == "" {
		return
	}
	if old, ok := t.owners[ownerKey]; ok {
		for key := range old.ips {
			state := t.ips[key]
			if state == nil {
				continue
			}
			delete(state.owners, ownerKey)
			if len(state.owners) == 0 {
				delete(t.ips, key)
				continue
			}
			state.merged = mergeDomainRoutingOwnerBitmaps(state.owners)
		}
		delete(t.owners, ownerKey)
	}
	if len(snapshot.ips) == 0 || isZeroDomainRoutingBitmap(snapshot.bitmap) {
		return
	}
	cloned := domainRoutingOwnerSnapshot{
		bitmap: snapshot.bitmap,
		ips:    cloneDomainRoutingIPSet(snapshot.ips),
	}
	t.owners[ownerKey] = cloned
	for key := range cloned.ips {
		state := t.ips[key]
		if state == nil {
			state = &domainRoutingIPState{
				owners: make(map[string]bpfDomainRouting),
			}
			t.ips[key] = state
		}
		state.owners[ownerKey] = cloned.bitmap
		state.merged = mergeDomainRoutingOwnerBitmaps(state.owners)
	}
}

func (t *domainRoutingTracker) syncOwner(
	m *ebpf.Map,
	ownerKey string,
	snapshot domainRoutingOwnerSnapshot,
) error {
	if ownerKey == "" {
		return fmt.Errorf("empty domain routing owner key")
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	oldSnapshot := t.owners[ownerKey]
	affected := make(map[[4]uint32]struct{}, len(oldSnapshot.ips)+len(snapshot.ips))
	for key := range oldSnapshot.ips {
		affected[key] = struct{}{}
	}
	for key := range snapshot.ips {
		affected[key] = struct{}{}
	}

	keysToUpdate := make([][4]uint32, 0, len(affected))
	valuesToUpdate := make([]bpfDomainRouting, 0, len(affected))
	keysToDelete := make([][4]uint32, 0, len(affected))

	for key := range affected {
		desiredBitmap, present := t.desiredBitmapForKeyLocked(key, ownerKey, snapshot)
		current := t.ips[key]
		switch {
		case !present:
			if current != nil {
				keysToDelete = append(keysToDelete, key)
			}
		case current == nil || current.merged != desiredBitmap:
			keysToUpdate = append(keysToUpdate, key)
			valuesToUpdate = append(valuesToUpdate, desiredBitmap)
		}
	}

	if m != nil {
		if len(keysToUpdate) > 0 {
			if _, err := BpfMapBatchUpdate(m, keysToUpdate, valuesToUpdate, &ebpf.BatchOptions{
				ElemFlags: uint64(ebpf.UpdateAny),
			}); err != nil {
				return fmt.Errorf("update domain_routing_map: %w", err)
			}
		}
		if len(keysToDelete) > 0 {
			if _, err := BpfMapBatchDelete(m, keysToDelete); err != nil {
				return fmt.Errorf("delete domain_routing_map: %w", err)
			}
		}
	}

	t.applyOwnerSnapshotLocked(ownerKey, snapshot)
	return nil
}
