/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"sync"

	"golang.org/x/sync/singleflight"
)

// realDomainSetCapacity bounds the confirmed-real set. Eviction is FIFO:
// evicting only costs one cheap re-probe of a domain, whereas an unbounded
// or probabilistic structure (the old bloom) degrades into permanent wrong
// answers once its false-positive rate climbs past its design point.
const realDomainSetCapacity = 8192

// controlPlaneRealDomainRuntime groups the real-domain detection state: the
// bounded FIFO confirmation set, negative caches, dialer selection snapshots,
// TCP sniff negative cache, and the negative-cache janitor lifecycle.
type controlPlaneRealDomainRuntime struct {
	muRealDomainSet   sync.RWMutex
	realDomainSet     map[string]struct{}
	realDomainOrd     []string
	realDomainNegSet  sync.Map // map[string]int64 (expiresAt unix nano)
	dnsDialerSnapshot sync.Map // map[dnsDialerSnapshotKey]*dnsDialerSnapshotEntry
	dnsDialerPenalty  sync.Map // map[dnsDialerPenaltyKey]*dnsDialerPenaltyEntry
	tcpSniffNegMu     sync.RWMutex
	tcpSniffNegSet    map[tcpSniffNegKey]tcpSniffNegEntry
	realDomainProbeS  singleflight.Group
	negJanitorStop    chan struct{}
	negJanitorDone    chan struct{}
	negJanitorOnce    sync.Once
}

func newControlPlaneRealDomainRuntime() controlPlaneRealDomainRuntime {
	return controlPlaneRealDomainRuntime{
		muRealDomainSet: sync.RWMutex{},
		realDomainSet:   make(map[string]struct{}, realDomainSetCapacity),
		realDomainOrd:   make([]string, 0, realDomainSetCapacity),
		tcpSniffNegSet:  make(map[tcpSniffNegKey]tcpSniffNegEntry),
		negJanitorStop:  make(chan struct{}),
		negJanitorDone:  make(chan struct{}),
	}
}

// rememberRealDomain records a confirmed-real domain under muRealDomainSet.
// Eviction is FIFO: an existing confirmation is left in place (no re-append),
// and overflowing inserts drop the oldest name.
func (c *controlPlaneRealDomainRuntime) rememberRealDomain(domain string) {
	if _, exists := c.realDomainSet[domain]; exists {
		return
	}
	if len(c.realDomainSet) >= realDomainSetCapacity && len(c.realDomainOrd) > 0 {
		evict := c.realDomainOrd[0]
		c.realDomainOrd = c.realDomainOrd[1:]
		delete(c.realDomainSet, evict)
	}
	c.realDomainSet[domain] = struct{}{}
	c.realDomainOrd = append(c.realDomainOrd, domain)
}
