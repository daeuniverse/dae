/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

// This file is the userspace half of the opt-in direct-traffic observer.
//
// A direct (non-proxied) flow never reaches userspace, so the relay byte
// counters cannot see it. control/kern/direct_stats.c attaches an
// observation-only TC program beside tproxy on the WAN/LAN interfaces dae
// already owns; this file loads that object, stages its hooks, and reads the
// per-CPU counters back. Nothing here runs unless api.direct_stats is on, so a
// deployment that does not ask for the figure pays nothing for it.
//
// The observer is read-only over conn_state_map: it decides whether a flow is
// direct by reading the flag tproxy already set, and it never writes a mark or
// a verdict. Its own maps are the counters and a NAT-independent flow index.
//
// The count is a lower bound, and the omissions are deliberate rather than
// papered over:
//   - the observer runs before tproxy, so a packet whose flow has no state yet
//     is not counted; the first packet of every flow is always missed;
//   - the figures are link bytes (L2 header included on *_l2 attachments), not
//     the relay's payload bytes;
//   - TCP retransmissions are counted once per transmitted packet;
//   - ICMP, non-initial fragments and other non-TCP/UDP pass-throughs are not
//     counted;
//   - a flow that predates a restart has no conn_state at all;
//   - the download side of a flow that never sent a second upload packet (a
//     one-request UDP exchange) is not recognised on a NAT gateway;
//   - the flow index is an LRU: an idle flow that gets evicted loses the reply
//     side until its upload is seen again.

import (
	"fmt"
	"sync/atomic"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/vishvananda/netlink"
)

// directStatsEnabled is the process-wide switch for direct-traffic observation.
// It is read whenever LAN/WAN hooks are staged, so it follows the active
// configuration across datapath reloads.
var directStatsEnabled atomic.Bool

// directStatsPriority must be lower than the tproxy hook priority so the
// observer runs before tproxy can return TC_ACT_OK for a direct pass-through.
const directStatsPriority = uint16(1)

// Counter keys mirror enum direct_stats_key in control/kern/direct_stats.c.
const (
	directStatsKeyUpBytes uint32 = iota
	directStatsKeyUpPackets
	directStatsKeyDownBytes
	directStatsKeyDownPackets
)

// DirectStatsCounters is the cumulative direct-traffic observation. Up is LAN
// or host to WAN; down is WAN to LAN or host.
type DirectStatsCounters struct {
	UpBytes     uint64
	UpPackets   uint64
	DownBytes   uint64
	DownPackets uint64
}

// directStatsObserver owns the loaded observer object. connState pins the
// conn_state_map the object was loaded against, so a new datapath generation
// forces a reload instead of counting against a replaced map.
type directStatsObserver struct {
	coll      *ebpf.Collection
	connState *ebpf.Map
}

// ConfigureDirectStats sets whether interfaces bound from now on include the
// direct-traffic observer. The control plane calls it from api.direct_stats
// before each build.
func ConfigureDirectStats(enabled bool) {
	directStatsEnabled.Store(enabled)
}

// DirectStatsEnabled reports the current observation switch.
func DirectStatsEnabled() bool {
	return directStatsEnabled.Load()
}

// DirectStatsSnapshot returns counters summed across CPUs. It returns zeros
// when observation is off or has never been loaded.
func (c *ControlPlane) DirectStatsSnapshot() (DirectStatsCounters, error) {
	if c == nil || c.core == nil {
		return DirectStatsCounters{}, nil
	}
	return c.core.readDirectStats()
}

// stageDirectStatsHooks attaches the observer to a link dae already binds.
// Every role gets the ingress observer (a LAN client upload or a WAN reply);
// only the WAN role gets the egress observer, whose ingress_ifindex guard
// leaves just locally generated sockets. On a dual-role interface the same
// ingress spec is staged twice, which is an idempotent upsert.
func (c *controlPlaneCore) stageDirectStatsHooks(link netlink.Link, layer2 bool, wan bool) error {
	if !directStatsEnabled.Load() {
		return nil
	}
	coll, err := c.ensureDirectStatsCollection()
	if err != nil {
		// Observation is optional: a hook that cannot load must never break
		// forwarding, so the bind continues and the API reports zeros.
		c.log.Warnf("direct stats observer unavailable: %v", err)
		return nil
	}
	ingressName := "direct_stats_ingress_l3"
	egressName := "direct_stats_egress_l3"
	if layer2 {
		ingressName = "direct_stats_ingress_l2"
		egressName = "direct_stats_egress_l2"
	}
	ingress := coll.Programs[ingressName]
	if ingress == nil {
		c.log.Warnf("direct stats observer has no %q program; skipping hooks", ingressName)
		return nil
	}
	if err := c.stageTCHook(makeTCHookSpec(tcHookScopeHost, link, tcHookIngress, directStatsPriority, 0x2023, ingress, consts.AppName+"_"+ingressName, nil)); err != nil {
		return fmt.Errorf("install direct stats ingress hook: %w", err)
	}
	if !wan {
		return nil
	}
	egress := coll.Programs[egressName]
	if egress == nil {
		c.log.Warnf("direct stats observer has no %q program; skipping egress hook", egressName)
		return nil
	}
	if err := c.stageTCHook(makeTCHookSpec(tcHookScopeHost, link, tcHookEgress, directStatsPriority, 0x2023, egress, consts.AppName+"_"+egressName, nil)); err != nil {
		return fmt.Errorf("install direct stats egress hook: %w", err)
	}
	return nil
}

// ensureDirectStatsCollection loads the observer object once per core and
// reuses the live conn_state_map, so the observer reads tproxy's flow state.
func (c *controlPlaneCore) ensureDirectStatsCollection() (*ebpf.Collection, error) {
	c.directStatsMu.Lock()
	defer c.directStatsMu.Unlock()
	bpf := c.bpf.Load()
	if bpf == nil || bpf.ConnStateMap == nil {
		return nil, fmt.Errorf("conn_state_map is unavailable")
	}
	if c.directStats != nil && c.directStats.connState == bpf.ConnStateMap {
		return c.directStats.coll, nil
	}
	info, err := bpf.ConnStateMap.Info()
	if err != nil {
		return nil, fmt.Errorf("query conn_state_map: %w", err)
	}
	spec, err := loadDirectstats()
	if err != nil {
		return nil, fmt.Errorf("load direct stats spec: %w", err)
	}
	connStateSpec := spec.Maps["conn_state_map"]
	if connStateSpec == nil {
		return nil, fmt.Errorf("direct stats spec has no conn_state_map")
	}
	connStateSpec.MaxEntries = info.MaxEntries
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{"conn_state_map": bpf.ConnStateMap},
	})
	if err != nil {
		return nil, fmt.Errorf("create direct stats collection: %w", err)
	}
	if c.directStats != nil {
		c.directStats.coll.Close()
	}
	c.directStats = &directStatsObserver{coll: coll, connState: bpf.ConnStateMap}
	c.addDeferFunc(func() error {
		coll.Close()
		return nil
	})
	return coll, nil
}

func (c *controlPlaneCore) readDirectStats() (DirectStatsCounters, error) {
	c.directStatsMu.Lock()
	observer := c.directStats
	c.directStatsMu.Unlock()
	if observer == nil {
		return DirectStatsCounters{}, nil
	}
	m := observer.coll.Maps["direct_stats_map"]
	if m == nil {
		return DirectStatsCounters{}, fmt.Errorf("direct_stats_map is missing")
	}
	ncpu, err := ebpf.PossibleCPU()
	if err != nil {
		return DirectStatsCounters{}, err
	}
	sum := func(key uint32) (uint64, error) {
		values := make([]uint64, ncpu)
		if err := m.Lookup(key, &values); err != nil {
			return 0, err
		}
		var total uint64
		for _, v := range values {
			total += v
		}
		return total, nil
	}
	var out DirectStatsCounters
	for _, field := range []struct {
		key uint32
		dst *uint64
	}{
		{directStatsKeyUpBytes, &out.UpBytes},
		{directStatsKeyUpPackets, &out.UpPackets},
		{directStatsKeyDownBytes, &out.DownBytes},
		{directStatsKeyDownPackets, &out.DownPackets},
	} {
		v, err := sum(field.key)
		if err != nil {
			return DirectStatsCounters{}, fmt.Errorf("read direct stats key %d: %w", field.key, err)
		}
		*field.dst = v
	}
	return out, nil
}
