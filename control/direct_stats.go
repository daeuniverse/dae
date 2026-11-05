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
// a verdict. Its only map is the per-CPU counter array.
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
//   - on a NAT gateway, replies whose post-SNAT tuple cannot match conn_state
//     are omitted because the reply packet does not identify its LAN host.

import (
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common/consts"
	internal "github.com/daeuniverse/dae/pkg/ebpf_internal"
	"github.com/sirupsen/logrus"
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

type directStatsBridgeRole struct {
	wan  bool
	dual bool
}

// ConfigureDirectStats sets whether interfaces bound from now on include the
// direct-traffic observer. The control plane calls it from api.direct_stats
// before each build.
func ConfigureDirectStats(enabled bool) {
	directStatsEnabled.Store(enabled)
}

// directStatsKernelVersion is replaceable so tests can model older kernels.
var directStatsKernelVersion = internal.KernelVersion

// directStatsKernelSupported reports whether the running kernel has TCX. The
// observer is only offered there: it hooks bridge ports and link ordering
// relative to tproxy through TCX, and the classic-TC fallback has no ordering
// or qdisc guarantees on those ports.
func directStatsKernelSupported() (bool, string) {
	version, err := directStatsKernelVersion()
	if err != nil {
		return false, "unknown"
	}
	return !version.Less(consts.TCXFeatureVersion), version.String()
}

// ResolveDirectStats returns whether the direct-traffic observer may be turned
// on. A request on a kernel without TCX is refused with a warning, so the
// optional observer can never stop the data plane from starting.
func ResolveDirectStats(log *logrus.Logger, requested bool) bool {
	if !requested {
		return false
	}
	if ok, version := directStatsKernelSupported(); !ok {
		if log != nil {
			log.Warnf("api.direct_stats requires TCX (Linux %v or later) but the running kernel is %v; direct traffic observation is disabled", consts.TCXFeatureVersion.String(), version)
		}
		return false
	}
	return true
}

// DirectStatsEnabled reports the current observation switch.
func DirectStatsEnabled() bool {
	return directStatsEnabled.Load()
}

// directStatsTotals holds the counters of generations that already closed, and
// the observers that are still live. The observer's map belongs to one
// generation, so a reload used to restart the totals while counter_since
// (process-level) stayed. During a staged reload the outgoing generation keeps
// counting until it drains, so the snapshot sums the retired total and every
// live observer: reading only the newest one made the figure dip.
var directStatsTotals struct {
	mu      sync.Mutex
	retired DirectStatsCounters
	live    map[*directStatsObserver]struct{}
}

func registerDirectStatsObserver(observer *directStatsObserver) {
	directStatsTotals.mu.Lock()
	defer directStatsTotals.mu.Unlock()
	if directStatsTotals.live == nil {
		directStatsTotals.live = make(map[*directStatsObserver]struct{})
	}
	directStatsTotals.live[observer] = struct{}{}
}

// retireDirectStatsObserver folds a closing observer's counters into the
// retired total and drops it from the live set in one step, so a concurrent
// snapshot sees its counters exactly once. Retiring twice is a no-op.
func retireDirectStatsObserver(observer *directStatsObserver) {
	directStatsTotals.mu.Lock()
	defer directStatsTotals.mu.Unlock()
	if _, ok := directStatsTotals.live[observer]; !ok {
		return
	}
	delete(directStatsTotals.live, observer)
	if counters, err := readDirectStatsFrom(observer); err == nil {
		directStatsTotals.retired = addDirectStats(directStatsTotals.retired, counters)
	}
}

func addDirectStats(a, b DirectStatsCounters) DirectStatsCounters {
	return DirectStatsCounters{
		UpBytes:     a.UpBytes + b.UpBytes,
		UpPackets:   a.UpPackets + b.UpPackets,
		DownBytes:   a.DownBytes + b.DownBytes,
		DownPackets: a.DownPackets + b.DownPackets,
	}
}

func accumulateDirectStats(counters DirectStatsCounters) {
	directStatsTotals.mu.Lock()
	defer directStatsTotals.mu.Unlock()
	directStatsTotals.retired = addDirectStats(directStatsTotals.retired, counters)
}

func retiredDirectStats() DirectStatsCounters {
	directStatsTotals.mu.Lock()
	defer directStatsTotals.mu.Unlock()
	return directStatsTotals.retired
}

// DirectStatsSnapshot returns counters summed across CPUs and generations. It
// returns zeros when observation is off or has never been loaded.
func (c *ControlPlane) DirectStatsSnapshot() (DirectStatsCounters, error) {
	if c == nil || c.core == nil {
		return DirectStatsCounters{}, nil
	}
	directStatsTotals.mu.Lock()
	defer directStatsTotals.mu.Unlock()
	total := directStatsTotals.retired
	for observer := range directStatsTotals.live {
		current, err := readDirectStatsFrom(observer)
		if err != nil {
			return DirectStatsCounters{}, err
		}
		total = addDirectStats(total, current)
	}
	return total, nil
}

// stageDirectStatsHooks attaches the observer to a link dae already binds.
// Every role gets an ingress observer; only the WAN role gets the egress
// observer, whose ingress_ifindex guard leaves just locally generated sockets.
// The ingress variant follows the role so a hook never runs lookups for a
// direction it cannot see: LAN-only watches client uploads, WAN-only watches
// replies, and an interface bound with both roles runs the combined program.
// On a dual-role interface both binds stage the same spec, which is an
// idempotent upsert.
//
// A bridge gets the observer on its member devices instead of on the master for
// ingress: traffic is received on the port, and routed traffic then crosses the
// master's ingress too, so observing both would count it twice. Only the
// observer is expanded: tproxy keeps
// running where it is, because running the redirect path twice on one packet
// (once on the port, once on the master) is not an idempotent operation.
func (c *controlPlaneCore) stageDirectStatsHooks(link netlink.Link, layer2 bool, wan bool, dual bool) error {
	if !directStatsEnabled.Load() {
		return nil
	}
	if link.Type() == "bridge" {
		c.directStatsBridgeMu.Lock()
		if c.directStatsBridges == nil {
			c.directStatsBridges = make(map[int]directStatsBridgeRole)
		}
		c.directStatsBridges[link.Attrs().Index] = directStatsBridgeRole{wan: wan, dual: dual}
		c.directStatsBridgeMu.Unlock()
	}
	ports, err := bridgePorts(link)
	if err != nil {
		// Observation is optional; a failed enumeration must not break binding.
		c.log.WithError(err).Warnf("direct stats observer: cannot list bridge ports of %v", link.Attrs().Name)
		ports = nil
	}
	var observed []netlink.Link
	for _, port := range ports {
		if port.Attrs().Name != HostVethName {
			observed = append(observed, port)
		}
	}
	// Traffic routed through a bridge enters the port and then the master, and
	// both hooks share the counters. Ingress is therefore observed on the ports
	// alone; the master keeps only the WAN egress hook, which sees locally
	// generated packets that never cross a port's ingress.
	masterIngress := len(observed) == 0
	if err := c.stageDirectStatsHookForLink(link, layer2, wan, dual, masterIngress, true); err != nil {
		return err
	}
	for _, port := range observed {
		// Bridge ports are Ethernet devices, whatever the master reports.
		portLayer2 := port.Attrs().EncapType == "ether"
		c.log.Infof("Bind direct stats observer to bridge port %v of %v", port.Attrs().Name, link.Attrs().Name)
		// Best effort, like every other bind: the clsact qdisc may exist.
		_ = c.addQdisc(port)
		if err := c.stageDirectStatsHookForLink(port, portLayer2, wan, dual, true, false); err != nil {
			return err
		}
	}
	return nil
}

func (c *controlPlaneCore) attachDirectStatsBridgePort(link netlink.Link) {
	if link == nil || link.Attrs() == nil || link.Attrs().MasterIndex == 0 {
		return
	}
	c.directStatsBridgeMu.RLock()
	role, ok := c.directStatsBridges[link.Attrs().MasterIndex]
	c.directStatsBridgeMu.RUnlock()
	if !ok || !c.beginBpfHookAttach() {
		return
	}
	defer c.endBpfHookAttach()
	_ = c.addQdisc(link)
	layer2 := link.Attrs().EncapType == "ether"
	if err := c.stageDirectStatsHookForLink(link, layer2, role.wan, role.dual, true, false); err != nil {
		c.log.WithError(err).Warnf("direct stats observer: cannot attach to bridge port %v", link.Attrs().Name)
	}
}

// stageDirectStatsHookForLink stages the observer hooks for one device.
func (c *controlPlaneCore) stageDirectStatsHookForLink(link netlink.Link, layer2 bool, wan bool, dual bool, ingressHook bool, egressHook bool) error {
	coll, err := c.ensureDirectStatsCollection()
	if err != nil {
		// Observation is optional: a hook that cannot load must never break
		// forwarding, so the bind continues and the API reports zeros.
		c.log.Warnf("direct stats observer unavailable: %v", err)
		return nil
	}
	ingressName, egressName := directStatsProgramNames(layer2, wan, dual)
	ingress := coll.Programs[ingressName]
	if ingress == nil {
		c.log.Warnf("direct stats observer has no %q program; skipping hooks", ingressName)
		return nil
	}
	if ingressHook {
		if err := c.stageTCHook(makeTCHookSpec(tcHookScopeHost, link, tcHookIngress, directStatsPriority, 0x2023, ingress, consts.AppName+"_"+ingressName, nil)); err != nil {
			return fmt.Errorf("install direct stats ingress hook: %w", err)
		}
	}
	if !wan || !egressHook {
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

// directStatsProgramNames picks the observer programs for an interface role.
func directStatsProgramNames(layer2, wan, dual bool) (ingress, egress string) {
	layer := "l3"
	if layer2 {
		layer = "l2"
	}
	role := "lan_"
	switch {
	case dual:
		role = ""
	case wan:
		role = "wan_"
	}
	return "direct_stats_" + role + "ingress_" + layer, "direct_stats_egress_" + layer
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
		// Fold the replaced observer's totals in before its map goes away.
		retireDirectStatsObserver(c.directStats)
		c.directStats.coll.Close()
	}
	observer := &directStatsObserver{coll: coll, connState: bpf.ConnStateMap}
	registerDirectStatsObserver(observer)
	c.directStats = observer
	c.addDeferFunc(func() error {
		// This generation's counters leave with its map; retire them first so
		// the process-level figure survives the reload. The observer is
		// captured because c.directStats may already name a successor.
		retireDirectStatsObserver(observer)
		coll.Close()
		return nil
	})
	return coll, nil
}

func readDirectStatsFrom(observer *directStatsObserver) (DirectStatsCounters, error) {
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
