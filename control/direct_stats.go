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
//     is not counted; the first state-creating packet of every flow is missed;
//   - the figures are link bytes (L2 header included on *_l2 attachments), not
//     the relay's payload bytes;
//   - TCP retransmissions are counted once per transmitted packet;
//   - ICMP, non-initial fragments and other non-TCP/UDP pass-throughs are not
//     counted;
//   - a flow that predates a restart has no conn_state at all, as does a flow
//     whose entry was dropped because conn_state_map was full;
//   - a local reply whose socket is wildcard-bound cannot be attributed to the
//     host and is therefore omitted from the WAN-ingress side;
//   - forwarded replies are counted on LAN egress after DNAT, so a masquerading
//     gateway no longer loses them; a dual-role interface has no separate LAN
//     egress hook and retains the pre-DNAT limitation;
//   - packets are skb counts: GSO/TSO/GRO can make one skb cover several wire
//     packets, so packet totals are lower than the on-wire count.

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common/consts"
	internal "github.com/daeuniverse/dae/pkg/ebpf_internal"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// directStatsEnabled is the process-wide switch for direct-traffic observation.
// It is read whenever LAN/WAN hooks are staged, so it follows the active
// configuration across datapath reloads.
var directStatsEnabled atomic.Bool

// directStatsPriority must be lower than the tproxy hook priority so the
// observer runs before tproxy can return TC_ACT_OK for a direct pass-through.
const directStatsPriority = uint16(1)

// Counter keys mirror enum direct_stats_key in control/kern/direct_stats.c.
// Each key owns both the byte and packet counters for one direction, so a
// direct packet performs a single counter-map lookup.
const (
	directStatsKeyUp uint32 = iota
	directStatsKeyDown
)

// directStatsValue mirrors struct direct_stats_value in the kernel object.
type directStatsValue struct {
	Bytes   uint64
	Packets uint64
}

// DirectStatsCounters is the cumulative direct-traffic observation. Up is LAN
// or host to WAN; down is WAN to LAN or host.
type DirectStatsCounters struct {
	UpBytes     uint64
	UpPackets   uint64
	DownBytes   uint64
	DownPackets uint64
}

// DirectStatsStatus describes whether the observer actually reached the
// datapath. Enabled only says the switch and the kernel support allowed it;
// Attached says at least one observer hook is installed, and LastError keeps
// the most recent load/attach failure instead of silently reporting zeros.
type DirectStatsStatus struct {
	Attached  bool
	Hooks     int
	LastError string
}

// directStatsSince records when the first observer counter map was created in
// this process. It is the process-level boundary exposed as counter_since; a
// reload keeps it, a process restart resets it.
var directStatsSince atomic.Int64

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

// directStatsPortRole remembers which bridge and role a member hook was
// installed for, so a runtime move can remove the old role (notably a LAN
// egress hook that the new WAN role does not need).
type directStatsPortRole struct {
	master int
	role   directStatsBridgeRole
}

// ConfigureDirectStats sets whether interfaces bound from now on include the
// direct-traffic observer. The control plane calls it from api.direct_stats
// before each build.
func ConfigureDirectStats(enabled bool) {
	directStatsEnabled.Store(enabled)
}

// directStatsKernelVersion is replaceable so tests can model older kernels.
var directStatsKernelVersion = internal.KernelVersion

// directStatsKernelSupported reports whether the running kernel has TCX. TCX is
// preferred because it gives the observer a stable position before tproxy and
// does not need a clsact qdisc on bridge ports; a kernel without it still has
// the classic TC fallback used by the hook set.
func directStatsKernelSupported() (bool, string) {
	version, err := directStatsKernelVersion()
	if err != nil {
		return false, "unknown"
	}
	return !version.Less(consts.TCXFeatureVersion), version.String()
}

// ResolveDirectStats returns whether the direct-traffic observer may be turned
// on. TCX is preferred because it gives the observer a stable position before
// tproxy and supports bridge ports without a clsact qdisc. A kernel without TCX
// still has classic TC, which the hook set already supports; refusals are
// therefore limited to "the operator did not ask for it". The classic fallback
// is logged because its filter ordering depends on the interface's existing
// tc filters and on the clsact qdisc being installable.
func ResolveDirectStats(log *logrus.Logger, requested bool) bool {
	if !requested {
		return false
	}
	if ok, version := directStatsKernelSupported(); ok {
		return true
	} else if log != nil {
		log.Warnf("api.direct_stats: kernel %v has no TCX (Linux %v or later); falling back to classic TC filters", version, consts.TCXFeatureVersion.String())
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
	if directStatsSince.Load() == 0 {
		directStatsSince.CompareAndSwap(0, time.Now().UnixNano())
	}
}

// DirectStatsCounterSince reports the process-level start of the direct
// counters, or the zero time if no observer has ever been registered.
func DirectStatsCounterSince() time.Time {
	nanos := directStatsSince.Load()
	if nanos == 0 {
		return time.Time{}
	}
	return time.Unix(0, nanos)
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

// DirectStatsSnapshot returns counters summed across CPUs and generations. A
// failed live observer is skipped so the readable generations still produce a
// figure; the joined error lets the API report a partial result instead of
// zeroing every counter.
func (c *ControlPlane) DirectStatsSnapshot() (DirectStatsCounters, error) {
	if c == nil || c.core == nil {
		return DirectStatsCounters{}, nil
	}
	directStatsTotals.mu.Lock()
	defer directStatsTotals.mu.Unlock()
	total := directStatsTotals.retired
	var errs []error
	for observer := range directStatsTotals.live {
		current, err := readDirectStatsFrom(observer)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		total = addDirectStats(total, current)
	}
	return total, errors.Join(errs...)
}

// DirectStatsStatus reports the active generation's attachment state. It is
// deliberately separate from DirectStatsEnabled: a switch that is on but whose
// hooks never loaded must not look like a healthy zero-traffic deployment.
func (c *ControlPlane) DirectStatsStatus() DirectStatsStatus {
	status := DirectStatsStatus{}
	if c == nil || c.core == nil {
		return status
	}
	status.Hooks = c.core.directStatsHookCount()
	status.Attached = status.Hooks > 0
	status.LastError = c.core.directStatsLastError()
	return status
}

// stageDirectStatsHooks attaches the observer to a link dae already binds.
// The ingress variant follows the role so a hook never runs lookups for a
// direction it cannot see: LAN-only watches client uploads, WAN-only watches
// replies delivered to local sockets, and an interface bound with both roles
// runs the combined program.
//
// Egress follows the role too. WAN egress watches locally generated uploads.
// LAN egress watches forwarded replies after DNAT, including replies on a
// masquerading gateway; the WAN-ingress program deliberately ignores forwarded
// replies so the two hooks cannot double count.
//
// A bridge gets the observer on its member devices. For ingress that avoids
// counting a routed packet on both the port and the master. For LAN egress the
// reply leaves through the member port, so the port is the only place where the
// post-DNAT packet is visible. A WAN bridge keeps its local-upload egress hook
// on the master, because locally generated packets never cross a port ingress.
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
	// A bridge forwards routed traffic through its member ports. Ingress is
	// therefore observed on the ports alone when they exist. LAN downloads are
	// also observed on the ports, because that is where the post-DNAT reply
	// leaves; the master keeps only the WAN local-upload egress hook. A LAN
	// bridge with no enumerated port keeps the master hooks as a fallback.
	masterIngress := len(observed) == 0
	masterEgress := wan || dual || len(observed) == 0
	if err := c.stageDirectStatsHookForLink(link, layer2, wan, dual, masterIngress, masterEgress); err != nil {
		return err
	}
	for _, port := range observed {
		// Bridge ports are Ethernet devices, whatever the master reports.
		portLayer2 := port.Attrs().EncapType == "ether"
		portIndex := port.Attrs().Index
		c.rememberDirectStatsPort(portIndex, link.Attrs().Index, directStatsBridgeRole{wan: wan, dual: dual})
		c.log.Debugf("Bind direct stats observer to bridge port %v of %v", port.Attrs().Name, link.Attrs().Name)
		// Best effort, like every other bind: the clsact qdisc may exist.
		_ = c.addQdisc(port)
		portEgress := !wan && !dual
		if err := c.stageDirectStatsHookForLink(port, portLayer2, wan, dual, true, portEgress); err != nil {
			return err
		}
	}
	return nil
}

func (c *controlPlaneCore) attachDirectStatsBridgePort(link netlink.Link) {
	if link == nil || link.Attrs() == nil || link.Attrs().MasterIndex == 0 ||
		link.Attrs().Name == HostVethName {
		return
	}
	c.directStatsBridgeMu.RLock()
	role, ok := c.directStatsBridges[link.Attrs().MasterIndex]
	c.directStatsBridgeMu.RUnlock()
	if !ok || !c.beginBpfHookAttach() {
		return
	}
	defer c.endBpfHookAttach()
	portIndex := link.Attrs().Index
	c.directStatsBridgeMu.Lock()
	previous, moved := c.directStatsPorts[portIndex]
	if c.directStatsPorts == nil {
		c.directStatsPorts = make(map[int]directStatsPortRole)
	}
	c.directStatsPorts[portIndex] = directStatsPortRole{master: link.Attrs().MasterIndex, role: role}
	c.directStatsBridgeMu.Unlock()
	if moved && (previous.master != link.Attrs().MasterIndex || previous.role != role) {
		// A port moving between bridges can change its role (LAN egress vs WAN
		// ingress only). Drop the old role's hooks first so an egress observer
		// from the previous bridge does not outlive the move.
		if err := c.removeDirectStatsHooksForInterface(portIndex); err != nil {
			c.recordDirectStatsError(fmt.Errorf("reset direct stats role for bridge port %v: %w", link.Attrs().Name, err))
			c.log.WithError(err).Warnf("direct stats observer: cannot reset role for bridge port %v", link.Attrs().Name)
		}
	}
	_ = c.addQdisc(link)
	layer2 := link.Attrs().EncapType == "ether"
	if err := c.stageDirectStatsHookForLink(link, layer2, role.wan, role.dual, true, !role.wan && !role.dual); err != nil {
		// The master fallback staged by the empty-bridge bind is the only
		// observer this bridge has while the port hook is missing. Removing it
		// would leave the bridge uncounted until the next reload, so keep it
		// and surface the failure instead.
		c.recordDirectStatsError(fmt.Errorf("observe bridge port %v: %w", link.Attrs().Name, err))
		c.log.WithError(err).Warnf("direct stats observer: cannot install hook on bridge port %v; keeping the master fallback", link.Attrs().Name)
		return
	}
	// The empty-bridge bind installed master ingress/egress as a fallback.
	// Once the first member is observed, the port is the only place a routed
	// packet or a DNAT reply crosses; keeping the master hooks would count the
	// same bytes twice. WAN and dual-role bridges keep the master egress hook
	// because locally generated packets never cross a port ingress.
	masterIndex := link.Attrs().MasterIndex
	if err := c.removeDirectStatsHooksOnInterface(masterIndex, "ingress"); err != nil {
		c.recordDirectStatsError(fmt.Errorf("remove direct stats master fallback on bridge %d: %w", masterIndex, err))
		c.log.WithError(err).Warnf("direct stats observer: cannot remove master ingress fallback on bridge %d", masterIndex)
	}
	if !role.wan && !role.dual {
		if err := c.removeDirectStatsHooksOnInterface(masterIndex, "egress"); err != nil {
			c.recordDirectStatsError(fmt.Errorf("remove direct stats master egress fallback on bridge %d: %w", masterIndex, err))
			c.log.WithError(err).Warnf("direct stats observer: cannot remove master egress fallback on bridge %d", masterIndex)
		}
	}
}

// removeDirectStatsHooksOnInterface removes the observer hooks for one
// direction on one device, leaving a WAN bridge's master egress hook and every
// tproxy hook untouched.
func (c *controlPlaneCore) removeDirectStatsHooksOnInterface(ifindex int, direction string) error {
	c.tcHookMu.Lock()
	hooks := c.tcHooks
	c.tcHookMu.Unlock()
	if hooks == nil {
		return nil
	}
	// The program name carries the interface role, so the fallback staged on an
	// empty bridge is direct_stats_ingress_* for a dual-role bridge but
	// direct_stats_lan_ingress_* or direct_stats_wan_ingress_* otherwise. A
	// single "ingress" prefix matched only the dual case and left a LAN/WAN
	// master hook counting the same bytes as the member port.
	for _, prefix := range directStatsProgramPrefixes(direction) {
		if err := hooks.removeHooksWithPrefix(tcHookScopeHost, ifindex, prefix); err != nil {
			return err
		}
	}
	return nil
}

func directStatsProgramPrefixes(direction string) []string {
	base := consts.AppName + "_direct_stats_"
	switch direction {
	case "ingress":
		return []string{base + "ingress_", base + "lan_ingress_", base + "wan_ingress_"}
	default:
		return []string{base + "egress_", base + "lan_egress_"}
	}
}

// rememberDirectStatsPort records that a bridge member is observed under the
// given master and role. It is written by both the bind path and the link
// watcher.
func (c *controlPlaneCore) rememberDirectStatsPort(portIndex, masterIndex int, role directStatsBridgeRole) {
	c.directStatsBridgeMu.Lock()
	if c.directStatsPorts == nil {
		c.directStatsPorts = make(map[int]directStatsPortRole)
	}
	c.directStatsPorts[portIndex] = directStatsPortRole{master: masterIndex, role: role}
	c.directStatsBridgeMu.Unlock()
}

// handleDirectStatsLinkUpdate reconciles bridge membership instead of only
// attaching to new ports. A port that leaves a bound bridge, or a bridge that
// disappears, must lose its observer; otherwise the hook keeps counting on an
// interface dae no longer owns and a recycled ifindex can be given the wrong
// role.
func (c *controlPlaneCore) handleDirectStatsLinkUpdate(upd netlink.LinkUpdate) {
	if upd.Link == nil || upd.Attrs() == nil {
		return
	}
	if upd.Header.Type == unix.RTM_DELLINK {
		if upd.Type() == "bridge" {
			c.forgetDirectStatsBridge(upd.Link.Attrs().Index)
		}
		c.forgetDirectStatsPort(upd.Link.Attrs().Index)
		return
	}
	c.attachDirectStatsBridgePort(upd.Link)
	c.detachDirectStatsBridgePort(upd.Link)
}

// detachDirectStatsBridgePort removes this port's observer when it is no longer
// a member of a bridge dae observes. A move to another observed bridge is kept:
// stageDirectStatsHooks/stageDirectStatsHookForLink updates the program in place.
func (c *controlPlaneCore) detachDirectStatsBridgePort(link netlink.Link) {
	if link == nil || link.Attrs() == nil {
		return
	}
	index := link.Attrs().Index
	c.directStatsBridgeMu.Lock()
	entry, observed := c.directStatsPorts[index]
	if !observed {
		c.directStatsBridgeMu.Unlock()
		return
	}
	if link.Attrs().MasterIndex != 0 {
		if role, tracked := c.directStatsBridges[link.Attrs().MasterIndex]; tracked {
			entry.master = link.Attrs().MasterIndex
			entry.role = role
			c.directStatsPorts[index] = entry
			c.directStatsBridgeMu.Unlock()
			return
		}
	}
	delete(c.directStatsPorts, index)
	c.directStatsBridgeMu.Unlock()

	if err := c.removeDirectStatsHooksForInterface(index); err != nil {
		// Keep the tracking entry so a later link event can retry; a failed
		// detach must not silently hide the hook forever.
		c.directStatsBridgeMu.Lock()
		if c.directStatsPorts == nil {
			c.directStatsPorts = make(map[int]directStatsPortRole)
		}
		c.directStatsPorts[index] = entry
		c.directStatsBridgeMu.Unlock()
		c.recordDirectStatsError(fmt.Errorf("detach direct stats from bridge port %v: %w", link.Attrs().Name, err))
		c.log.WithError(err).Warnf("direct stats observer: cannot detach from bridge port %v", link.Attrs().Name)
	}
}

// forgetDirectStatsPort drops one port no matter what its MasterIndex says.
// A DELLINK update can still carry the old master, so the normal stale-master
// check must not preserve a hook for a device that no longer exists.
func (c *controlPlaneCore) forgetDirectStatsPort(index int) {
	c.directStatsBridgeMu.Lock()
	_, observed := c.directStatsPorts[index]
	delete(c.directStatsPorts, index)
	c.directStatsBridgeMu.Unlock()
	if !observed {
		return
	}
	if err := c.removeDirectStatsHooksForInterface(index); err != nil {
		c.recordDirectStatsError(fmt.Errorf("detach direct stats from deleted bridge port %d: %w", index, err))
		c.log.WithError(err).Warnf("direct stats observer: cannot detach from deleted bridge port %d", index)
	}
}

// forgetDirectStatsBridge removes the role and every observed port of a bridge
// that was deleted. Ports may not receive their own event when the bridge goes
// away, so they are detached here by ifindex.
func (c *controlPlaneCore) forgetDirectStatsBridge(bridgeIndex int) {
	c.directStatsBridgeMu.Lock()
	delete(c.directStatsBridges, bridgeIndex)
	var ports []int
	for port, entry := range c.directStatsPorts {
		if entry.master == bridgeIndex {
			ports = append(ports, port)
			delete(c.directStatsPorts, port)
		}
	}
	c.directStatsBridgeMu.Unlock()
	for _, port := range ports {
		if err := c.removeDirectStatsHooksForInterface(port); err != nil {
			c.recordDirectStatsError(fmt.Errorf("detach direct stats from deleted bridge port %d: %w", port, err))
			c.log.WithError(err).Warnf("direct stats observer: cannot detach from deleted bridge port %d", port)
		}
	}
}

// removeDirectStatsHooksForInterface removes only dae's direct-stats hooks from
// one device. It deliberately does not use the generic removeInterface path:
// a bridge port is not a bound tproxy interface, and a future topology could
// have other hooks on that ifindex that must stay.
func (c *controlPlaneCore) removeDirectStatsHooksForInterface(ifindex int) error {
	c.tcHookMu.Lock()
	hooks := c.tcHooks
	c.tcHookMu.Unlock()
	if hooks == nil {
		return nil
	}
	return hooks.removeHooksWithPrefix(tcHookScopeHost, ifindex, consts.AppName+"_direct_stats_")
}

// countDirectStatsHooks reports how many observer hooks the current generation
// owns. It is a userspace map walk, not a kernel query.
func (c *controlPlaneCore) directStatsHookCount() int {
	c.tcHookMu.Lock()
	hooks := c.tcHooks
	c.tcHookMu.Unlock()
	if hooks == nil {
		return 0
	}
	return hooks.countHooksWithPrefix(consts.AppName + "_direct_stats_")
}

func (c *controlPlaneCore) recordDirectStatsError(err error) {
	if err == nil {
		return
	}
	c.directStatsStatusMu.Lock()
	c.directStatsStatusErr = err.Error()
	c.directStatsStatusMu.Unlock()
}

func (c *controlPlaneCore) directStatsLastError() string {
	c.directStatsStatusMu.Lock()
	defer c.directStatsStatusMu.Unlock()
	return c.directStatsStatusErr
}

// stageDirectStatsHookForLink stages the observer hooks for one device.
// Observation is optional: every load and attach failure is logged and
// recorded in the status, but never propagated into the bind transaction. A
// read-only observer must not be able to abort interface binding or startup.
func (c *controlPlaneCore) stageDirectStatsHookForLink(link netlink.Link, layer2 bool, wan bool, dual bool, ingressHook bool, egressHook bool) error {
	coll, err := c.ensureDirectStatsCollection()
	if err != nil {
		c.recordDirectStatsError(err)
		c.log.Warnf("direct stats observer unavailable on %v: %v", link.Attrs().Name, err)
		return nil
	}
	ingressName, egressName := directStatsProgramNames(layer2, wan, dual)
	if ingressHook {
		ingress := coll.Programs[ingressName]
		if ingress == nil {
			c.recordDirectStatsError(fmt.Errorf("direct stats observer has no %q program", ingressName))
			c.log.Warnf("direct stats observer has no %q program; skipping ingress hook on %v", ingressName, link.Attrs().Name)
		} else {
			spec := makeTCHookSpec(tcHookScopeHost, link, tcHookIngress, directStatsPriority, 0x2023, ingress, consts.AppName+"_"+ingressName, nil)
			spec.Optional = true
			spec.OnError = func(err error) {
				c.recordDirectStatsError(fmt.Errorf("install direct stats ingress hook on %v: %w", link.Attrs().Name, err))
			}
			if err := c.stageTCHook(spec); err != nil {
				c.recordDirectStatsError(fmt.Errorf("install direct stats ingress hook on %v: %w", link.Attrs().Name, err))
				c.log.WithError(err).Warnf("direct stats observer: cannot install ingress hook on %v", link.Attrs().Name)
			}
		}
	}
	if egressHook {
		egress := coll.Programs[egressName]
		if egress == nil {
			c.recordDirectStatsError(fmt.Errorf("direct stats observer has no %q program", egressName))
			c.log.Warnf("direct stats observer has no %q program; skipping egress hook on %v", egressName, link.Attrs().Name)
		} else {
			spec := makeTCHookSpec(tcHookScopeHost, link, tcHookEgress, directStatsPriority, 0x2023, egress, consts.AppName+"_"+egressName, nil)
			spec.Optional = true
			spec.OnError = func(err error) {
				c.recordDirectStatsError(fmt.Errorf("install direct stats egress hook on %v: %w", link.Attrs().Name, err))
			}
			if err := c.stageTCHook(spec); err != nil {
				c.recordDirectStatsError(fmt.Errorf("install direct stats egress hook on %v: %w", link.Attrs().Name, err))
				c.log.WithError(err).Warnf("direct stats observer: cannot install egress hook on %v", link.Attrs().Name)
			}
		}
	}
	return nil
}

// directStatsProgramNames picks the observer programs for an interface role.
// A LAN-only egress hook watches forwarded replies after DNAT; WAN and dual
// interfaces keep the local-socket upload program.
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
	egress = "direct_stats_egress_" + layer
	if !wan && !dual {
		egress = "direct_stats_lan_egress_" + layer
	}
	return "direct_stats_" + role + "ingress_" + layer, egress
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
	if mark := spec.Variables["DIRECT_STATS_DAE_SOCKET_MARK"]; mark != nil {
		if err := mark.Set(soMarkFromDae.Load()); err != nil {
			return nil, fmt.Errorf("set direct stats socket mark: %w", err)
		}
	}
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
	if !c.addDeferFunc(func() error {
		// This generation's counters leave with its map; retire them first so
		// the process-level figure survives the reload. The observer is
		// captured because c.directStats may already name a successor.
		retireDirectStatsObserver(observer)
		coll.Close()
		return nil
	}) {
		// The core closed while the object was loading. Do not leave a live
		// observer whose collection is never closed.
		retireDirectStatsObserver(observer)
		coll.Close()
		c.directStats = nil
		return nil, fmt.Errorf("direct stats core is closed")
	}
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
	sum := func(key uint32) (directStatsValue, error) {
		values := make([]directStatsValue, ncpu)
		if err := m.Lookup(key, &values); err != nil {
			return directStatsValue{}, err
		}
		var total directStatsValue
		for _, v := range values {
			total.Bytes += v.Bytes
			total.Packets += v.Packets
		}
		return total, nil
	}
	up, err := sum(directStatsKeyUp)
	if err != nil {
		return DirectStatsCounters{}, fmt.Errorf("read direct stats upload key: %w", err)
	}
	down, err := sum(directStatsKeyDown)
	if err != nil {
		return DirectStatsCounters{}, fmt.Errorf("read direct stats download key: %w", err)
	}
	return DirectStatsCounters{
		UpBytes:     up.Bytes,
		UpPackets:   up.Packets,
		DownBytes:   down.Bytes,
		DownPackets: down.Packets,
	}, nil
}
