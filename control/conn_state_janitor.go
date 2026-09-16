/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

const (
	janitorBatchLookupSize = 1024
	janitorDeleteInitCap   = 256
	janitorDeleteRetainMax = 8192
)

func ensureJanitorLookupScratch[T any](buf []T) []T {
	if cap(buf) < janitorBatchLookupSize {
		return make([]T, janitorBatchLookupSize)
	}
	return buf[:janitorBatchLookupSize]
}

func takeJanitorDeleteScratch[T any](buf []T) []T {
	if cap(buf) < janitorDeleteInitCap {
		return make([]T, 0, janitorDeleteInitCap)
	}
	return buf[:0]
}

func keepJanitorDeleteScratch[T any](buf []T) []T {
	if cap(buf) > janitorDeleteRetainMax {
		return make([]T, 0, janitorDeleteInitCap)
	}
	return buf[:0]
}

var (
	// UDP connection state timeout constants (matching former bpf_timer values).
	// DNS connections are shorter-lived since they're typically query/response.
	udpConnStateTimeoutDNS = 17 * time.Second

	// DNS port in network byte order for connection state cleanup.
	// Precomputed to avoid repeated Htons() calls during janitor iterations.
	dnsPortNetworkOrder = common.Htons(53)
	// connStateJanitorPressureInterval is the fast-path scan interval used
	// while the connection-state maps are under pressure (overflow or high
	// usage).
	connStateJanitorPressureInterval = 1 * time.Second
	// connStateJanitorMaxInterval caps the poll backoff when the maps are
	// calm. Kernel overflow events still wake the janitor immediately, so
	// the relaxed cadence only delays the periodic non-event cleanups.
	connStateJanitorMaxInterval = 30 * time.Second
	// connStateJanitorSteadyInterval is the default scan interval for steady
	// state. This keeps cleanup prompt without paying a full-table cost every
	// second when map pressure is low.
	connStateJanitorSteadyInterval = 5 * time.Second
	// connStateJanitorPressureEnterUsage is the usage percentage that activates
	// pressure mode for connection-state cleanup.
	connStateJanitorPressureEnterUsage = 70
	// connStateJanitorPressureExitUsage is the usage percentage below which the
	// janitor starts counting down to leave pressure mode.
	connStateJanitorPressureExitUsage = 50
	// connStateJanitorPressureExitRounds is the number of consecutive low-usage
	// cleanup rounds required before leaving pressure mode.
	connStateJanitorPressureExitRounds = 3

	// TCP ACTIVE state has no age timeout because an idle socket can remain valid
	// indefinitely. FIN/RST transitions state to CLOSING for prompt cleanup.
	tcpConnStateTimeoutClosing = 10 * time.Second

	// tcpConnStateRoutinglessBackstop bounds routing-less TCP tracking
	// entries (WAN egress creates them for direct traffic with no routing
	// metadata, e.g. SYNs to blackholed destinations that never complete).
	// Every read path treats a routing-less entry exactly like a missing
	// one (LAN ingress passes it through, WAN egress re-routes the packet),
	// and a same-tuple SYN recreates it, so retiring idle ones is
	// behavior-neutral. Aligned with the kernel's 300s UDP backstop.
	tcpConnStateRoutinglessBackstop = 5 * time.Minute
)

type mapCleanupStats struct {
	entries      int
	deleted      int
	usagePercent int
	maxEntries   int
}

type connStateJanitorPressureState struct {
	active               bool
	belowThresholdRounds int
	lastUdpOverflow      uint64
	lastTcpOverflow      uint64
}

func updateConnStateJanitorPressure(
	state connStateJanitorPressureState,
	overflowDelta bool,
	maxUsagePercent int,
) connStateJanitorPressureState {
	if overflowDelta || maxUsagePercent >= connStateJanitorPressureEnterUsage {
		state.active = true
		state.belowThresholdRounds = 0
		return state
	}
	if !state.active {
		return state
	}
	if maxUsagePercent < connStateJanitorPressureExitUsage {
		state.belowThresholdRounds++
		if state.belowThresholdRounds >= connStateJanitorPressureExitRounds {
			state.active = false
			state.belowThresholdRounds = 0
		}
		return state
	}
	state.belowThresholdRounds = 0
	return state
}

// startConnStateJanitor activates the single maintenance runtime for this BPF
// object set. The runtime owns periodic cleanup and the event reader across
// control-plane generation handoffs.
func (c *ControlPlane) startConnStateJanitor() {
	if c == nil || c.bpfMaintenance == nil || c.bpfMaintenance.runtime == nil {
		return
	}
	if err := c.activateBpfMaintenance(); err != nil && c.log != nil {
		c.log.WithError(err).Error("Failed to activate BPF maintenance runtime")
	}
}

func (r *bpfMaintenanceRuntime) run() {
	interval := connStateJanitorPressureInterval
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var (
		lastConnCleanup      time.Time
		lastRedirectCleanup  time.Time
		lastCookiePidCleanup time.Time
		lastRoutingHandoff   time.Time
		lastHealthCheck      time.Time
		pressureState        connStateJanitorPressureState
	)

	runJanitorRound := func(c *ControlPlane, now time.Time, overflowHint bool) {
		if c == nil {
			return
		}
		bpf := r.bpf

		var udpOverflow, tcpOverflow uint64
		overflowDelta := overflowHint
		if bpf != nil && bpf.BpfStatsMap != nil {
			udpOverflow, tcpOverflow = c.readMapOverflowCounters(bpf.BpfStatsMap)
			if !overflowDelta {
				overflowDelta = udpOverflow > pressureState.lastUdpOverflow ||
					tcpOverflow > pressureState.lastTcpOverflow
			}
			pressureState.lastUdpOverflow = udpOverflow
			pressureState.lastTcpOverflow = tcpOverflow
		}
		if overflowDelta {
			pressureState.active = true
			pressureState.belowThresholdRounds = 0
		}

		connCleanupInterval := connStateJanitorSteadyInterval
		redirectCleanupInterval := redirectTrackJanitorSteadyInterval
		if pressureState.active {
			connCleanupInterval = connStateJanitorPressureInterval
			redirectCleanupInterval = redirectTrackJanitorPressureInterval
		}

		cleaned := 0
		mapEntries := 0
		if lastRedirectCleanup.IsZero() || now.Sub(lastRedirectCleanup) >= redirectCleanupInterval {
			cleaned += c.cleanupRedirectTrackMap()
			lastRedirectCleanup = now
		}
		if lastCookiePidCleanup.IsZero() || now.Sub(lastCookiePidCleanup) >= redirectCleanupInterval {
			cleaned += c.cleanupCookiePidMap()
			lastCookiePidCleanup = now
		}
		routingHandoffInterval := routingHandoffSteadyInterval
		if pressureState.active {
			routingHandoffInterval = routingHandoffPressureInterval
		}
		if lastRoutingHandoff.IsZero() || now.Sub(lastRoutingHandoff) >= routingHandoffInterval {
			cleaned += c.cleanupRoutingHandoffMap()
			lastRoutingHandoff = now
		}

		if lastConnCleanup.IsZero() || now.Sub(lastConnCleanup) >= connCleanupInterval {
			udpStats, tcpStats := c.cleanupConnStateMap(pressureState.active)
			mapEntries = udpStats.entries + tcpStats.entries

			maxUsagePercent := 0
			if udpStats.maxEntries > 0 {
				maxUsagePercent = (udpStats.entries + tcpStats.entries) * 100 / udpStats.maxEntries
			}
			pressureState = updateConnStateJanitorPressure(pressureState, overflowDelta, maxUsagePercent)
			lastConnCleanup = now
			cleaned += udpStats.deleted + tcpStats.deleted
		}

		if lastHealthCheck.IsZero() || now.Sub(lastHealthCheck) >= 5*time.Second {
			c.checkBpfMapHealth(udpOverflow, tcpOverflow)
			lastHealthCheck = now
		}

		// Back off the poll cadence only while the maps are empty and
		// calm. Any live entries, cleanup activity, or overflow event
		// keeps the fast cadence; the relaxed poll only covers a fully
		// idle datapath (and serves as a fallback if ringbuf events are
		// lost).
		if pressureState.active || cleaned > 0 || overflowHint || mapEntries > 0 {
			interval = connStateJanitorPressureInterval
		} else if interval < connStateJanitorMaxInterval {
			interval *= 2
			if interval > connStateJanitorMaxInterval {
				interval = connStateJanitorMaxInterval
			}
		}
		ticker.Reset(interval)
	}

	for {
		select {
		case <-r.stop:
			return
		case request := <-r.requests:
			switch request.kind {
			case bpfMaintenanceRetirement:
				if request.target != nil {
					request.target.runReloadRetirementCleanup(request.staleBeforeNs)
				}
			case bpfMaintenanceOverflow:
				runJanitorRound(request.target, time.Now(), true)
			case bpfMaintenanceBarrier:
			}
			if request.done != nil {
				close(request.done)
			}
		case now := <-ticker.C:
			if r.cleanup != nil && r.cleanup.active.Load() != r {
				continue
			}
			runJanitorRound(r.active.Load(), now, false)
		}
	}
}

func (c *ControlPlane) stopConnStateJanitor() {
	if c == nil {
		return
	}
	c.stopOnce.Do(func() {
		if c.stop != nil {
			close(c.stop)
		}
		if c.bpfMaintenance != nil && c.bpfMaintenance.runtime != nil {
			c.bpfMaintenance.deactivate()
			c.bpfMaintenance.runtime.barrier()
		}
	})
}

// cleanupConnStateMap performs a single-pass scan of ConnStateMap, classifying
// entries by L4 protocol and applying protocol-specific timeout/expiry logic.
// This replaces the former separate cleanupUdpConnStateMap + cleanupTcpConnStateMap
// pair, halving the BatchLookup syscalls and ClockGettime overhead per tick.
func (c *ControlPlane) cleanupConnStateMap(aggressiveCleanup bool) (udpStats, tcpStats mapCleanupStats) {
	cleanupMu, _ := c.maintenanceState()
	cleanupMu.Lock()
	defer cleanupMu.Unlock()
	return c.cleanupConnStateMapBeforeLocked(aggressiveCleanup, 0)
}

// cleanupConnStateMapBeforeLocked scans ConnStateMap under connStateCleanupMu.
// aggressiveCleanup halves the protocol TTLs under map pressure. A nonzero
// staleBeforeNs (monotonic reload-request timestamp) additionally retires
// entries not refreshed since the retired generation; pinned entries are
// exempt via the pin snapshots and the scan-to-delete recheck below.
func (c *ControlPlane) cleanupConnStateMapBeforeLocked(aggressiveCleanup bool, staleBeforeNs uint64) (udpStats, tcpStats mapCleanupStats) {
	select {
	case <-c.stop:
		return
	default:
	}

	bpf := c.currentBpf()
	if bpf == nil || bpf.ConnStateMap == nil {
		return
	}

	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		c.log.Errorf("cleanupConnStateMap: failed to get monotonic time: %v", err)
		return
	}
	nowNano := ts.Nano()

	dnsTimeoutNano := udpConnStateTimeoutDNS.Nanoseconds()
	normalTimeoutNano := QuicNatTimeout.Nanoseconds()
	aggressiveTimeout := normalTimeoutNano / 2
	aggressiveDnsTimeout := dnsTimeoutNano / 2

	closingTimeoutNano := tcpConnStateTimeoutClosing.Nanoseconds()
	aggressiveClosingTimeout := closingTimeoutNano / 2
	routinglessBackstopNano := tcpConnStateRoutinglessBackstop.Nanoseconds()
	if aggressiveCleanup {
		// Halve like every other protocol TTL here: pressure mode runs when
		// the map is filling, exactly when dead-SYN tracking entries should
		// retire fastest.
		routinglessBackstopNano /= 2
	}

	scratch := c.connStateJanitorScratch()
	udpKeysToDelete := takeJanitorDeleteScratch(scratch.udpDelete)
	tcpKeysToDelete := takeJanitorDeleteScratch(scratch.tcpDelete)
	keysOut := ensureJanitorLookupScratch(scratch.udpKeys)
	valuesOut := ensureJanitorLookupScratch(scratch.udpValues)
	defer func() {
		scratch.udpDelete = keepJanitorDeleteScratch(udpKeysToDelete)
		scratch.tcpDelete = keepJanitorDeleteScratch(tcpKeysToDelete)
		scratch.udpKeys = keysOut
		scratch.udpValues = valuesOut
	}()

	var cursor ebpf.MapBatchCursor
	manager, _ := c.controlPlaneSessionManager()

	// Snapshot pin sets once to avoid per-entry RLock/RUnlock during the scan.
	// The final recheck at the bottom still acquires both locks for precise
	// scan-to-delete race prevention.
	pinnedUDPSnap := manager.snapshotPinnedUDP()
	pinnedTCPSnap := manager.snapshotPinnedTCP()

	for {
		count, err := bpf.ConnStateMap.BatchLookup(&cursor, keysOut, valuesOut, nil)
		if count > 0 {
			for i := range count {
				key := keysOut[i]
				value := valuesOut[i]
				switch key.L4proto {
				case unix.IPPROTO_UDP:
					udpStats.entries++
					if _, pinned := pinnedUDPSnap[key]; pinned {
						continue
					}
					isDNS := key.Sport == dnsPortNetworkOrder || key.Dport == dnsPortNetworkOrder
					timeout := normalTimeoutNano
					if isDNS {
						timeout = dnsTimeoutNano
					}
					if aggressiveCleanup {
						if isDNS {
							timeout = aggressiveDnsTimeout
						} else {
							timeout = aggressiveTimeout
						}
					}
					age := nowNano - int64(value.LastSeenNs)
					if age > timeout ||
						(staleBeforeNs > 0 && (value.LastSeenNs == 0 || value.LastSeenNs < staleBeforeNs)) {
						udpKeysToDelete = append(udpKeysToDelete, key)
					}
				case unix.IPPROTO_TCP:
					tcpStats.entries++
					if _, pinned := pinnedTCPSnap[key]; pinned {
						continue
					}
					closingTimeout := closingTimeoutNano
					if aggressiveCleanup {
						closingTimeout = aggressiveClosingTimeout
					}
					shouldDelete := false
					if value.State == 1 {
						age := nowNano - int64(value.LastSeenNs)
						if age > closingTimeout {
							shouldDelete = true
						}
					}
					// Routing-less tracking entries are neutral to delete on
					// every read path (LAN ingress passes them through, WAN
					// egress re-routes the packet, and a same-tuple SYN
					// recreates them), so idle ones get a backstop instead
					// of lingering until the next reload's stale threshold.
					if !shouldDelete && value.Meta.Data.HasRouting == 0 {
						age := nowNano - int64(value.LastSeenNs)
						if age > routinglessBackstopNano {
							shouldDelete = true
						}
					}
					// Established TCP with routing metadata has no TTL here
					// (pin-governed), so the stale threshold is the only
					// retirement path for orphaned entries.
					if !shouldDelete && staleBeforeNs > 0 &&
						(value.LastSeenNs == 0 || value.LastSeenNs < staleBeforeNs) {
						shouldDelete = true
					}
					if shouldDelete {
						tcpKeysToDelete = append(tcpKeysToDelete, key)
					}
				}
			}
		}
		if err != nil {
			if !isIgnorableBatchLookupErr(err) {
				c.log.Errorf("cleanupConnStateMap: BatchLookup error: %v", err)
			}
			break
		}
	}

	maxEntries := bpf.ConnStateMap.MaxEntries()
	if maxEntries > 0 {
		udpStats.maxEntries = int(maxEntries)
		tcpStats.maxEntries = int(maxEntries)
		udpStats.usagePercent = udpStats.entries * 100 / int(maxEntries)
		tcpStats.usagePercent = tcpStats.entries * 100 / int(maxEntries)
	}

	// Recheck pins while blocking process-owned flow adoption and release, then
	// delete inside the SAME critical section. This closes the scan-to-delete
	// race without holding the manager locks during the potentially large map
	// walk.
	//
	// The two key classes take disjoint locks, so each delete is scoped to the
	// lock that actually protects its key class and a UDP-only cycle never
	// queues behind the generationsMu write lock that guards TCP flow
	// registration/release:
	//   - UDP keys live in manager.pinnedUDP, exclusively guarded by
	//     udpStateMu (see RetainUdpConnStateTuples / ReleaseUdpConnStateTuples).
	//   - TCP keys live in the manager.pinnedShards, which generationsMu
	//     covers for registration/unpin bookkeeping.
	// No path holds both locks here, so the former generationsMu -> udpStateMu
	// nesting (the order releaseFlow still uses) is not exercised by the
	// janitor at all. The deletes must NOT move outside these critical
	// sections: a pin slipping between the recheck and the delete would lose a
	// live entry.
	// A delete failure is not fatal (the next cycle retries), but it must not
	// be silent: Debug-level made a persistently failing map invisible to
	// operators. Every failure is counted and warned about.
	deleteKeys := func(keys []bpfTuplesKey, label string) {
		if len(keys) == 0 {
			return
		}
		if _, err := BpfMapBatchDelete(bpf.ConnStateMap, keys); err != nil {
			countConnStateJanitorDeleteError(label, err)
		}
	}
	if manager != nil && len(udpKeysToDelete) > 0 {
		manager.udpStateMu.RLock()
		udpPinnedFiltered := udpKeysToDelete[:0]
		for _, key := range udpKeysToDelete {
			if manager.pinnedUDP[key] == 0 {
				udpPinnedFiltered = append(udpPinnedFiltered, key)
			}
		}
		udpKeysToDelete = udpPinnedFiltered
		deleteKeys(udpKeysToDelete, "UDP")
		manager.udpStateMu.RUnlock()
	} else {
		deleteKeys(udpKeysToDelete, "UDP")
	}
	udpStats.deleted = len(udpKeysToDelete)

	if manager != nil && len(tcpKeysToDelete) > 0 {
		manager.generationsMu.Lock()
		tcpPinnedFiltered := tcpKeysToDelete[:0]
		for _, key := range tcpKeysToDelete {
			shard := &manager.pinnedShards[tuplesShardIndex(&key)]
			shard.mu.Lock()
			refs := shard.keys[key]
			shard.mu.Unlock()
			if refs == 0 {
				tcpPinnedFiltered = append(tcpPinnedFiltered, key)
			}
		}
		tcpKeysToDelete = tcpPinnedFiltered
		deleteKeys(tcpKeysToDelete, "TCP")
		manager.generationsMu.Unlock()
	} else {
		deleteKeys(tcpKeysToDelete, "TCP")
	}
	tcpStats.deleted = len(tcpKeysToDelete)

	if len(udpKeysToDelete) > 0 {
		if aggressiveCleanup {
			c.log.Debugf("cleanupConnStateMap: aggressive cleanup removed %d UDP entries (%d%% usage)",
				len(udpKeysToDelete), udpStats.usagePercent)
		} else {
			c.log.Debugf("cleanupConnStateMap: removed %d expired UDP entries", len(udpKeysToDelete))
		}
	}
	if len(tcpKeysToDelete) > 0 {
		if aggressiveCleanup {
			c.log.Debugf("cleanupConnStateMap: aggressive cleanup removed %d TCP entries (%d%% usage)",
				len(tcpKeysToDelete), tcpStats.usagePercent)
		} else {
			c.log.Debugf("cleanupConnStateMap: removed %d expired TCP entries", len(tcpKeysToDelete))
		}
	}

	return udpStats, tcpStats
}

// connStateJanitorDeleteErrorCount counts failed janitor deletions from
// conn_state_map. A failure only delays retirement to the next cycle, but a
// persistently failing map must stay visible: it was Debug-level before, which
// made a broken map invisible at the default log level.
var connStateJanitorDeleteErrorCount atomic.Uint64

// countConnStateJanitorDeleteError counts one failed janitor deletion and warns
// on the first and every 2^n-th occurrence so a recurring failure cannot flood
// the log while never going unreported.
func countConnStateJanitorDeleteError(class string, err error) {
	if err == nil {
		return
	}
	count := connStateJanitorDeleteErrorCount.Add(1)
	if !shouldReportEveryPow2(count) {
		return
	}
	logrus.WithFields(logrus.Fields{
		"class": class,
		"error": err.Error(),
		"count": count,
	}).Warn("cleanupConnStateMap: batch delete failed")
}

func (c *ControlPlane) connStateJanitorScratch() *connStateJanitorScratch {
	if c == nil {
		return nil
	}
	_, scratch := c.maintenanceState()
	return scratch
}
