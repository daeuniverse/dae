/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/outbound/pkg/fastrand"
	"github.com/sirupsen/logrus"
)

const (
	Init = 1 + iota
	NotAlive
)

type minLatency struct {
	sortingLatency time.Duration
	dialer         *Dialer
}

// aliveEntry combines a dialer pointer with its cached sorting latency.
// This struct enables slice-based storage that eliminates map lookups in hot paths.
type aliveEntry struct {
	dialer         *Dialer
	sortingLatency time.Duration
}

// AliveDialerSet assumes mapping between index and dialer MUST remain unchanged.
//
// It is thread-safe.
type AliveDialerSet struct {
	log             *logrus.Logger
	dialerGroupName string
	CheckTyp        *NetworkType
	tolerance       time.Duration

	aliveChangeCallback func(alive bool)

	mu                    sync.RWMutex
	dialerToIndex         map[*Dialer]int // *Dialer -> index in aliveEntries, -Init, or -NotAlive
	dialerToLatency       map[*Dialer]time.Duration
	dialerToLatencyOffset map[*Dialer]time.Duration

	// aliveEntries stores all alive dialers with their precomputed sorting latency.
	// This is the primary data structure for hot path operations (GetMinLatency, GetRandExcluded).
	// Using a slice of structs provides better cache locality and eliminates map lookups.
	aliveEntries []aliveEntry

	selectionPolicy consts.DialerSelectionPolicy
	minLatency      minLatency
}

func NewAliveDialerSet(
	log *logrus.Logger,
	dialerGroupName string,
	networkType *NetworkType,
	tolerance time.Duration,
	selectionPolicy consts.DialerSelectionPolicy,
	dialers []*Dialer,
	dialersAnnotations []*Annotation,
	aliveChangeCallback func(alive bool),
	setAlive bool,
) *AliveDialerSet {
	if len(dialers) != len(dialersAnnotations) {
		panic(fmt.Sprintf("unmatched annotations length: %v dialers and %v annotations", len(dialers), len(dialersAnnotations)))
	}
	dialerToLatencyOffset := make(map[*Dialer]time.Duration)
	for i := range dialers {
		d, a := dialers[i], dialersAnnotations[i]
		dialerToLatencyOffset[d] = a.AddLatency
	}
	a := &AliveDialerSet{
		log:                   log,
		dialerGroupName:       dialerGroupName,
		CheckTyp:              networkType,
		tolerance:             tolerance,
		aliveChangeCallback:   aliveChangeCallback,
		dialerToIndex:         make(map[*Dialer]int),
		dialerToLatency:       make(map[*Dialer]time.Duration),
		dialerToLatencyOffset: dialerToLatencyOffset,
		aliveEntries:          make([]aliveEntry, 0, len(dialers)),
		selectionPolicy:       selectionPolicy,
		minLatency: minLatency{
			// Initiate the latency with a very big value.
			sortingLatency: time.Hour,
		},
	}
	for _, d := range dialers {
		a.dialerToIndex[d] = -Init
	}
	for _, d := range dialers {
		a.NotifyLatencyChange(d, setAlive)
	}
	return a
}

func (a *AliveDialerSet) GetRandExcluded(excluded *Dialer) *Dialer {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if len(a.aliveEntries) == 0 {
		return nil
	}
	if excluded == nil {
		return a.aliveEntries[fastrand.Intn(len(a.aliveEntries))].dialer
	}

	var chosen *Dialer
	var candidateCount int
	for i := range a.aliveEntries {
		d := a.aliveEntries[i].dialer
		if d == excluded {
			continue
		}
		candidateCount++
		// Reservoir sampling keeps uniform randomness without a shared scratch buffer.
		if fastrand.Intn(candidateCount) == 0 {
			chosen = d
		}
	}

	return chosen
}

func (a *AliveDialerSet) Len() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.aliveEntries)
}

// GetMinLatency acquires correct selectionPolicy.
func (a *AliveDialerSet) GetMinLatency(excluded *Dialer) (d *Dialer, latency time.Duration) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if a.minLatency.dialer != nil && excluded != a.minLatency.dialer {
		return a.minLatency.dialer, a.minLatency.sortingLatency
	}

	// Find the best non-excluded dialer.
	// Using aliveEntries with direct field access avoids map lookups.
	var nextBest *Dialer
	var nextBestSortingLatency = time.Hour
	for i := range a.aliveEntries {
		entry := &a.aliveEntries[i]
		if entry.dialer == excluded {
			continue
		}
		if entry.sortingLatency < nextBestSortingLatency {
			nextBestSortingLatency = entry.sortingLatency
			nextBest = entry.dialer
		}
	}

	if nextBest != nil {
		return nextBest, nextBestSortingLatency
	}

	// No dialer available
	return nil, time.Hour
}

// latencySnapshotEntry is one dialer's display state copied by value while
// a.mu is held. The dialer pointer, its subscription tag, and its name are
// all captured here on purpose: property is replaced wholesale on reload and
// aliveEntries is mutated in place (append / swap-remove), so carrying either
// the slice header or a *Dialer out of the lock would race with the writer.
type latencySnapshotEntry struct {
	name    string
	tag     string
	latency time.Duration
	offset  time.Duration
}

// latencySnapshot is the lock-free rendering input for printLatenciesOutOfLock.
type latencySnapshot struct {
	group   string
	network string
	entries []latencySnapshotEntry
}

// snapshotLatenciesLocked copies the per-dialer display state while a.mu is
// held. It must be called with a.mu held (read or write); it performs no I/O
// and no logging.
func (a *AliveDialerSet) snapshotLatenciesLocked() (latencySnapshot, bool) {
	if !a.log.IsLevelEnabled(logrus.DebugLevel) {
		// The caller logs the rendered list at Debug; skip building the
		// snapshot (which walks every entry) when it would be discarded anyway.
		return latencySnapshot{}, false
	}
	snap := latencySnapshot{
		group:   a.dialerGroupName,
		network: a.CheckTyp.String(),
		entries: make([]latencySnapshotEntry, 0, len(a.aliveEntries)),
	}
	for i := range a.aliveEntries {
		d := a.aliveEntries[i].dialer
		latency, ok := a.dialerToLatency[d]
		if !ok {
			continue
		}
		entry := latencySnapshotEntry{
			latency: latency,
			offset:  a.dialerToLatencyOffset[d],
		}
		if d != nil && d.property != nil {
			entry.name = d.property.Name
			entry.tag = d.property.SubscriptionTag
		}
		snap.entries = append(snap.entries, entry)
	}
	return snap, true
}

// printLatenciesOutOfLock sorts and renders a snapshot taken by
// snapshotLatenciesLocked. It must run with a.mu RELEASED: the whole point is
// to keep list formatting and log I/O out of the latency-update critical
// section (the 30s health cycle calls this for the whole group).
//
// The list is per-dialer detail, and the caller already emits the milestone
// (which dialer was selected and why) at info, so this render is debug: at N
// dialers it is N lines per best-dialer change, which is exactly the kind of
// detail log_level=debug exists for. It is not removed, because the ordering
// behind a selection decision is what an operator needs when they disagree
// with the choice.
func (a *AliveDialerSet) printLatenciesOutOfLock(snap latencySnapshot) {
	alive := snap.entries
	sort.SliceStable(alive, func(i, j int) bool {
		return alive[i].latency+alive[i].offset < alive[j].latency+alive[j].offset
	})
	var builder strings.Builder
	fmt.Fprintf(&builder, "Group '%v' [%v]:\n", snap.group, snap.network)
	for i, dl := range alive {
		fmt.Fprintf(&builder, "%4d. [%v] %v: %v\n", i+1, dl.tag, dl.name, latencyString(dl.latency, dl.offset))
	}
	a.log.Debugln(strings.TrimSuffix(builder.String(), "\n"))
}

// NotifyLatencyChange should be invoked when dialer every time latency and alive state changes.
func (a *AliveDialerSet) NotifyLatencyChange(dialer *Dialer, alive bool) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Unknown dialer: dialerToIndex's zero value is 0, which a naive lookup
	// would misread as "alive at index 0" and corrupt another dialer's entry.
	// The set's dialer list is fixed at construction, so an unknown dialer is
	// a caller bug; ignore it rather than corrupt the invariant.
	if _, ok := a.dialerToIndex[dialer]; !ok {
		if a.log.IsLevelEnabled(logrus.DebugLevel) {
			name := "<nil dialer>"
			if dialer != nil {
				name = dialer.property.Name
			}
			a.log.WithFields(logrus.Fields{
				"group":   a.dialerGroupName,
				"dialer":  name,
				"network": a.CheckTyp.String(),
			}).Debugln("NotifyLatencyChange: dialer not in this set; ignored")
		}
		return
	}

	// Revalidate membership against the dialer's current collection state.
	// Notifications are published after the collection lock is released, so a
	// slow failure report can arrive after a newer success already flipped
	// the collection back to alive; trusting the stale bool would remove a
	// healthy node from this set. The data-UDP health domain has no periodic
	// probe and its traffic-success notifications are suppressed while the
	// dialer is already alive, so such a stale removal could persist for a
	// long time. MustGetAlive only performs an atomic load on the collection
	// (no collection lock is taken), so no lock-order cycle with the
	// collection fine lock is introduced by revalidating here. Sets are
	// registered under their own CheckTyp collection, so the revalidated
	// state is the very state the notification was derived from.
	if actual := dialer.MustGetAlive(a.CheckTyp); actual != alive {
		if a.log.IsLevelEnabled(logrus.DebugLevel) {
			a.log.WithFields(logrus.Fields{
				"group":        a.dialerGroupName,
				"dialer":       dialer.property.Name,
				"network":      a.CheckTyp.String(),
				"notified":     alive,
				"actual":       actual,
				"notifySource": "out-of-order availability notification",
			}).Debugln("NotifyLatencyChange: ignoring stale availability notification")
		}
		alive = actual
	}

	var (
		rawLatency     time.Duration
		sortingLatency time.Duration
		hasLatency     bool
		minPolicy      bool
	)

	switch a.selectionPolicy {
	case consts.DialerSelectionPolicy_MinLastLatency:
		rawLatency, hasLatency = dialer.snapshotLatencyForPolicy(a.CheckTyp, a.selectionPolicy)
		minPolicy = true
	case consts.DialerSelectionPolicy_MinAverage10Latencies:
		rawLatency, hasLatency = dialer.snapshotLatencyForPolicy(a.CheckTyp, a.selectionPolicy)
		minPolicy = true
	case consts.DialerSelectionPolicy_MinMovingAverageLatencies:
		rawLatency, hasLatency = dialer.snapshotLatencyForPolicy(a.CheckTyp, a.selectionPolicy)
		minPolicy = true
	}

	if alive {
		index := a.dialerToIndex[dialer]
		if index >= 0 {
			// This dialer is already alive.
		} else {
			// Dialer: not alive -> alive.
			if index == -NotAlive {
				if a.log.IsLevelEnabled(logrus.InfoLevel) {
					a.log.WithFields(logrus.Fields{
						"dialer": dialer.property.Name,
						"group":  a.dialerGroupName,
					}).Infof("[NOT ALIVE --%v-> ALIVE]", a.CheckTyp.String())
				}
			}
			a.dialerToIndex[dialer] = len(a.aliveEntries)
			a.aliveEntries = append(a.aliveEntries, aliveEntry{
				dialer:         dialer,
				sortingLatency: rawLatency + a.dialerToLatencyOffset[dialer],
			})
		}
	} else {
		index := a.dialerToIndex[dialer]
		if index >= 0 {
			removedBestWithoutLatency := minPolicy && !hasLatency && a.minLatency.dialer == dialer
			// Dialer: alive -> not alive.
			if a.log.IsLevelEnabled(logrus.InfoLevel) {
				a.log.WithFields(logrus.Fields{
					"dialer": dialer.property.Name,
					"group":  a.dialerGroupName,
				}).Infof("[ALIVE --%v-> NOT ALIVE]", a.CheckTyp.String())
			}
			// Remove the dialer from aliveEntries.
			if index >= len(a.aliveEntries) {
				a.log.Panicf("index:%v >= len(a.aliveEntries):%v", index, len(a.aliveEntries))
			}
			a.dialerToIndex[dialer] = -NotAlive
			if index < len(a.aliveEntries)-1 {
				// Swap this element with the last element.
				// CRITICAL: Must update dialerToIndex for the swapped dialer.
				lastIdx := len(a.aliveEntries) - 1
				swappedEntry := a.aliveEntries[lastIdx]
				if dialer == swappedEntry.dialer {
					a.log.Panicf("dialer[%p] == swappedEntry.dialer[%p]", dialer, swappedEntry.dialer)
				}

				a.dialerToIndex[swappedEntry.dialer] = index
				a.aliveEntries[index] = swappedEntry
			}
			// Pop the last element.
			a.aliveEntries = a.aliveEntries[:len(a.aliveEntries)-1]
			if removedBestWithoutLatency {
				a.minLatency.dialer = nil
				a.minLatency.sortingLatency = time.Hour
				a.calcMinLatency()
				if a.minLatency.dialer == nil {
					a.mu.Unlock()
					a.aliveChangeCallback(false)
					a.mu.Lock()
					if a.log.IsLevelEnabled(logrus.InfoLevel) {
						a.log.WithFields(logrus.Fields{
							"group":   a.dialerGroupName,
							"network": a.CheckTyp.String(),
						}).Infof("Group has no dialer alive")
					}
				}
			}
		}
	}

	if hasLatency {
		bakOldBestDialer := a.minLatency.dialer
		bakOldMinSortingLatency := a.minLatency.sortingLatency
		// Calc minLatency.
		a.dialerToLatency[dialer] = rawLatency
		// Update sorting latency in aliveEntries for GetMinLatency hot path optimization.
		sortingLatency = rawLatency + a.dialerToLatencyOffset[dialer]
		// If dialer is alive, update its sortingLatency in aliveEntries.
		if index := a.dialerToIndex[dialer]; index >= 0 {
			a.aliveEntries[index].sortingLatency = sortingLatency
		}
		if alive &&
			sortingLatency <= a.minLatency.sortingLatency &&
			(a.minLatency.sortingLatency < a.tolerance || sortingLatency <= a.minLatency.sortingLatency-a.tolerance) {
			a.minLatency.sortingLatency = sortingLatency
			a.minLatency.dialer = dialer
		} else if a.minLatency.dialer == dialer {
			a.minLatency.sortingLatency = sortingLatency
			if !alive || sortingLatency > bakOldMinSortingLatency {
				// Latency increases.
				if !alive {
					a.minLatency.dialer = nil
				}
				a.calcMinLatency()
				// Now `a.minLatency.dialer` will be nil if there is no alive dialer.
			}
		}
		currentAlive := a.minLatency.dialer != nil
		// If best dialer changed.
		if a.minLatency.dialer != bakOldBestDialer {
			if currentAlive {
				newBestDialer := a.minLatency.dialer
				newBestLatency := a.dialerToLatency[newBestDialer]
				newBestOffset := a.dialerToLatencyOffset[newBestDialer]
				re := "re-"
				var oldDialerName string
				if bakOldBestDialer == nil {
					// Not alive -> alive
					a.mu.Unlock()
					a.aliveChangeCallback(true)
					a.mu.Lock()
					re = ""
					oldDialerName = "<nil>"
				} else {
					oldDialerName = bakOldBestDialer.property.Name
				}
				if a.log.IsLevelEnabled(logrus.InfoLevel) {
					// One line carries the decision: which dialer won, what
					// it displaced, the selection key, and why the change
					// happened. The full latency table moves to debug (see
					// printLatenciesOutOfLock): it is detail, this line is
					// the event.
					reason := "best latency"
					if bakOldBestDialer == nil {
						reason = "no dialer was alive"
					}
					fields := logrus.Fields{
						string(a.selectionPolicy): latencyString(newBestLatency, newBestOffset),
						"_new_dialer":             newBestDialer.property.Name,
						"_old_dialer":             oldDialerName,
						"reason":                  reason,
						"alive_dialers":           len(a.aliveEntries),
						"group":                   a.dialerGroupName,
						"network":                 a.CheckTyp.String(),
					}
					if bakOldBestDialer != nil {
						delta := newBestLatency + newBestOffset - bakOldMinSortingLatency
						fields["latency_delta_ms"] = delta.Milliseconds()
					}
					a.log.WithFields(fields).Infof("Group %vselects dialer", re)
				}

				// Lock order / critical-section discipline: the snapshot is
				// taken under a.mu and the formatting + log write happen
				// after unlocking, mirroring the aliveChangeCallback calls
				// below. Holding a.mu across the render would serialize every
				// other latency update behind a full-list sort and a log
				// write (the caller may hold the group's publish lock too).
				if snap, ok := a.snapshotLatenciesLocked(); ok {
					a.mu.Unlock()
					a.printLatenciesOutOfLock(snap)
					a.mu.Lock()
				}
			} else {
				// Alive -> not alive
				a.mu.Unlock()
				a.aliveChangeCallback(false)
				a.mu.Lock()
				if a.log.IsLevelEnabled(logrus.InfoLevel) {
					a.log.WithFields(logrus.Fields{
						"group":   a.dialerGroupName,
						"network": a.CheckTyp.String(),
					}).Infof("Group has no dialer alive")
				}
			}
		}
	} else if alive && minPolicy {
		// No active latency probe for this network type (e.g. data-UDP), so
		// hasLatency is false here. Honor add_latency as a manual weight and
		// let it override the optimistic first-dialer selection.
		sortingLatency = rawLatency + a.dialerToLatencyOffset[dialer]
		if index := a.dialerToIndex[dialer]; index >= 0 {
			a.aliveEntries[index].sortingLatency = sortingLatency
		}
		wasNoAliveDialer := a.minLatency.dialer == nil
		if wasNoAliveDialer || sortingLatency < a.minLatency.sortingLatency {
			a.minLatency.dialer = dialer
			a.minLatency.sortingLatency = sortingLatency
		}
		if wasNoAliveDialer && a.minLatency.dialer != nil {
			// Not alive -> alive: mirror the has-latency branch above so the
			// group-level callback (which drives the kernel outbound
			// connectivity map) learns about traffic-driven revival. Without
			// this, a revived data-UDP domain leaves the map at 0 and the
			// kernel keeps dropping new flows routed to this group.
			a.mu.Unlock()
			a.aliveChangeCallback(true)
			a.mu.Lock()
		}
		if a.log.IsLevelEnabled(logrus.InfoLevel) {
			a.log.WithFields(logrus.Fields{
				"group":   a.dialerGroupName,
				"network": a.CheckTyp.String(),
				"dialer":  dialer.property.Name,
			}).Infof("Group selects dialer")
		}
	}
}

func (a *AliveDialerSet) calcMinLatency() {
	var minLatency = time.Hour
	var minDialer *Dialer
	for i := range a.aliveEntries {
		if a.aliveEntries[i].sortingLatency < minLatency {
			minLatency = a.aliveEntries[i].sortingLatency
			minDialer = a.aliveEntries[i].dialer
		}
	}
	if a.minLatency.dialer == nil {
		a.minLatency.sortingLatency = minLatency
		a.minLatency.dialer = minDialer
	} else if minDialer != nil &&
		minLatency <= a.minLatency.sortingLatency &&
		(a.minLatency.sortingLatency < a.tolerance || minLatency <= a.minLatency.sortingLatency-a.tolerance) {
		a.minLatency.sortingLatency = minLatency
		a.minLatency.dialer = minDialer
	}
}

func (a *AliveDialerSet) SetSelectionPolicy(policy consts.DialerSelectionPolicy) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.selectionPolicy == policy {
		return
	}
	a.selectionPolicy = policy
	a.recomputeSelectionStateLocked()
}

func (a *AliveDialerSet) recomputeSelectionStateLocked() {
	a.dialerToLatency = make(map[*Dialer]time.Duration, len(a.dialerToLatencyOffset))
	a.minLatency = minLatency{
		sortingLatency: time.Hour,
	}

	if !isMinLatencyPolicy(a.selectionPolicy) {
		return
	}

	for i := range a.aliveEntries {
		entry := &a.aliveEntries[i]
		rawLatency, hasLatency := entry.dialer.snapshotLatencyForPolicy(a.CheckTyp, a.selectionPolicy)
		if hasLatency {
			a.dialerToLatency[entry.dialer] = rawLatency
		}
		// Always apply the manual latency offset. For network types without
		// an active latency probe (e.g. data-UDP) the offset is the only
		// ranking signal, so add_latency acts as a true manual weight.
		entry.sortingLatency = rawLatency + a.dialerToLatencyOffset[entry.dialer]
	}

	a.calcMinLatency()
}

func isMinLatencyPolicy(policy consts.DialerSelectionPolicy) bool {
	switch policy {
	case consts.DialerSelectionPolicy_MinLastLatency,
		consts.DialerSelectionPolicy_MinAverage10Latencies,
		consts.DialerSelectionPolicy_MinMovingAverageLatencies:
		return true
	default:
		return false
	}
}
