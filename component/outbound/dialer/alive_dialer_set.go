/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
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

// AliveDialerSet assumes mapping between index and dialer MUST remain unchanged.
//
// It is thread-safe.
type AliveDialerSet struct {
	log             *logrus.Logger
	dialerGroupName string
	CheckTyp        *NetworkType
	tolerance       time.Duration

	aliveChangeCallback func(alive bool)

	mu                      sync.RWMutex
	dialerToIndex           map[*Dialer]int // *Dialer -> index of inorderedAliveDialerSet
	dialerToLatency         map[*Dialer]time.Duration
	dialerToLatencyOffset   map[*Dialer]time.Duration
	inorderedAliveDialerSet []*Dialer

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
		log:                     log,
		dialerGroupName:         dialerGroupName,
		CheckTyp:                networkType,
		tolerance:               tolerance,
		aliveChangeCallback:     aliveChangeCallback,
		dialerToIndex:           make(map[*Dialer]int),
		dialerToLatency:         make(map[*Dialer]time.Duration),
		dialerToLatencyOffset:   dialerToLatencyOffset,
		inorderedAliveDialerSet: make([]*Dialer, 0, len(dialers)),
		selectionPolicy:         selectionPolicy,
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

func (a *AliveDialerSet) GetRand() *Dialer {
	return a.GetRandExcluded(nil)
}

func (a *AliveDialerSet) GetRandExcluded(excluded *Dialer) *Dialer {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if len(a.inorderedAliveDialerSet) == 0 {
		return nil
	}

	var candidates []*Dialer

	for _, d := range a.inorderedAliveDialerSet {
		if d == excluded {
			continue
		}
		candidates = append(candidates, d)
	}

	if len(candidates) > 0 {
		return candidates[fastrand.Intn(len(candidates))]
	}

	// No dialer available
	return nil
}

func (a *AliveDialerSet) Len() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.inorderedAliveDialerSet)
}

func (a *AliveDialerSet) SortingLatency(d *Dialer) time.Duration {
	return a.dialerToLatency[d] + a.dialerToLatencyOffset[d]
}

// GetMinLatency acquires correct selectionPolicy.
func (a *AliveDialerSet) GetMinLatency(excluded *Dialer) (d *Dialer, latency time.Duration) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	// Find the best non-excluded dialer.
	var nextBest *Dialer
	var nextBestSortingLatency = time.Hour
	for _, candidate := range a.inorderedAliveDialerSet {
		if candidate == excluded {
			continue
		}
		if sortingLatency := a.SortingLatency(candidate); sortingLatency < nextBestSortingLatency {
			nextBestSortingLatency = sortingLatency
			nextBest = candidate
		}
	}

	if nextBest != nil {
		return nextBest, nextBestSortingLatency
	}

	// No dialer available
	return nil, time.Hour
}

func (a *AliveDialerSet) printLatencies() {
	var builder strings.Builder
	builder.WriteString(fmt.Sprintf("Group '%v' [%v]:\n", a.dialerGroupName, a.CheckTyp.String()))
	var alive []*struct {
		d *Dialer
		l time.Duration
		o time.Duration
	}
	for _, d := range a.inorderedAliveDialerSet {
		latency, ok := a.dialerToLatency[d]
		if !ok {
			continue
		}
		offset := a.dialerToLatencyOffset[d]
		alive = append(alive, &struct {
			d *Dialer
			l time.Duration
			o time.Duration
		}{d, latency, offset})
	}
	sort.SliceStable(alive, func(i, j int) bool {
		return alive[i].l+alive[i].o < alive[j].l+alive[j].o
	})
	for i, dl := range alive {
		builder.WriteString(fmt.Sprintf("%4d. [%v] %v: %v\n", i+1, dl.d.property.SubscriptionTag, dl.d.property.Name, latencyString(dl.l, dl.o)))
	}
	a.log.Infoln(strings.TrimSuffix(builder.String(), "\n"))
}

// NotifyLatencyChange should be invoked when dialer every time latency and alive state changes.
func (a *AliveDialerSet) NotifyLatencyChange(dialer *Dialer, alive bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
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
			a.dialerToIndex[dialer] = len(a.inorderedAliveDialerSet)
			a.inorderedAliveDialerSet = append(a.inorderedAliveDialerSet, dialer)
		}
	} else {
		index := a.dialerToIndex[dialer]
		if index >= 0 {
			// Dialer: alive -> not alive.
			if a.log.IsLevelEnabled(logrus.InfoLevel) {
				a.log.WithFields(logrus.Fields{
					"dialer": dialer.property.Name,
					"group":  a.dialerGroupName,
				}).Infof("[ALIVE --%v-> NOT ALIVE]", a.CheckTyp.String())
			}
			// Remove the dialer from inorderedAliveDialerSet.
			if index >= len(a.inorderedAliveDialerSet) {
				a.log.Panicf("index:%v >= len(a.inorderedAliveDialerSet):%v", index, len(a.inorderedAliveDialerSet))
			}
			a.dialerToIndex[dialer] = -NotAlive
			if index < len(a.inorderedAliveDialerSet)-1 {
				// Swap this element with the last element.
				dialerToSwap := a.inorderedAliveDialerSet[len(a.inorderedAliveDialerSet)-1]
				if dialer == dialerToSwap {
					a.log.Panicf("dialer[%p] == dialerToSwap[%p]", dialer, dialerToSwap)
				}

				a.dialerToIndex[dialerToSwap] = index
				a.inorderedAliveDialerSet[index], a.inorderedAliveDialerSet[len(a.inorderedAliveDialerSet)-1] =
					a.inorderedAliveDialerSet[len(a.inorderedAliveDialerSet)-1], a.inorderedAliveDialerSet[index]
			}
			// Pop the last element.
			a.inorderedAliveDialerSet = a.inorderedAliveDialerSet[:len(a.inorderedAliveDialerSet)-1]
		} else {
			// This dialer is already not alive.
		}
	}

	if hasLatency {
		bakOldBestDialer := a.minLatency.dialer
		bakOldMinSortingLatency := a.minLatency.sortingLatency
		// Calc minLatency.
		a.dialerToLatency[dialer] = rawLatency
		sortingLatency = a.SortingLatency(dialer)
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
					a.log.WithFields(logrus.Fields{
						string(a.selectionPolicy): latencyString(newBestLatency, newBestOffset),
						"_new_dialer":             newBestDialer.property.Name,
						"_old_dialer":             oldDialerName,
						"group":                   a.dialerGroupName,
						"network":                 a.CheckTyp.String(),
					}).Infof("Group %vselects dialer", re)
				}

				a.printLatencies()
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
	} else {
		if alive && minPolicy && a.minLatency.dialer == nil {
			// Use first dialer if no dialer has alive state (usually happen at the very beginning).
			a.minLatency.dialer = dialer
			if a.log.IsLevelEnabled(logrus.InfoLevel) {
				a.log.WithFields(logrus.Fields{
					"group":   a.dialerGroupName,
					"network": a.CheckTyp.String(),
					"dialer":  a.minLatency.dialer.property.Name,
				}).Infof("Group selects dialer")
			}
		}
	}
}

func (a *AliveDialerSet) calcMinLatency() {
	var minLatency = time.Hour
	var minDialer *Dialer
	for _, d := range a.inorderedAliveDialerSet {
		_, ok := a.dialerToLatency[d]
		if !ok {
			continue
		}
		sortingLatency := a.SortingLatency(d)
		if sortingLatency < minLatency {
			minLatency = sortingLatency
			minDialer = d
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
