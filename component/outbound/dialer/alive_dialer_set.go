/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2023, v2rayA Organization <team@v2raya.org>
 */

package dialer

import (
	"fmt"
	"github.com/mzz2017/softwind/pkg/fastrand"
	"github.com/sirupsen/logrus"
	"github.com/v2rayA/dae/common/consts"
	"strings"
	"sync"
	"time"
)

const (
	Init = 1 + iota
	NotAlive
)

type minLatency struct {
	latency time.Duration
	dialer  *Dialer
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

	mu                      sync.Mutex
	dialerToIndex           map[*Dialer]int // *Dialer -> index of inorderedAliveDialerSet
	dialerToLatency         map[*Dialer]time.Duration
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
	aliveChangeCallback func(alive bool),
	setAlive bool,
) *AliveDialerSet {
	a := &AliveDialerSet{
		log:                     log,
		dialerGroupName:         dialerGroupName,
		CheckTyp:                networkType,
		tolerance:               tolerance,
		aliveChangeCallback:     aliveChangeCallback,
		dialerToIndex:           make(map[*Dialer]int),
		dialerToLatency:         make(map[*Dialer]time.Duration),
		inorderedAliveDialerSet: make([]*Dialer, 0, len(dialers)),
		selectionPolicy:         selectionPolicy,
		minLatency: minLatency{
			// Initiate the latency with a very big value.
			latency: time.Hour,
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
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.inorderedAliveDialerSet) == 0 {
		return nil
	}
	ind := fastrand.Intn(len(a.inorderedAliveDialerSet))
	return a.inorderedAliveDialerSet[ind]
}

// GetMinLatency acquires correct selectionPolicy.
func (a *AliveDialerSet) GetMinLatency() (d *Dialer, latency time.Duration) {
	return a.minLatency.dialer, a.minLatency.latency
}

func (a *AliveDialerSet) printLatencies() {
	var builder strings.Builder
	builder.WriteString(fmt.Sprintf("Group '%v' [%v]:\n", a.dialerGroupName, a.CheckTyp.String()))
	for _, d := range a.inorderedAliveDialerSet {
		latency, ok := a.dialerToLatency[d]
		if !ok {
			continue
		}
		builder.WriteString(fmt.Sprintf("%v: %v\n", d.property.Name, latency.String()))
	}
	a.log.Traceln(builder.String())
}

// NotifyLatencyChange should be invoked when dialer every time latency and alive state changes.
func (a *AliveDialerSet) NotifyLatencyChange(dialer *Dialer, alive bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	var (
		latency    time.Duration
		hasLatency bool
		minPolicy  bool
	)

	switch a.selectionPolicy {
	case consts.DialerSelectionPolicy_MinLastLatency:
		latency, hasLatency = dialer.mustGetCollection(a.CheckTyp).Latencies10.LastLatency()
		minPolicy = true
	case consts.DialerSelectionPolicy_MinAverage10Latencies:
		latency, hasLatency = dialer.mustGetCollection(a.CheckTyp).Latencies10.AvgLatency()
		minPolicy = true
	case consts.DialerSelectionPolicy_MinMovingAverageLatencies:
		latency = dialer.mustGetCollection(a.CheckTyp).MovingAverage
		hasLatency = latency > 0
		minPolicy = true
	}

	if alive {
		index := a.dialerToIndex[dialer]
		if index >= 0 {
			// This dialer is already alive.
		} else {
			// Dialer: not alive -> alive.
			if index == -NotAlive {
				a.log.WithFields(logrus.Fields{
					"dialer":  dialer.property.Name,
					"group":   a.dialerGroupName,
					"network": a.CheckTyp.StringWithoutDns(),
				}).Infoln("NOT ALIVE -> ALIVE:")
			}
			a.dialerToIndex[dialer] = len(a.inorderedAliveDialerSet)
			a.inorderedAliveDialerSet = append(a.inorderedAliveDialerSet, dialer)
		}
	} else {
		index := a.dialerToIndex[dialer]
		if index >= 0 {
			// Dialer: alive -> not alive.
			a.log.WithFields(logrus.Fields{
				"dialer":  dialer.property.Name,
				"group":   a.dialerGroupName,
				"network": a.CheckTyp.StringWithoutDns(),
			}).Infoln("ALIVE -> NOT ALIVE:")
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
		// Calc minLatency.
		a.dialerToLatency[dialer] = latency
		if alive &&
			latency <= a.minLatency.latency && // To avoid arithmetic overflow.
			latency <= a.minLatency.latency-a.tolerance {
			a.minLatency.latency = latency
			a.minLatency.dialer = dialer
		} else if a.minLatency.dialer == dialer {
			a.minLatency.latency = latency
			if !alive || latency > a.minLatency.latency {
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
				re := "re-"
				var oldDialerName string
				if bakOldBestDialer == nil {
					// Not alive -> alive
					defer a.aliveChangeCallback(true)
					re = ""
					oldDialerName = "<nil>"
				} else {
					oldDialerName = bakOldBestDialer.property.Name
				}
				a.log.WithFields(logrus.Fields{
					string(a.selectionPolicy): a.minLatency.latency,
					"group":                   a.dialerGroupName,
					"network":                 a.CheckTyp.String(),
					"new_dialer":              a.minLatency.dialer.property.Name,
					"old_dialer":              oldDialerName,
				}).Infof("Group %vselects dialer", re)

				if a.log.IsLevelEnabled(logrus.TraceLevel) {
					a.printLatencies()
				}
			} else {
				// Alive -> not alive
				defer a.aliveChangeCallback(false)
				a.log.WithFields(logrus.Fields{
					"group":   a.dialerGroupName,
					"network": a.CheckTyp.String(),
				}).Infof("Group has no dialer alive")
			}
		}
	} else {
		if alive && minPolicy && a.minLatency.dialer == nil {
			// Use first dialer if no dialer has alive state (usually happen at the very beginning).
			a.minLatency.dialer = dialer
			a.log.WithFields(logrus.Fields{
				"group":   a.dialerGroupName,
				"network": a.CheckTyp.String(),
				"dialer":  a.minLatency.dialer.property.Name,
			}).Infof("Group selects dialer")
		}
	}
}

func (a *AliveDialerSet) calcMinLatency() {
	var minLatency = time.Hour
	var minDialer *Dialer
	for _, d := range a.inorderedAliveDialerSet {
		latency, ok := a.dialerToLatency[d]
		if !ok {
			continue
		}
		if latency < minLatency {
			minLatency = latency
			minDialer = d
		}
	}
	if a.minLatency.dialer == nil {
		a.minLatency.latency = minLatency
		a.minLatency.dialer = minDialer
	} else if minDialer != nil &&
		minLatency <= a.minLatency.latency && // To avoid arithmetic overflow.
		minLatency <= a.minLatency.latency-a.tolerance {
		a.minLatency.latency = minLatency
		a.minLatency.dialer = minDialer
	}
}
