/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2023, v2rayA Organization <team@v2raya.org>
 */

package dialer

import (
	"github.com/mzz2017/softwind/pkg/fastrand"
	"github.com/sirupsen/logrus"
	"github.com/v2rayA/dae/common/consts"
	"sync"
	"time"
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
	l4proto         consts.L4ProtoStr
	ipversion       consts.IpVersionStr

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
	l4proto consts.L4ProtoStr,
	ipversion consts.IpVersionStr,
	selectionPolicy consts.DialerSelectionPolicy,
	dialers []*Dialer,
	setAlive bool,
) *AliveDialerSet {
	a := &AliveDialerSet{
		log:                     log,
		dialerGroupName:         dialerGroupName,
		l4proto:                 l4proto,
		ipversion:               ipversion,
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
		a.dialerToIndex[d] = -1
	}
	for _, d := range dialers {
		a.SetAlive(d, setAlive)
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
func (a *AliveDialerSet) GetMinLatency() *Dialer {
	return a.minLatency.dialer
}

// SetAlive should be invoked when dialer every time latency and alive state changes.
func (a *AliveDialerSet) SetAlive(dialer *Dialer, alive bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	var (
		latency    time.Duration
		hasLatency bool
		minPolicy  bool
	)

	switch a.selectionPolicy {
	case consts.DialerSelectionPolicy_MinLastLatency:
		latency, hasLatency = dialer.MustGetLatencies10(a.l4proto, a.ipversion).LastLatency()
		minPolicy = true
	case consts.DialerSelectionPolicy_MinAverage10Latencies:
		latency, hasLatency = dialer.MustGetLatencies10(a.l4proto, a.ipversion).AvgLatency()
		minPolicy = true
	}

	if alive {
		index := a.dialerToIndex[dialer]
		if index >= 0 {
			// This dialer is already alive.
		} else {
			// Not alive -> alive.
			a.dialerToIndex[dialer] = len(a.inorderedAliveDialerSet)
			a.inorderedAliveDialerSet = append(a.inorderedAliveDialerSet, dialer)
		}
	} else {
		index := a.dialerToIndex[dialer]
		if index >= 0 {
			// Alive -> not alive.
			// Remove the dialer from inorderedAliveDialerSet.
			if index >= len(a.inorderedAliveDialerSet) {
				a.log.Panicf("index:%v >= len(a.inorderedAliveDialerSet):%v", index, len(a.inorderedAliveDialerSet))
			}
			a.dialerToIndex[dialer] = -1
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
		oldBestDialer := a.minLatency.dialer
		// Calc minLatency.
		a.dialerToLatency[dialer] = latency
		if latency < a.minLatency.latency {
			a.minLatency.latency = latency
			a.minLatency.dialer = dialer
		} else if a.minLatency.dialer == dialer {
			a.minLatency.latency = time.Hour
			a.minLatency.dialer = nil
			a.calcMinLatency()
		}
		if a.minLatency.dialer != oldBestDialer {
			if a.minLatency.dialer != nil {
				a.log.WithFields(logrus.Fields{
					string(a.selectionPolicy): a.minLatency.latency,
					"group":                   a.dialerGroupName,
					"l4proto":                 a.l4proto,
					"dialer":                  a.minLatency.dialer.Name(),
				}).Infof("Group re-selects dialer")
			} else {
				a.log.WithFields(logrus.Fields{
					"group":   a.dialerGroupName,
					"l4proto": a.l4proto,
				}).Infof("Group has no dialer alive")
			}
		}
	} else {
		if alive && minPolicy && a.minLatency.dialer == nil {
			// Use first dialer if no dialer has alive state (usually happen at the very beginning).
			a.minLatency.dialer = dialer
			a.log.WithFields(logrus.Fields{
				"group":   a.dialerGroupName,
				"l4proto": a.l4proto,
				"dialer":  a.minLatency.dialer.Name(),
			}).Infof("Group selects dialer")
		}
	}
}

func (a *AliveDialerSet) calcMinLatency() {
	for _, d := range a.inorderedAliveDialerSet {
		latency := a.dialerToLatency[d]
		if latency < a.minLatency.latency {
			a.minLatency.latency = latency
			a.minLatency.dialer = d
		}
	}
}
