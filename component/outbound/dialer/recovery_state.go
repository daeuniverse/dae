/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/sirupsen/logrus"
)

type dialerRecoveryManager struct {
	owner         *Dialer
	recoveryState *[3]dialerRecoveryState
	lastPunish    *[3]atomic.Int64
}

func newDialerRecoveryManager(owner *Dialer) *dialerRecoveryManager {
	return &dialerRecoveryManager{
		owner:         owner,
		recoveryState: &owner.recoveryState,
		lastPunish:    &owner.lastPunish,
	}
}

func (d *Dialer) ensureRecoveryManager() *dialerRecoveryManager {
	if d == nil {
		return nil
	}
	d.recoveryManagerMu.Lock()
	defer d.recoveryManagerMu.Unlock()
	if d.recoveryManager == nil || d.recoveryManager.owner != d {
		d.recoveryManager = newDialerRecoveryManager(d)
	}
	return d.recoveryManager
}

func (m *dialerRecoveryManager) state(idx int) *dialerRecoveryState {
	return &m.recoveryState[idx]
}

func (m *dialerRecoveryManager) snapshot(nowNano int64) [3]DialerRecoveryHealthSnapshot {
	var snapshot [3]DialerRecoveryHealthSnapshot
	if m == nil {
		return snapshot
	}
	for idx := range m.recoveryState {
		state := m.state(idx)
		state.Lock()
		snapshot[idx] = DialerRecoveryHealthSnapshot{
			BackoffLevel:       state.backoffLevel,
			StableSuccessCount: state.stableSuccessCount,
			LastPunishUnixNano: m.lastPunish[idx].Load(),
		}
		if state.confirmTimer != nil && state.pendingNetworkType != nil && state.confirmDeadlineUnixNano > nowNano {
			snapshot[idx].PendingNetworkType = cloneNetworkType(state.pendingNetworkType)
			snapshot[idx].PendingConfirmDelay = time.Duration(state.confirmDeadlineUnixNano - nowNano)
		}
		state.Unlock()
	}
	return snapshot
}

func (m *dialerRecoveryManager) restore(snapshot [3]DialerRecoveryHealthSnapshot) {
	if m == nil {
		return
	}
	for idx := range m.recoveryState {
		recoverySnapshot := snapshot[idx]
		state := m.state(idx)
		state.Lock()
		if state.confirmTimer != nil {
			state.confirmTimer.Stop()
			state.confirmTimer = nil
		}
		state.pendingNetworkType = nil
		state.confirmDeadlineUnixNano = 0
		state.backoffLevel = recoverySnapshot.BackoffLevel
		state.stableSuccessCount = recoverySnapshot.StableSuccessCount
		state.Unlock()

		m.lastPunish[idx].Store(recoverySnapshot.LastPunishUnixNano)
		if recoverySnapshot.PendingNetworkType == nil {
			continue
		}
		delay := max(recoverySnapshot.PendingConfirmDelay, 0)
		maxDelay := m.getRecoveryBackoffDurationByIndex(idx)
		if maxDelay > 0 && delay > maxDelay {
			delay = maxDelay
		}
		m.armRecoveryConfirmationFromSnapshot(idx, recoverySnapshot.PendingNetworkType, delay)
	}
}

func (m *dialerRecoveryManager) indexForType(typ *NetworkType) int {
	if typ == nil || typ.L4Proto == consts.L4ProtoStr_TCP {
		return idxTcp
	}
	if typ.EffectiveUdpHealthDomain() == UdpHealthDomainDns {
		return idxDnsUdp
	}
	return idxDataUdp
}

func (m *dialerRecoveryManager) indexForProto(proto consts.L4ProtoStr) int {
	if proto == consts.L4ProtoStr_UDP {
		return idxDnsUdp
	}
	return idxTcp
}

func (m *dialerRecoveryManager) init(checkInterval time.Duration) {
	maxBackoff := max(time.Duration(float64(checkInterval)*2.0/3.0), minRecoveryBackoff)
	for i := range m.recoveryState {
		state := m.state(i)
		state.Lock()
		state.maxBackoff = maxBackoff
		state.Unlock()
	}
	m.owner.Log.WithFields(logrus.Fields{
		"dialer":         m.owner.Property().Name,
		"check_interval": checkInterval.String(),
		"max_backoff":    maxBackoff.String(),
	}).Debugln("Recovery detection initialized")
}

func (m *dialerRecoveryManager) trigger(target *NetworkType) {
	select {
	case <-m.owner.ctx.Done():
		m.owner.Log.WithFields(logrus.Fields{
			"dialer": m.owner.Property().Name,
		}).Traceln("Recovery detection skipped: dialer is shutting down")
		return
	default:
	}

	protoIdx := m.indexForType(target)
	state := m.state(protoIdx)
	state.Lock()
	defer state.Unlock()

	if state.confirmTimer != nil {
		m.owner.Log.WithFields(logrus.Fields{
			"dialer": m.owner.Property().Name,
			"proto":  target.L4Proto,
		}).Traceln("Recovery detection already in progress, skip")
		return
	}

	backoff := m.owner.calculateBackoffDurationLocked(state.backoffLevel, state.maxBackoff)
	m.owner.Log.WithFields(logrus.Fields{
		"dialer":        m.owner.Property().Name,
		"network":       target.String(),
		"backoff":       backoff.String(),
		"backoff_level": state.backoffLevel,
	}).Debugln("Recovery detection scheduled with exponential backoff")

	state.pendingNetworkType = cloneNetworkType(target)
	state.confirmDeadlineUnixNano = time.Now().Add(backoff).UnixNano()
	confirmSequence := state.nextConfirmSequenceLocked()
	networkType := cloneNetworkType(target)
	state.confirmTimer = time.AfterFunc(backoff, func() {
		m.confirm(networkType, confirmSequence)
	})
}

func (m *dialerRecoveryManager) armRecoveryConfirmationFromSnapshot(protoIdx int, target *NetworkType, delay time.Duration) {
	if m == nil || target == nil {
		return
	}
	select {
	case <-m.owner.ctx.Done():
		return
	default:
	}
	if delay < 0 {
		delay = 0
	}
	networkType := cloneNetworkType(target)
	if networkType == nil {
		return
	}
	state := m.state(protoIdx)
	state.Lock()
	defer state.Unlock()
	if state.confirmTimer != nil {
		state.confirmTimer.Stop()
		state.confirmTimer = nil
	}
	state.pendingNetworkType = cloneNetworkType(networkType)
	state.confirmDeadlineUnixNano = time.Now().Add(delay).UnixNano()
	confirmSequence := state.nextConfirmSequenceLocked()
	state.confirmTimer = time.AfterFunc(delay, func() {
		m.confirm(networkType, confirmSequence)
	})
}

func (m *dialerRecoveryManager) confirm(networkType *NetworkType, confirmSequence uint64) {
	select {
	case <-m.owner.ctx.Done():
		m.owner.Log.WithFields(logrus.Fields{
			"dialer":  m.owner.Property().Name,
			"network": networkType.String(),
		}).Debugln("Recovery confirmation aborted: dialer is shutting down")
		return
	default:
	}

	protoIdx := m.indexForType(networkType)
	state := m.state(protoIdx)
	state.Lock()
	if state.confirmSequence != confirmSequence ||
		!networkTypesEqual(state.pendingNetworkType, networkType) {
		state.Unlock()
		return
	}
	state.confirmTimer = nil
	state.confirmDeadlineUnixNano = 0
	state.pendingNetworkType = nil
	currentBackoffLevel := state.backoffLevel
	state.Unlock()

	select {
	case <-m.owner.ctx.Done():
		m.owner.Log.WithFields(logrus.Fields{
			"dialer":  m.owner.Property().Name,
			"network": networkType.String(),
		}).Debugln("Recovery confirmation aborted: dialer is shutting down")
		return
	default:
	}

	state.Lock()
	alive := m.owner.isRecoveryTypeAlive(networkType)
	if !alive {
		state.Unlock()
		m.owner.Log.WithFields(logrus.Fields{
			"dialer":  m.owner.Property().Name,
			"proto":   networkType.L4Proto,
			"network": networkType.String(),
		}).Debugln("Recovery confirmation failed: all IP versions unhealthy, will retry on next health check")
		return
	}

	if state.backoffLevel == currentBackoffLevel {
		if state.backoffLevel > 0 {
			state.backoffLevel--
		}
		m.owner.Log.WithFields(logrus.Fields{
			"dialer":        m.owner.Property().Name,
			"proto":         networkType.L4Proto,
			"network":       networkType.String(),
			"backoff_level": state.backoffLevel,
		}).Infoln("Recovery confirmed after exponential backoff: penalty decreased")
	} else {
		m.owner.Log.WithFields(logrus.Fields{
			"dialer":        m.owner.Property().Name,
			"network":       networkType.String(),
			"backoff_level": state.backoffLevel,
		}).Debugln("Recovery confirmation skipped: backoff level was reset by concurrent failure")
	}
	state.Unlock()
}

func (m *dialerRecoveryManager) cancelPendingConfirmationByIndex(protoIdx int, proto consts.L4ProtoStr) {
	state := m.state(protoIdx)
	state.Lock()
	defer state.Unlock()
	if state.confirmTimer != nil {
		state.confirmTimer.Stop()
		state.confirmTimer = nil
		state.confirmDeadlineUnixNano = 0
		state.pendingNetworkType = nil
		m.owner.Log.WithFields(logrus.Fields{
			"dialer": m.owner.Property().Name,
			"proto":  proto,
		}).Debugln("Pending recovery confirmation cancelled due to new failure")
	}
}

func (m *dialerRecoveryManager) getRecoveryBackoffDurationByIndex(protoIdx int) time.Duration {
	state := m.state(protoIdx)
	state.Lock()
	defer state.Unlock()
	return m.owner.calculateBackoffDurationLocked(state.backoffLevel, state.maxBackoff)
}

func (m *dialerRecoveryManager) resetStabilityCountByIndex(protoIdx int) {
	state := m.state(protoIdx)
	state.Lock()
	defer state.Unlock()
	state.stableSuccessCount = 0
}

func (m *dialerRecoveryManager) incrementBackoffLevelByIndex(protoIdx int) {
	now := CachedTimeNano()
	if now-m.lastPunish[protoIdx].Swap(now) < int64(time.Second) {
		return
	}
	state := m.state(protoIdx)
	state.Lock()
	defer state.Unlock()
	if state.backoffLevel < maxBackoffLevel {
		state.backoffLevel++
	}
}

func (m *dialerRecoveryManager) getBackoffLevelByIndex(protoIdx int) int {
	state := m.state(protoIdx)
	state.Lock()
	defer state.Unlock()
	return state.backoffLevel
}

func (m *dialerRecoveryManager) getBackoffPenaltyByIndex(protoIdx int) time.Duration {
	state := m.state(protoIdx)
	state.Lock()
	defer state.Unlock()
	if state.backoffLevel == 0 {
		return 0
	}
	return m.owner.calculateBackoffDurationLocked(state.backoffLevel, state.maxBackoff) / 20
}

func (m *dialerRecoveryManager) notifyPeriodicCheckResultByIndex(protoIdx int, proto consts.L4ProtoStr, success bool, failure bool) {
	if failure {
		m.resetStabilityCountByIndex(protoIdx)
		return
	}
	if !success {
		return
	}
	state := m.state(protoIdx)
	state.Lock()
	defer state.Unlock()
	if state.backoffLevel == 0 {
		state.stableSuccessCount = 0
		return
	}
	state.stableSuccessCount++
	if state.stableSuccessCount >= 2 {
		state.stableSuccessCount = 0
		state.backoffLevel--
		m.owner.Log.WithFields(logrus.Fields{
			"dialer":        m.owner.Property().Name,
			"proto":         proto,
			"backoff_level": state.backoffLevel,
		}).Infoln("Recovery confirmed: long-term stability detected, backoff level decreased")
	}
}
