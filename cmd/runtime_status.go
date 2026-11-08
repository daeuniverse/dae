/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync/atomic"
	"time"
)

type runtimeLifecycleState string

const (
	runtimeStateStarting  runtimeLifecycleState = "starting"
	runtimeStateRunning   runtimeLifecycleState = "running"
	runtimeStateReloading runtimeLifecycleState = "reloading"
	runtimeStateSuspended runtimeLifecycleState = "suspended"
	runtimeStateDraining  runtimeLifecycleState = "draining"
	runtimeStateFailed    runtimeLifecycleState = "failed"
)

type lastReloadRecord struct {
	OperationID string
	Status      string
	FinishedAt  time.Time
	Error       string
}

type runtimeStatusSnapshot struct {
	InstanceID string
	StartedAt  time.Time
	State      string
	LastReload *lastReloadRecord
}

// runtimeStatus is the process-wide runtime identity and lifecycle state
// exposed by the native API. It is intentionally independent of any one
// control-plane generation.
type runtimeStatus struct {
	instanceID string
	startedAt  time.Time
	state      atomic.Value // string
	lastReload atomic.Pointer[lastReloadRecord]
}

func newRuntimeStatus() *runtimeStatus {
	s := &runtimeStatus{
		instanceID: newOpaqueID("instance"),
		startedAt:  time.Now(),
	}
	s.state.Store(string(runtimeStateStarting))
	return s
}

func (s *runtimeStatus) setState(state runtimeLifecycleState) {
	if s == nil {
		return
	}
	s.state.Store(string(state))
}

func (s *runtimeStatus) getState() string {
	if s == nil {
		return ""
	}
	state, _ := s.state.Load().(string)
	return state
}

func (s *runtimeStatus) recordLastReload(operationID, status string, err error) {
	if s == nil {
		return
	}
	record := &lastReloadRecord{
		OperationID: operationID,
		Status:      status,
		FinishedAt:  time.Now(),
	}
	if err != nil {
		// Keep the API message safe; detailed engine errors stay in the log.
		record.Error = "reload failed"
	}
	s.lastReload.Store(record)
}

func (s *runtimeStatus) snapshot() runtimeStatusSnapshot {
	if s == nil {
		return runtimeStatusSnapshot{}
	}
	snapshot := runtimeStatusSnapshot{
		InstanceID: s.instanceID,
		StartedAt:  s.startedAt,
		State:      s.getState(),
	}
	if record := s.lastReload.Load(); record != nil {
		copied := *record
		snapshot.LastReload = &copied
	}
	return snapshot
}

func newOpaqueID(prefix string) string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
	}
	return prefix + "-" + hex.EncodeToString(b[:])
}

func newGenerationID() string {
	return newOpaqueID("gen")
}

func newOperationID() string {
	return newOpaqueID("op")
}
