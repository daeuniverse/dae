/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package nativeapi

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// Operation status values from the contract.
const (
	OperationStatusQueued    = "queued"
	OperationStatusRunning   = "running"
	OperationStatusSucceeded = "succeeded"
	OperationStatusFailed    = "failed"
)

// Operation kinds this engine starts.
const (
	OperationKindReload  = "reload"
	OperationKindSuspend = "suspend"
	OperationKindResume  = "resume"
	OperationKindProbe   = "probe"
)

// OperationStore is the bounded in-memory operation record. Unfinished
// operations are never evicted; finished ones expire after the retention
// window, and Idempotency-Key replays keep their original response.
type OperationStore struct {
	mu            sync.Mutex
	now           func() time.Time
	retention     time.Duration
	maxReplayKeys int

	operations map[string]*storedOperation
	order      []string

	replay      map[string]storedReplay
	replayOrder []string
}

type storedOperation struct {
	accepted   OperationAccepted
	createdAt  time.Time
	startedAt  *time.Time
	finishedAt *time.Time
	status     string
	result     any
	apiError   *SafeError
}

type storedReplay struct {
	kind     string
	accepted OperationAccepted
}

// NewOperationStore returns a store with the given retention and replay-key
// budget. Non-positive values fall back to the contract defaults.
func NewOperationStore(retention time.Duration, maxReplayKeys int) *OperationStore {
	if retention <= 0 {
		retention = OperationRetention
	}
	if maxReplayKeys <= 0 {
		maxReplayKeys = MaxOperationReplayKeys
	}
	return &OperationStore{
		now:           time.Now,
		retention:     retention,
		maxReplayKeys: maxReplayKeys,
		operations:    make(map[string]*storedOperation),
		replay:        make(map[string]storedReplay),
	}
}

// Accept records a queued operation and returns the 202 body. A repeated
// Idempotency-Key replays the original body when the request matches (replayed
// is true, so the caller must not start the work twice), and reports a
// conflict when it names another kind.
func (s *OperationStore) Accept(kind, idempotencyKey string) (OperationAccepted, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked()

	if idempotencyKey != "" {
		if previous, ok := s.replay[idempotencyKey]; ok {
			if previous.kind != kind {
				return OperationAccepted{}, false, NewAPIError(http.StatusConflict, codeIdempotencyConflict,
					"the Idempotency-Key was already used for a different request")
			}
			return previous.accepted, true, nil
		}
	}

	operationID := newOperationID()
	accepted := OperationAccepted{
		OperationID: operationID,
		Kind:        kind,
		Status:      OperationStatusQueued,
		Href:        BasePath + "/operations/" + operationID,
	}
	s.operations[operationID] = &storedOperation{
		accepted:  accepted,
		createdAt: s.now(),
		status:    OperationStatusQueued,
	}
	s.order = append(s.order, operationID)

	if idempotencyKey != "" {
		s.replay[idempotencyKey] = storedReplay{kind: kind, accepted: accepted}
		s.replayOrder = append(s.replayOrder, idempotencyKey)
		s.evictReplayKeysLocked()
	}
	return accepted, false, nil
}

// ReleaseReplayKey forgets an Idempotency-Key binding. A request that never
// started, such as a rejected 409, must not consume the key: otherwise a retry
// would replay a body for work nobody queued and could never be retried.
func (s *OperationStore) ReleaseReplayKey(idempotencyKey string) {
	if s == nil || idempotencyKey == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.replay, idempotencyKey)
	kept := s.replayOrder[:0]
	for _, key := range s.replayOrder {
		if key == idempotencyKey {
			continue
		}
		kept = append(kept, key)
	}
	s.replayOrder = kept
}

// Start marks an accepted operation as running. Unknown IDs are ignored so a
// signal-triggered reload, which owns no operation record, is harmless.
func (s *OperationStore) Start(operationID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	operation, ok := s.operations[operationID]
	if !ok || operation.status != OperationStatusQueued {
		return
	}
	started := s.now()
	operation.startedAt = &started
	operation.status = OperationStatusRunning
}

// Succeed completes an operation successfully.
func (s *OperationStore) Succeed(operationID string, result any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	operation, ok := s.operations[operationID]
	if !ok || isTerminalOperationStatus(operation.status) {
		return
	}
	finished := s.now()
	if operation.startedAt == nil {
		operation.startedAt = &finished
	}
	operation.finishedAt = &finished
	operation.status = OperationStatusSucceeded
	operation.result = result
}

// Fail completes an operation with an engine-defined safe error.
func (s *OperationStore) Fail(operationID string, safeErr *SafeError) {
	s.mu.Lock()
	defer s.mu.Unlock()
	operation, ok := s.operations[operationID]
	if !ok || isTerminalOperationStatus(operation.status) {
		return
	}
	finished := s.now()
	if operation.startedAt == nil {
		operation.startedAt = &finished
	}
	operation.finishedAt = &finished
	operation.status = OperationStatusFailed
	operation.apiError = safeErr
}

// Get returns one operation and whether it is still retained.
func (s *OperationStore) Get(operationID string) (Operation, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked()
	operation, ok := s.operations[operationID]
	if !ok {
		return Operation{}, false
	}
	return operation.snapshot(), true
}

// Kind reports the kind recorded for an accepted operation.
func (s *OperationStore) Kind(operationID string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	operation, ok := s.operations[operationID]
	if !ok {
		return "", false
	}
	return operation.accepted.Kind, true
}

func (o *storedOperation) snapshot() Operation {
	operation := Operation{
		OperationID: o.accepted.OperationID,
		Kind:        o.accepted.Kind,
		Status:      o.status,
		CreatedAt:   o.createdAt.UTC().Format(time.RFC3339),
		StartedAt:   formatOptionalTime(o.startedAt),
		FinishedAt:  formatOptionalTime(o.finishedAt),
		Result:      o.result,
		Error:       o.apiError,
	}
	return operation
}

func formatOptionalTime(value *time.Time) *string {
	if value == nil {
		return nil
	}
	formatted := value.UTC().Format(time.RFC3339)
	return &formatted
}

func isTerminalOperationStatus(status string) bool {
	return status == OperationStatusSucceeded || status == OperationStatusFailed
}

func (s *OperationStore) pruneLocked() {
	cutoff := s.now().Add(-s.retention)
	kept := s.order[:0]
	for _, operationID := range s.order {
		operation, ok := s.operations[operationID]
		if !ok {
			continue
		}
		if operation.finishedAt != nil && operation.finishedAt.Before(cutoff) {
			delete(s.operations, operationID)
			continue
		}
		kept = append(kept, operationID)
	}
	s.order = kept

	replayKept := s.replayOrder[:0]
	for _, key := range s.replayOrder {
		record, ok := s.replay[key]
		if !ok {
			continue
		}
		if _, retained := s.operations[record.accepted.OperationID]; !retained {
			delete(s.replay, key)
			continue
		}
		replayKept = append(replayKept, key)
	}
	s.replayOrder = replayKept
}

func (s *OperationStore) evictReplayKeysLocked() {
	for len(s.replayOrder) > s.maxReplayKeys {
		oldest := s.replayOrder[0]
		s.replayOrder = s.replayOrder[1:]
		// Only finished operations may lose their replay key.
		if record, ok := s.replay[oldest]; ok {
			if operation, retained := s.operations[record.accepted.OperationID]; retained &&
				!isTerminalOperationStatus(operation.status) {
				s.replayOrder = append(s.replayOrder, oldest)
				break
			}
			delete(s.replay, oldest)
		}
	}
}

func newOperationID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("op-%d", time.Now().UnixNano())
	}
	return "op-" + hex.EncodeToString(b[:])
}
