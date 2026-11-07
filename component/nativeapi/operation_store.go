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

// MaxOperationRecords bounds retained operation records independently of the
// replay-key budget. A rejected transition still leaves a readable operation
// behind (the contract names it in the 409), but a client that retries while a
// reload is busy must not grow the store without limit.
const MaxOperationRecords = 4096

// Operation kinds this engine starts.
const (
	OperationKindReload          = "reload"
	OperationKindSuspend         = "suspend"
	OperationKindResume          = "resume"
	OperationKindProbe           = "probe"
	OperationKindNodeCreate      = "node_create"
	OperationKindNodeUpdate      = "node_update"
	OperationKindNodeDelete      = "node_delete"
	OperationKindProviderRefresh = "provider_refresh"
	OperationKindGroupUpdate     = "group_update"
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
	// reserved holds keys whose operation was created but not yet queued. They
	// are not replayable yet: a concurrent request with the same key must not
	// receive a 202 body for work that may still be rejected.
	reserved map[string]storedReplay
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
	kind string
	// scope identifies the request the key was first used for (method, path and
	// body in the caller's terms). A key reused for another request of the same
	// kind is a conflict, not a replay: the original body describes work that
	// was never done for the second caller.
	scope    string
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
		reserved:      make(map[string]storedReplay),
	}
}

// Accept records a queued operation and returns the 202 body. A repeated
// Idempotency-Key replays the original body when the request matches (replayed
// is true, so the caller must not start the work twice), and reports a
// conflict when the key names another request. Scope is the caller's identity
// for the request: comparing the kind alone let a key used to refresh one
// subscription replay that operation for another subscription.
func (s *OperationStore) Accept(kind, scope, idempotencyKey string) (OperationAccepted, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked()

	if idempotencyKey != "" {
		if previous, ok := s.replay[idempotencyKey]; ok {
			if previous.kind != kind || previous.scope != scope {
				return OperationAccepted{}, false, NewAPIError(http.StatusConflict, codeIdempotencyConflict,
					"the Idempotency-Key was already used for a different request")
			}
			return previous.accepted, true, nil
		}
		if _, busy := s.reserved[idempotencyKey]; busy {
			// The first request is still being admitted. Answering 202 here would
			// promise work that the admission may still reject.
			return OperationAccepted{}, false, NewAPIError(http.StatusConflict, codeIdempotencyConflict,
				"the Idempotency-Key is being admitted by another request")
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
		s.reserved[idempotencyKey] = storedReplay{kind: kind, scope: scope, accepted: accepted}
	}
	return accepted, false, nil
}

// Replay reports whether an Idempotency-Key already describes this request
// without creating an operation. Write paths call it before touching the
// filesystem, so a replayed key cannot cause a side effect that the replayed
// operation will not reload. It returns the same conflicts Accept would.
func (s *OperationStore) Replay(kind, scope, idempotencyKey string) (OperationAccepted, bool, error) {
	if s == nil || idempotencyKey == "" {
		return OperationAccepted{}, false, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked()
	if previous, ok := s.replay[idempotencyKey]; ok {
		if previous.kind != kind || previous.scope != scope {
			return OperationAccepted{}, false, NewAPIError(http.StatusConflict, codeIdempotencyConflict,
				"the Idempotency-Key was already used for a different request")
		}
		return previous.accepted, true, nil
	}
	if _, busy := s.reserved[idempotencyKey]; busy {
		return OperationAccepted{}, false, NewAPIError(http.StatusConflict, codeIdempotencyConflict,
			"the Idempotency-Key is being admitted by another request")
	}
	return OperationAccepted{}, false, nil
}

// CommitReplayKey publishes a reserved key, so a retry replays the accepted
// body. It is called only after the work is queued: the key and the queue entry
// must become visible together, or a concurrent caller could see one without
// the other.
func (s *OperationStore) CommitReplayKey(idempotencyKey string) {
	if s == nil || idempotencyKey == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	reserved, ok := s.reserved[idempotencyKey]
	if !ok {
		return
	}
	delete(s.reserved, idempotencyKey)
	s.replay[idempotencyKey] = reserved
	s.replayOrder = append(s.replayOrder, idempotencyKey)
	s.evictReplayKeysLocked()
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
	delete(s.reserved, idempotencyKey)
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

	// Bound retained records even when every request is a finished failure.
	// Unfinished operations are never evicted, and a finished operation that
	// still holds an Idempotency-Key is evicted only when no keyless record is
	// left: dropping it would turn an idempotent retry into a second write or a
	// second reload. Only once the cap cannot be met that way does the oldest
	// finished record (and the keys that pointed at it) go.
	if len(s.operations) > MaxOperationRecords && len(s.order) > 0 {
		protected := make(map[string]struct{}, len(s.replay))
		for _, record := range s.replay {
			protected[record.accepted.OperationID] = struct{}{}
		}
		for len(s.operations) > MaxOperationRecords && len(s.order) > 0 {
			victim := -1
			fallback := -1
			for index, operationID := range s.order {
				operation, ok := s.operations[operationID]
				if !ok || operation.finishedAt == nil {
					continue
				}
				if fallback < 0 {
					fallback = index
				}
				if _, keep := protected[operationID]; !keep {
					victim = index
					break
				}
			}
			if victim < 0 {
				victim = fallback
			}
			if victim < 0 {
				break
			}
			operationID := s.order[victim]
			delete(s.operations, operationID)
			s.order = append(s.order[:victim], s.order[victim+1:]...)
		}
	}
	for key, record := range s.replay {
		if _, retained := s.operations[record.accepted.OperationID]; !retained {
			delete(s.replay, key)
		}
	}
	keptReplay := s.replayOrder[:0]
	for _, key := range s.replayOrder {
		if _, ok := s.replay[key]; ok {
			keptReplay = append(keptReplay, key)
		}
	}
	s.replayOrder = keptReplay
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
