/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	"time"

	"github.com/daeuniverse/dae/component/nativeapi"
)

// nativeAPIOperations adapts the reload manager to the contract's async
// operation resources. The store owns the response shape and retention; the
// manager owns the actual transition.
type nativeAPIOperations struct {
	store      *nativeapi.OperationStore
	manager    *reloadManager
	supervisor *runtimeSupervisor
	events     *nativeAPIProvider
	probes     *probeGate
}

func newNativeAPIOperations(manager *reloadManager, supervisor *runtimeSupervisor) *nativeAPIOperations {
	return &nativeAPIOperations{
		store:      nativeapi.NewOperationStore(nativeapi.OperationRetention, nativeapi.MaxOperationReplayKeys),
		manager:    manager,
		supervisor: supervisor,
		probes:     newProbeGate(),
	}
}

func (o *nativeAPIOperations) StartOperation(ctx context.Context, kind, idempotencyKey string) (nativeapi.OperationAccepted, error) {
	if err := ctx.Err(); err != nil {
		return nativeapi.OperationAccepted{}, err
	}
	if o == nil || o.manager == nil {
		return nativeapi.OperationAccepted{}, nativeapi.NewAPIError(503, "temporarily_unavailable",
			"the reload manager is unavailable")
	}
	accepted, replayed, err := o.store.Accept(kind, idempotencyKey)
	if err != nil {
		return nativeapi.OperationAccepted{}, err
	}
	if replayed {
		// The original request already started the transition; report its
		// response unchanged and start nothing.
		return accepted, nil
	}
	request := reloadRequest{
		isSuspend:       kind == nativeapi.OperationKindSuspend,
		requestedAt:     time.Now(),
		requestedAtMono: monotonicNowNano(),
		apiOperationID:  accepted.OperationID,
	}
	if !o.manager.queueReloadRequest(nil, request) {
		// The transition never started, so the key stays usable for the retry
		// the client is expected to make.
		o.store.ReleaseReplayKey(idempotencyKey)
		o.store.Fail(accepted.OperationID, &nativeapi.SafeError{
			Code:    "state_conflict",
			Message: "a reload is already in progress",
		})
		return nativeapi.OperationAccepted{}, &nativeapi.APIError{
			Status:  409,
			Code:    "state_conflict",
			Message: "a reload is already in progress",
			Details: map[string]string{"operation_id": accepted.OperationID},
		}
	}
	return accepted, nil
}

func (o *nativeAPIOperations) GetOperation(ctx context.Context, operationID string) (nativeapi.Operation, bool, error) {
	if err := ctx.Err(); err != nil {
		return nativeapi.Operation{}, false, err
	}
	if o == nil || o.store == nil {
		return nativeapi.Operation{}, false, nil
	}
	operation, ok := o.store.Get(operationID)
	return operation, ok, nil
}

// FollowReload reports a reload lifecycle transition for the operation that
// requested it. Signal-triggered reloads carry an ID no operation owns, so
// their notifications are ignored.
func (o *nativeAPIOperations) FollowReload(operationID string, started bool, success bool, reloadErr error) {
	if o == nil {
		return
	}
	if started {
		if o.store != nil && operationID != "" {
			o.store.Start(operationID)
			o.events.publishOperationUpdated(operationID, "running")
		}
		return
	}
	// A signal-triggered reload owns no operation but still changes the
	// generation, so it must publish the same invalidation events.
	kind, known := "", false
	if o.store != nil && operationID != "" {
		kind, known = o.store.Kind(operationID)
		if !known {
			return
		}
	}
	if !success {
		if known {
			o.store.Fail(operationID, &nativeapi.SafeError{
				Code:    "reload_rejected",
				Message: "the configuration change was rejected and the previous generation keeps running",
			})
			o.events.publishOperationUpdated(operationID, "failed")
		}
		o.events.publishRuntimeUpdated()
		return
	}
	if known {
		switch kind {
		case nativeapi.OperationKindSuspend:
			state := "suspended"
			o.store.Succeed(operationID, nativeapi.RuntimeStateResult{RuntimeState: &state})
		case nativeapi.OperationKindResume:
			state := "running"
			o.store.Succeed(operationID, nativeapi.RuntimeStateResult{RuntimeState: &state})
		default:
			var activeGenerationID *string
			var datapathGenerationID *string
			if active := o.supervisor.activeSnapshot(); active != nil {
				id := active.id
				activeGenerationID = &id
				if datapath := active.controlPlane.DatapathGenerationID(); datapath != "" {
					datapathGenerationID = &datapath
				}
			}
			o.store.Succeed(operationID, nativeapi.ReloadResult{
				ActiveGenerationID:   activeGenerationID,
				DatapathGenerationID: datapathGenerationID,
			})
		}
		o.events.publishOperationUpdated(operationID, "succeeded")
	}
	o.publishGenerationEvents()
}

// publishGenerationEvents emits the invalidation events a successful reload
// implies.
func (o *nativeAPIOperations) publishGenerationEvents() {
	if o == nil || o.events == nil {
		return
	}
	current := ""
	if active := o.supervisor.activeSnapshot(); active != nil {
		current = active.id
	}
	o.events.publishRuntimeUpdated()
	if current != "" && current != o.events.lastGenerationID {
		o.events.publishGenerationChanged(o.events.lastGenerationID, current)
		o.events.lastGenerationID = current
	}
}
