/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/nativeapi"
	"github.com/stretchr/testify/require"
)

func newTestOperations() (*nativeAPIOperations, *reloadManager) {
	manager := newReloadManager(make(chan reloadRequest, 1), make(chan struct{}, 1), make(chan os.Signal, 1))
	return newNativeAPIOperations(manager, newRuntimeSupervisor(nil)), manager
}

func TestNativeAPIOperationsFollowReloadLifecycle(t *testing.T) {
	operations, manager := newTestOperations()
	ctx := context.Background()

	accepted, err := operations.StartOperation(ctx, nativeapi.OperationKindReload, "", "")
	require.NoError(t, err)
	require.Equal(t, nativeapi.OperationKindReload, accepted.Kind)
	require.Equal(t, nativeapi.BasePath+"/operations/"+accepted.OperationID, accepted.Href)

	var request reloadRequest
	select {
	case request = <-manager.reloadReqs:
	default:
		t.Fatal("reload request was not queued")
	}
	require.Equal(t, accepted.OperationID, request.apiOperationID)
	require.False(t, request.isSuspend)

	operations.FollowReload(accepted.OperationID, true, false, nil)
	operation, ok, err := operations.GetOperation(ctx, accepted.OperationID)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, nativeapi.OperationStatusRunning, operation.Status)
	require.NotNil(t, operation.StartedAt)

	operations.FollowReload(accepted.OperationID, false, true, nil)
	operation, _, _ = operations.GetOperation(ctx, accepted.OperationID)
	require.Equal(t, nativeapi.OperationStatusSucceeded, operation.Status)
	require.NotNil(t, operation.FinishedAt)
	require.IsType(t, nativeapi.ReloadResult{}, operation.Result)
}

func TestNativeAPIOperationsSuspendAndResumeResults(t *testing.T) {
	operations, manager := newTestOperations()
	ctx := context.Background()

	suspend, err := operations.StartOperation(ctx, nativeapi.OperationKindSuspend, "", "")
	require.NoError(t, err)
	suspendRequest := <-manager.reloadReqs
	require.True(t, suspendRequest.isSuspend)
	operations.FollowReload(suspend.OperationID, true, false, nil)
	operations.FollowReload(suspend.OperationID, false, true, nil)
	suspendOperation, _, _ := operations.GetOperation(ctx, suspend.OperationID)
	result, ok := suspendOperation.Result.(nativeapi.RuntimeStateResult)
	require.True(t, ok)
	require.NotNil(t, result.RuntimeState)
	require.Equal(t, "suspended", *result.RuntimeState)

	// A completed reload releases the pending slot, so resume is accepted.
	manager.reloadPending.Store(false)
	manager.reloadActive.Store(false)

	resume, err := operations.StartOperation(ctx, nativeapi.OperationKindResume, "", "")
	require.NoError(t, err)
	resumeRequest := <-manager.reloadReqs
	require.False(t, resumeRequest.isSuspend)
	operations.FollowReload(resume.OperationID, true, false, nil)
	operations.FollowReload(resume.OperationID, false, true, nil)
	resumeOperation, _, _ := operations.GetOperation(ctx, resume.OperationID)
	result, ok = resumeOperation.Result.(nativeapi.RuntimeStateResult)
	require.True(t, ok)
	require.Equal(t, "running", *result.RuntimeState)
}

func TestNativeAPIOperationsRejectsConcurrentReload(t *testing.T) {
	operations, _ := newTestOperations()
	ctx := context.Background()

	_, err := operations.StartOperation(ctx, nativeapi.OperationKindReload, "", "")
	require.NoError(t, err)
	accepted, err := operations.StartOperation(ctx, nativeapi.OperationKindReload, "", "")
	require.Error(t, err)
	require.Empty(t, accepted.OperationID)
	apiErr, ok := err.(*nativeapi.APIError)
	require.True(t, ok)
	require.Equal(t, 409, apiErr.Status)
	require.Equal(t, "state_conflict", apiErr.Code)
}

func TestNativeAPIOperationsIdempotentReplay(t *testing.T) {
	operations, manager := newTestOperations()
	ctx := context.Background()

	first, err := operations.StartOperation(ctx, nativeapi.OperationKindReload, "", "key-1")
	require.NoError(t, err)
	<-manager.reloadReqs

	// Replaying the same key and body returns the original operation instead
	// of queueing another reload.
	manager.reloadPending.Store(false)
	manager.reloadActive.Store(false)
	second, err := operations.StartOperation(ctx, nativeapi.OperationKindReload, "", "key-1")
	require.NoError(t, err)
	require.Equal(t, first.OperationID, second.OperationID)
	select {
	case unexpected := <-manager.reloadReqs:
		t.Fatalf("replay queued another reload: %#v", unexpected)
	default:
	}

	// The same key with a different body conflicts.
	_, err = operations.StartOperation(ctx, nativeapi.OperationKindSuspend, "", "key-1")
	require.Error(t, err)
	apiErr, ok := err.(*nativeapi.APIError)
	require.True(t, ok)
	require.Equal(t, 409, apiErr.Status)
	require.Equal(t, "idempotency_conflict", apiErr.Code)
}

// A rejected transition must leave a readable, failed operation behind and
// name it in the conflict so a client can follow up.
func TestNativeAPIOperationsRecordsRejectedReload(t *testing.T) {
	operations, manager := newTestOperations()
	ctx := context.Background()

	_, err := operations.StartOperation(ctx, nativeapi.OperationKindReload, "", "key-2")
	require.NoError(t, err)
	<-manager.reloadReqs

	_, err = operations.StartOperation(ctx, nativeapi.OperationKindReload, "", "key-3")
	require.Error(t, err)
	apiErr, ok := err.(*nativeapi.APIError)
	require.True(t, ok)
	require.Equal(t, 409, apiErr.Status)
	details, ok := apiErr.Details.(map[string]string)
	require.True(t, ok)

	operation, found, err := operations.GetOperation(ctx, details["operation_id"])
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, nativeapi.OperationStatusFailed, operation.Status)
	require.NotNil(t, operation.Error)
	require.Equal(t, "state_conflict", operation.Error.Code)

	// The rejected request must not consume the key: once the in-flight reload
	// finishes, the same key queues a fresh operation instead of replaying the
	// failed one.
	manager.reloadPending.Store(false)
	manager.reloadActive.Store(false)
	retried, err := operations.StartOperation(ctx, nativeapi.OperationKindReload, "", "key-3")
	require.NoError(t, err)
	require.NotEqual(t, details["operation_id"], retried.OperationID)
	select {
	case queued := <-manager.reloadReqs:
		require.Equal(t, retried.OperationID, queued.apiOperationID)
	default:
		t.Fatal("retry did not queue a reload")
	}
}

func TestFollowReloadPublishesEventsForSignalReloads(t *testing.T) {
	// A signal-triggered reload owns no operation id the store knows, but it still
	// changes the generation. The observer used to return before publishing, so a
	// client watching /events never saw generation.changed for SIGHUP reloads.
	operations, _ := newTestOperations()
	hub := newFrameHub("test-instance", "events", 8, time.Minute, 4)
	operations.events = &nativeAPIProvider{eventHub: hub, status: newRuntimeStatus()}

	operations.FollowReload("signal-reload", true, false, nil)
	operations.FollowReload("signal-reload", false, true, nil)

	found := false
	for i := 0; i < hub.length; i++ {
		if hub.frames[(hub.start+i)%len(hub.frames)].event == "runtime.updated" {
			found = true
		}
	}
	if !found {
		t.Fatal("an unknown operation id must still publish the reload invalidation events")
	}

	// The operation bookkeeping must still be skipped: nothing was created for it.
	if _, ok, err := operations.GetOperation(context.Background(), "signal-reload"); err != nil || ok {
		t.Fatalf("a signal reload must not create an operation record: ok=%v err=%v", ok, err)
	}
}

func TestOperationResultReportsTheResourceNotTheReload(t *testing.T) {
	// The contract asks a write operation for the resource it produced: a Node,
	// a deletion count or a Provider. Every write used to report the reload's
	// generation ids instead, which is not what a client reads.
	operations, _ := newTestOperations()
	ctx := context.Background()

	drainReload := func() {
		<-operations.manager.reloadReqs
		// No worker is running in this test, so the transition must be released
		// by hand before the next write can queue its own.
		operations.manager.reloadActive.Store(false)
		operations.manager.reloadPending.Store(false)
	}

	created, err := operations.StartOperation(ctx, nativeapi.OperationKindNodeCreate, "scope-1", "")
	require.NoError(t, err)
	drainReload()
	operations.SetResultResolver(created.OperationID, func() (any, error) {
		return nativeapi.Node{ID: "n_mock", Name: "mock-01"}, nil
	})
	operations.FollowReload(created.OperationID, false, true, nil)
	operation, ok, err := operations.GetOperation(ctx, created.OperationID)
	require.NoError(t, err)
	require.True(t, ok)
	node, isNode := operation.Result.(nativeapi.Node)
	require.True(t, isNode, "result = %T, want nativeapi.Node", operation.Result)
	require.Equal(t, "n_mock", node.ID)

	deleted, err := operations.StartOperation(ctx, nativeapi.OperationKindNodeDelete, "scope-2", "")
	require.NoError(t, err)
	drainReload()
	operations.SetResultResolver(deleted.OperationID, func() (any, error) {
		return nativeapi.NodeDeleteResult{Deleted: 1}, nil
	})
	operations.FollowReload(deleted.OperationID, false, true, nil)
	operation, _, _ = operations.GetOperation(ctx, deleted.OperationID)
	deletedResult, isDelete := operation.Result.(nativeapi.NodeDeleteResult)
	require.True(t, isDelete, "result = %T, want nativeapi.NodeDeleteResult", operation.Result)
	require.Equal(t, 1, deletedResult.Deleted)

	refreshed, err := operations.StartOperation(ctx, nativeapi.OperationKindProviderRefresh, "p_a", "")
	require.NoError(t, err)
	drainReload()
	operations.SetResultResolver(refreshed.OperationID, func() (any, error) {
		return nativeapi.Provider{ID: "p_a", Name: "subA"}, nil
	})
	operations.FollowReload(refreshed.OperationID, false, true, nil)
	operation, _, _ = operations.GetOperation(ctx, refreshed.OperationID)
	provider, isProvider := operation.Result.(nativeapi.Provider)
	require.True(t, isProvider, "result = %T, want nativeapi.Provider", operation.Result)
	require.Equal(t, "p_a", provider.ID)

	// A plain reload keeps reporting the generation boundary it moved.
	reload, err := operations.StartOperation(ctx, nativeapi.OperationKindReload, "", "")
	require.NoError(t, err)
	drainReload()
	operations.FollowReload(reload.OperationID, false, true, nil)
	operation, _, _ = operations.GetOperation(ctx, reload.OperationID)
	require.IsType(t, nativeapi.ReloadResult{}, operation.Result)
}

func TestOperationResultFallsBackWhenTheResourceIsUnreadable(t *testing.T) {
	operations, _ := newTestOperations()
	ctx := context.Background()
	accepted, err := operations.StartOperation(ctx, nativeapi.OperationKindNodeCreate, "scope-3", "")
	require.NoError(t, err)
	operations.SetResultResolver(accepted.OperationID, func() (any, error) {
		return nil, nativeapi.NewAPIError(404, "resource_not_found", "node not found")
	})
	operations.FollowReload(accepted.OperationID, false, true, nil)
	operation, _, _ := operations.GetOperation(ctx, accepted.OperationID)
	require.Equal(t, nativeapi.OperationStatusFailed, operation.Status)
	require.NotNil(t, operation.Error)
	require.Equal(t, "result_unavailable", operation.Error.Code)
}

func TestOperationResultResolverIsReleasedOnFailure(t *testing.T) {
	operations, _ := newTestOperations()
	ctx := context.Background()
	accepted, err := operations.StartOperation(ctx, nativeapi.OperationKindNodeCreate, "scope-4", "")
	require.NoError(t, err)
	called := false
	operations.SetResultResolver(accepted.OperationID, func() (any, error) {
		called = true
		return nil, nil
	})
	operations.FollowReload(accepted.OperationID, false, false, errors.New("reload rejected"))
	require.False(t, called, "a rejected reload must not resolve a resource")
	require.Nil(t, operations.takeResultResolver(accepted.OperationID), "a rejected reload must drop the resolver")

	operation, ok, err := operations.GetOperation(ctx, accepted.OperationID)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, nativeapi.OperationStatusFailed, operation.Status)
}
