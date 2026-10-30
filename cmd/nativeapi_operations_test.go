/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	"os"
	"testing"

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

	accepted, err := operations.StartOperation(ctx, nativeapi.OperationKindReload, "")
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

	suspend, err := operations.StartOperation(ctx, nativeapi.OperationKindSuspend, "")
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

	resume, err := operations.StartOperation(ctx, nativeapi.OperationKindResume, "")
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

	_, err := operations.StartOperation(ctx, nativeapi.OperationKindReload, "")
	require.NoError(t, err)
	accepted, err := operations.StartOperation(ctx, nativeapi.OperationKindReload, "")
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

	first, err := operations.StartOperation(ctx, nativeapi.OperationKindReload, "key-1")
	require.NoError(t, err)
	<-manager.reloadReqs

	// Replaying the same key and body returns the original operation instead
	// of queueing another reload.
	manager.reloadPending.Store(false)
	manager.reloadActive.Store(false)
	second, err := operations.StartOperation(ctx, nativeapi.OperationKindReload, "key-1")
	require.NoError(t, err)
	require.Equal(t, first.OperationID, second.OperationID)
	select {
	case unexpected := <-manager.reloadReqs:
		t.Fatalf("replay queued another reload: %#v", unexpected)
	default:
	}

	// The same key with a different body conflicts.
	_, err = operations.StartOperation(ctx, nativeapi.OperationKindSuspend, "key-1")
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

	_, err := operations.StartOperation(ctx, nativeapi.OperationKindReload, "key-2")
	require.NoError(t, err)
	<-manager.reloadReqs

	_, err = operations.StartOperation(ctx, nativeapi.OperationKindReload, "key-3")
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
	retried, err := operations.StartOperation(ctx, nativeapi.OperationKindReload, "key-3")
	require.NoError(t, err)
	require.NotEqual(t, details["operation_id"], retried.OperationID)
	select {
	case queued := <-manager.reloadReqs:
		require.Equal(t, retried.OperationID, queued.apiOperationID)
	default:
		t.Fatal("retry did not queue a reload")
	}
}
