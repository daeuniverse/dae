/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/nativeapi"
	"github.com/stretchr/testify/require"
)

// updated_at is "last successful load or refresh". A failed refresh must keep
// the previous success time instead of moving it to the attempt time.
func TestPublishSubscriptionHealthKeepsLastSuccess(t *testing.T) {
	t.Cleanup(func() { publishSubscriptionHealth(nil) })

	publishSubscriptionHealth(map[string]error{"subA": nil})
	first, ok := subscriptionHealth("subA")
	require.True(t, ok)
	require.False(t, first.updatedAt.IsZero())
	require.Empty(t, first.err)

	time.Sleep(2 * time.Millisecond)
	publishSubscriptionHealth(map[string]error{"subA": errors.New("HTTP 500")})
	second, ok := subscriptionHealth("subA")
	require.True(t, ok)
	require.Equal(t, "HTTP 500", second.err)
	require.Equal(t, first.updatedAt, second.updatedAt, "a failed refresh must not move updated_at")

	// A later success advances it again.
	time.Sleep(2 * time.Millisecond)
	publishSubscriptionHealth(map[string]error{"subA": nil})
	third, ok := subscriptionHealth("subA")
	require.True(t, ok)
	require.Empty(t, third.err)
	require.True(t, third.updatedAt.After(first.updatedAt))
}

// A refresh whose fetch failed still completes its reload (the cached copy
// keeps running), so the operation has to fail through the result resolver.
func TestProviderRefreshFailureFailsOperation(t *testing.T) {
	operations, _ := newTestOperations()
	ctx := context.Background()

	accepted, err := operations.StartOperation(ctx, nativeapi.OperationKindProviderRefresh, "p_sub", "")
	require.NoError(t, err)
	operations.SetResultResolver(accepted.OperationID, func() (any, error) {
		return nil, &providerRefreshError{code: "fetch_failed", message: "subscription answered HTTP 500"}
	})

	operations.FollowReload(accepted.OperationID, true, false, nil)
	operations.FollowReload(accepted.OperationID, false, true, nil)

	operation, ok, err := operations.GetOperation(ctx, accepted.OperationID)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, nativeapi.OperationStatusFailed, operation.Status)
	require.NotNil(t, operation.Error)
	require.Equal(t, "fetch_failed", operation.Error.Code)
	require.Contains(t, operation.Error.Message, "HTTP 500")
}
