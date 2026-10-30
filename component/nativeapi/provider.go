/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package nativeapi

import (
	"context"
	"time"
)

// Contract limits shared by the handler validation and the capabilities
// document, so the two can never disagree.
const (
	MaxTrafficHistoryWindowSeconds = 3600
	MaxTrafficHistoryPoints        = 180
	DefaultTrafficHistoryWindow    = 3600
	DefaultTrafficHistoryPoints    = 180

	OperationRetentionSeconds = 3600
	MaxOperationReplayKeys    = 1024

	NodeListDefaultLimit = 100
	NodeListMaxLimit     = 1000
)

// OperationRetention is OperationRetentionSeconds as a duration.
var OperationRetention = time.Duration(OperationRetentionSeconds) * time.Second

// GroupProvider serves the read-only group resources and runtime selection.
// A nil provider makes the resource unavailable in capabilities.
type GroupProvider interface {
	ListGroups(ctx context.Context) ([]GroupSummary, error)
	GetGroup(ctx context.Context, groupID string) (*Group, error)
	// GetGroupConfig returns the configuration document and the
	// configuration-wide revision used for ETag and If-Match.
	GetGroupConfig(ctx context.Context, groupID string) (GroupConfigDocument, string, error)
	SetGroupSelection(ctx context.Context, groupID, memberID, network string) (GroupSelectionResult, error)
	// ClearGroupSelection either clears a pinned member or reports why the
	// policy cannot be overridden, through *APIError.
	ClearGroupSelection(ctx context.Context, groupID, network string) (GroupOverrideCleared, error)
}

// OperationProvider starts and reports asynchronous control operations.
type OperationProvider interface {
	StartOperation(ctx context.Context, kind, idempotencyKey string) (OperationAccepted, error)
	GetOperation(ctx context.Context, operationID string) (Operation, bool, error)
}

// NodeProvider serves the read-only node inventory. A nil provider makes the
// resource unavailable in capabilities.
type NodeProvider interface {
	// ListNodes returns one page. An empty groupID lists every node; an
	// unknown groupID is reported through *APIError.
	ListNodes(ctx context.Context, groupID string, limit int, cursor string) (NodeList, error)
	GetNode(ctx context.Context, nodeID string) (*Node, error)
}

// TrafficHistoryProvider serves recorded traffic samples.
type TrafficHistoryProvider interface {
	TrafficHistory(ctx context.Context, windowSeconds, maxPoints int) (TrafficHistory, error)
}
