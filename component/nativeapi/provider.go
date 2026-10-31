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

	MaxRuleDictionarySize = 1 << 20

	MaxMemoryHistoryWindowSeconds = 3600
	MaxMemoryHistoryPoints        = 180
	DefaultMemoryHistoryWindow    = 3600
	DefaultMemoryHistoryPoints    = 180
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

// ProviderProvider serves provider metadata (subscriptions and inline nodes).
type ProviderProvider interface {
	ListProviders(ctx context.Context, limit int, cursor string) (ProviderList, error)
	GetProvider(ctx context.Context, providerID string) (*Provider, error)
}

// GeoDataProvider serves the loaded geodata asset report.
type GeoDataProvider interface {
	GeoData(ctx context.Context) (GeoData, error)
}

// RulesProvider serves the running generation's routing rule dictionary.
type RulesProvider interface {
	RoutingRules(ctx context.Context) (RuleList, error)
}

// OutboundProvider serves the per-outbound counter projection.
type OutboundProvider interface {
	RuntimeOutbounds(ctx context.Context) (RuntimeOutbounds, error)
}

// MemoryProvider serves the process memory snapshot, its bounded history, and
// the metrics the engine can observe.
type MemoryProvider interface {
	SnapshotMemory(ctx context.Context) (RuntimeMemory, error)
	MemoryHistory(ctx context.Context, windowSeconds, maxPoints int) (MemoryHistory, error)
	MemoryMetrics(ctx context.Context) []string
}

// DatapathProvider serves the detailed datapath state.
type DatapathProvider interface {
	SnapshotDatapath(ctx context.Context, detail string) (Datapath, error)
}

const (
	DnsLogMaxRecords    = 1024
	DnsLogMaxPageSize   = 1000
	DnsRulesMaxCapacity = 65536
	DnsQueryMaxTypes    = 8
	DnsQueryTimeoutMs   = 5000

	// Probe caps are both advertised in capabilities.probes.limits and
	// enforced by the executor, so clients can rely on the numbers they read.
	ProbeMaxMembersPerJob  = 256
	ProbeMaxResultsPerJob  = 512
	ProbeMaxActiveJobs     = 4
	ProbeMaxQueuedJobs     = 16
	ProbeJobTimeoutMs      = 30000
	ProbeRequestsPerMinute = 120
)

// DnsCacheFilter selects DNS cache entries for listing or deletion.
type DnsCacheFilter struct {
	Name           string
	Domain         string
	Types          []string
	IncludeExpired bool
	Limit          int
	Cursor         string
}

// DnsLogFilter selects DNS log records.
type DnsLogFilter struct {
	Name   string
	Types  []string
	Src    string
	Limit  int
	Cursor string
}

// DnsProvider serves DNS cache, log, rules and active query resources.
type DnsProvider interface {
	DnsCache(ctx context.Context, filter DnsCacheFilter) (DnsCacheList, error)
	DeleteDnsCacheByName(ctx context.Context, name string, types []string) (DeleteMatchingCount, error)
	DeleteDnsCacheEntry(ctx context.Context, entryID string) (DeleteCount, error)
	FlushDnsCache(ctx context.Context) (DeleteMatchingCount, error)
	DnsLog(ctx context.Context, filter DnsLogFilter) (DnsLogList, error)
	DnsRules(ctx context.Context) (DnsRuleList, error)
	QueryDns(ctx context.Context, request DnsQueryRequest) (DnsQueryResponse, error)
}

// ConnectionFilter selects live connections.
type ConnectionFilter struct {
	Type  string
	Src   string
	Limit int
}

// ConnectionProvider serves live connections and their close operation.
type ConnectionProvider interface {
	ListConnections(ctx context.Context, filter ConnectionFilter) (ConnectionList, error)
	// CloseConnection returns an error with code resource_not_found when the
	// ID is unknown or already gone.
	CloseConnection(ctx context.Context, connectionID string) error
	CloseConnections(ctx context.Context, filter ConnectionFilter, all bool) (BulkCloseResult, error)
}

// FlowFilter selects retained flows.
type FlowFilter struct {
	Network      string
	State        string
	ConnectionID string
	Limit        int
	Cursor       string
}

// ProbeProvider starts bounded probe operations.
type ProbeProvider interface {
	StartProbe(ctx context.Context, request ProbeRequest, idempotencyKey string) (OperationAccepted, error)
}

// FlowProvider serves the bounded flow history.
type FlowProvider interface {
	ListFlows(ctx context.Context, filter FlowFilter) (FlowList, error)
	GetFlow(ctx context.Context, flowID string) (*FlowDetail, error)
}

const (
	LogRetentionSeconds    = 300
	LogMaxBufferedRecords  = 1024
	EventRetentionSeconds  = 300
	EventMaxBufferedEvents = 1024
	EventMaxClients        = 32
	SSEHeartbeatSeconds    = 10
)

// LogProvider opens a resumable log stream.
type LogProvider interface {
	OpenLogStream(ctx context.Context, level, target, lastEventID string) (*SSEStream, error)
	LogLevels() []string
	LogFilters() []string
}

// EventProvider opens a resumable event stream.
type EventProvider interface {
	OpenEventStream(ctx context.Context, kinds []string, flowID, lastEventID string) (*SSEStream, error)
	EventKinds() []string
}
