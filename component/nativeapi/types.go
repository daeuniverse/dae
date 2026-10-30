/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package nativeapi

import "context"

const (
	APIName    = "daeuniverse/native"
	APIMajor   = 1
	APIStatus  = "draft"
	BasePath   = "/api/v1"
	EngineName = "dae"
)

// RuntimeProvider supplies a coherent runtime snapshot for GET /api/v1/runtime.
type RuntimeProvider interface {
	SnapshotRuntime(ctx context.Context, detail string) (Runtime, error)
}

type Discovery struct {
	Name     string         `json:"name"`
	Status   string         `json:"status"`
	APIMajor int            `json:"api_major"`
	BasePath string         `json:"base_path"`
	Links    map[string]any `json:"links"`
	Auth     AuthDiscovery  `json:"auth"`
}

type PublicDiscovery struct {
	Name     string              `json:"name"`
	APIMajor int                 `json:"api_major"`
	Links    map[string]any      `json:"links"`
	Auth     PublicAuthDiscovery `json:"auth"`
}

type AuthDiscovery struct {
	Mode              string `json:"mode"`
	SetupRequired     bool   `json:"setup_required"`
	AnonymousLoopback bool   `json:"anonymous_loopback"`
}

type PublicAuthDiscovery struct {
	Mode          string `json:"mode"`
	SetupRequired bool   `json:"setup_required"`
}

type Version struct {
	API    APIVersion     `json:"api"`
	Engine EngineVersion  `json:"engine"`
	Build  *BuildMetadata `json:"build,omitempty"`
}

type APIVersion struct {
	Name   string `json:"name"`
	Major  int    `json:"major"`
	Status string `json:"status"`
}

type EngineVersion struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type BuildMetadata struct {
	Revision *string `json:"revision"`
	Target   *string `json:"target"`
	BuiltAt  *string `json:"built_at"`
}

type Capabilities struct {
	ObservedAt string         `json:"observed_at"`
	Profiles   []string       `json:"profiles"`
	Limits     Limits         `json:"limits"`
	Resources  map[string]any `json:"resources"`
}

type Limits struct {
	MaxRequestTargetBytes int `json:"max_request_target_bytes"`
	MaxHeaderBytes        int `json:"max_header_bytes"`
	MaxJSONBodyBytes      int `json:"max_json_body_bytes"`
}

type Runtime struct {
	ObservedAt string          `json:"observed_at"`
	InstanceID string          `json:"instance_id"`
	Lifecycle  Lifecycle       `json:"lifecycle"`
	Generation Generation      `json:"generation"`
	Datapath   DatapathSummary `json:"datapath"`
	Traffic    TrafficSummary  `json:"traffic"`
	Process    Process         `json:"process"`
	LastReload *LastReload     `json:"last_reload"`
}

type Lifecycle struct {
	State         string  `json:"state"`
	StartedAt     *string `json:"started_at"`
	UptimeSeconds *string `json:"uptime_seconds"`
}

type Generation struct {
	ActiveID       string  `json:"active_id"`
	ConfigRevision *string `json:"config_revision"`
	State          string  `json:"state"`
	ActivatedAt    *string `json:"activated_at"`
}

type DatapathSummary struct {
	Kind       string `json:"kind"`
	State      string `json:"state"`
	Visibility string `json:"visibility"`
	Ebpf       any    `json:"ebpf"`
}

type TrafficSummary struct {
	Scope        string      `json:"scope"`
	ObservedBy   string      `json:"observed_by"`
	CounterSince *string     `json:"counter_since"`
	SampledAt    *string     `json:"sampled_at"`
	Connections  Connections `json:"connections"`
	Bytes        Bytes       `json:"bytes"`
	Rates        *Rates      `json:"rates"`
}

type Connections struct {
	TCP   *uint64 `json:"tcp"`
	UDP   *uint64 `json:"udp"`
	Total *uint64 `json:"total"`
}

type Bytes struct {
	Upload   *string `json:"upload"`
	Download *string `json:"download"`
}

type Rates struct {
	WindowSeconds          float64 `json:"window_seconds"`
	UploadBytesPerSecond   *string `json:"upload_bytes_per_second"`
	DownloadBytesPerSecond *string `json:"download_bytes_per_second"`
}

type Process struct {
	Pid        *uint32  `json:"pid,omitempty"`
	CPUPercent *float64 `json:"cpu_percent"`
}

type LastReload struct {
	OperationID string     `json:"operation_id"`
	Status      string     `json:"status"`
	FinishedAt  *string    `json:"finished_at"`
	Error       *SafeError `json:"error"`
}

type SafeError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details any    `json:"details,omitempty"`
}

type ErrorResponse struct {
	Error     SafeError `json:"error"`
	RequestID *string   `json:"request_id"`
}

// GroupPolicy is the contract view of a dae group policy.
type GroupPolicy struct {
	Kind   string `json:"kind"`
	Native string `json:"native"`
}

type GroupMember struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Kind string `json:"kind"`
}

// GroupConfigExtension carries dae-only group options. The contract keeps them
// out of the patchable document under config["x-dae"].
type GroupConfigExtension struct {
	CheckAddresses     []string `json:"check_addresses"`
	TCPCheckHTTPMethod string   `json:"tcp_check_http_method"`
	UDPCheckDNS        []string `json:"udp_check_dns"`
}

type GroupConfig struct {
	DefaultMemberID      *string               `json:"default_member_id"`
	FinalOutbound        *string               `json:"final_outbound"`
	CheckURL             *string               `json:"check_url"`
	CheckInterval        *int                  `json:"check_interval"`
	Tolerance            *int                  `json:"tolerance"`
	IdleTimeout          *int                  `json:"idle_timeout"`
	InterruptConnections *bool                 `json:"interrupt_connections"`
	XDae                 *GroupConfigExtension `json:"x-dae,omitempty"`
}

type GroupConfigDocument struct {
	Policy GroupPolicy `json:"policy"`
	Config GroupConfig `json:"config"`
}

type GroupSelection struct {
	MemberID           string  `json:"member_id"`
	ResolvedLeafNodeID *string `json:"resolved_leaf_node_id"`
	Source             string  `json:"source"`
}

type GroupSelectionPair struct {
	TCP *GroupSelection `json:"tcp"`
	UDP *GroupSelection `json:"udp"`
}

type GroupRuntime struct {
	Selection GroupSelectionPair       `json:"selection"`
	Health    []GroupHealthObservation `json:"health"`
}

// HealthObservation is one typed per-member health sample.
type HealthObservation struct {
	Transport    string   `json:"transport"`
	Purpose      string   `json:"purpose"`
	IpVersion    string   `json:"ip_version"`
	Warmth       string   `json:"warmth"`
	Measurement  string   `json:"measurement"`
	SampleSource string   `json:"sample_source"`
	State        string   `json:"state"`
	LatencyMs    *float64 `json:"latency_ms"`
	MovingAvgMs  *float64 `json:"moving_avg_ms"`
	Avg10Ms      *float64 `json:"avg10_ms"`
	ObservedAt   string   `json:"observed_at"`
	Error        *string  `json:"error"`
}

// GroupRanking explains how a member was scored for its group. dae does not
// expose a score, so it is always null today.
type GroupRanking struct {
	Metric            *string  `json:"metric"`
	RecoveryPenaltyMs *float64 `json:"recovery_penalty_ms"`
	GroupOffsetMs     *float64 `json:"group_offset_ms"`
	Score             *float64 `json:"score"`
	Reason            *string  `json:"reason"`
}

// GroupHealthObservation is one member's health sample plus the latency the
// group sorts by.
type GroupHealthObservation struct {
	HealthObservation
	MemberID           string        `json:"member_id"`
	ResolvedLeafNodeID *string       `json:"resolved_leaf_node_id"`
	SortingLatencyMs   *float64      `json:"sorting_latency_ms"`
	Ranking            *GroupRanking `json:"ranking"`
}

// Node is one dialer of this generation.
type Node struct {
	ID              string              `json:"id"`
	Name            string              `json:"name"`
	Protocol        *string             `json:"protocol"`
	StreamTransport *string             `json:"stream_transport,omitempty"`
	SubscriptionTag *string             `json:"subscription_tag"`
	ProviderID      *string             `json:"provider_id"`
	GroupIDs        []string            `json:"group_ids"`
	Health          []HealthObservation `json:"health"`
}

type NodeList struct {
	ObservedAt string  `json:"observed_at"`
	Nodes      []Node  `json:"nodes"`
	NextCursor *string `json:"next_cursor"`
}

type GroupCapabilities struct {
	CanSelect            bool     `json:"can_select"`
	CanOverride          bool     `json:"can_override"`
	SupportsNestedGroups bool     `json:"supports_nested_groups"`
	MutableConfig        []string `json:"mutable_config"`
	ProbeTransports      []string `json:"probe_transports"`
}

type Group struct {
	ID             string            `json:"id"`
	Name           string            `json:"name"`
	Icon           *string           `json:"icon"`
	ConfigRevision string            `json:"config_revision"`
	Policy         GroupPolicy       `json:"policy"`
	Members        []GroupMember     `json:"members"`
	Config         GroupConfig       `json:"config"`
	Runtime        GroupRuntime      `json:"runtime"`
	Capabilities   GroupCapabilities `json:"capabilities"`
}

type GroupSummarySelection struct {
	TCPMemberID *string `json:"tcp_member_id"`
	UDPMemberID *string `json:"udp_member_id"`
}

type GroupSummary struct {
	ID             string                `json:"id"`
	Name           string                `json:"name"`
	Icon           *string               `json:"icon"`
	ConfigRevision string                `json:"config_revision"`
	Policy         GroupPolicy           `json:"policy"`
	MemberCount    int                   `json:"member_count"`
	Selection      GroupSummarySelection `json:"selection"`
}

type GroupSelectionRequest struct {
	MemberID string `json:"member_id"`
	Network  string `json:"network"`
}

type GroupSelectionResult struct {
	GroupID                string  `json:"group_id"`
	MemberID               string  `json:"member_id"`
	ResolvedLeafNodeID     *string `json:"resolved_leaf_node_id"`
	Network                string  `json:"network"`
	Source                 string  `json:"source"`
	SelectionRevision      string  `json:"selection_revision"`
	ConnectionsInterrupted bool    `json:"connections_interrupted"`
}

// GroupOverrideCleared is the outcome of clearing a pinned member. dae has no
// overridable policy yet, so DELETE selection never succeeds; the type exists
// so the handler stays contract-shaped if pinning is added later.
type GroupOverrideCleared struct {
	GroupID                string             `json:"group_id"`
	Network                string             `json:"network"`
	SelectionRevision      string             `json:"selection_revision"`
	ConnectionsInterrupted bool               `json:"connections_interrupted"`
	Selection              GroupSelectionPair `json:"selection"`
}

type OperationAccepted struct {
	OperationID string `json:"operation_id"`
	Kind        string `json:"kind"`
	Status      string `json:"status"`
	Href        string `json:"href"`
}

type Operation struct {
	OperationID string     `json:"operation_id"`
	Kind        string     `json:"kind"`
	Status      string     `json:"status"`
	CreatedAt   string     `json:"created_at"`
	StartedAt   *string    `json:"started_at"`
	FinishedAt  *string    `json:"finished_at"`
	Result      any        `json:"result"`
	Error       *SafeError `json:"error"`
}

type ReloadResult struct {
	ActiveGenerationID   *string `json:"active_generation_id"`
	DatapathGenerationID *string `json:"datapath_generation_id"`
}

type RuntimeStateResult struct {
	RuntimeState *string `json:"runtime_state"`
}

type TrafficHistory struct {
	ObservedAt          string                 `json:"observed_at"`
	WindowSeconds       int                    `json:"window_seconds"`
	SampledEverySeconds float64                `json:"sampled_every_seconds"`
	Samples             []TrafficHistorySample `json:"samples"`
}

type TrafficHistorySample struct {
	SampledAt              string  `json:"sampled_at"`
	UploadBytesPerSecond   *string `json:"upload_bytes_per_second"`
	DownloadBytesPerSecond *string `json:"download_bytes_per_second"`
	Connections            *uint64 `json:"connections"`
}
