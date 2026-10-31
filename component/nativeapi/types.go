/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package nativeapi

import (
	"context"
	"encoding/json"
)

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

// ProviderList is one page of provider metadata.
type ProviderList struct {
	Providers  []Provider `json:"providers"`
	NextCursor *string    `json:"next_cursor"`
}

type Provider struct {
	ID          string           `json:"id"`
	Name        string           `json:"name"`
	Kind        string           `json:"kind"`
	URLRedacted *string          `json:"url_redacted"`
	NodeCount   uint64           `json:"node_count"`
	UpdatedAt   *string          `json:"updated_at"`
	ExpiresAt   *string          `json:"expires_at"`
	Traffic     *ProviderTraffic `json:"traffic"`
	Status      string           `json:"status"`
	LastError   *SafeError       `json:"last_error"`
	Download    *GeoDataDownload `json:"download,omitempty"`
}

type ProviderTraffic struct {
	UploadBytes   *string `json:"upload_bytes"`
	DownloadBytes *string `json:"download_bytes"`
	TotalBytes    *string `json:"total_bytes"`
}

type GeoDataDownload struct {
	Route   string  `json:"route"`
	GroupID *string `json:"group_id"`
}

// GeoData is the loaded geodata asset report.
type GeoData struct {
	ObservedAt string     `json:"observed_at"`
	Assets     []GeoAsset `json:"assets"`
}

type GeoAsset struct {
	Kind           string  `json:"kind"`
	SHA256         string  `json:"sha256"`
	SizeBytes      string  `json:"size_bytes"`
	ModifiedAt     *string `json:"modified_at"`
	SourceRedacted *string `json:"source_redacted"`
}

// RuleList is the complete routing dictionary of one generation.
type RuleList struct {
	GenerationID string        `json:"generation_id"`
	Rules        []RoutingRule `json:"rules"`
	Fallback     RuleFallback  `json:"fallback"`
}

type RoutingRule struct {
	RuleID     string      `json:"rule_id"`
	Index      uint64      `json:"index"`
	Expression string      `json:"expression"`
	Outbound   string      `json:"outbound"`
	Must       bool        `json:"must"`
	Source     *RuleSource `json:"source"`
	Kind       string      `json:"kind"`
}

type RuleSource struct {
	File     string  `json:"file"`
	SourceID string  `json:"source_id"`
	Line     uint64  `json:"line"`
	Column   *uint64 `json:"column"`
}

type RuleFallback struct {
	Outbound string      `json:"outbound"`
	Source   *RuleSource `json:"source"`
}

// RuntimeOutbounds is the per-outbound counter projection.
type RuntimeOutbounds struct {
	ObservedAt   string             `json:"observed_at"`
	CounterSince string             `json:"counter_since"`
	Outbounds    []OutboundCounters `json:"outbounds"`
}

// OutboundCounters is one outbound's cumulative counters. Byte totals are
// decimal strings because they are UInt64 in the contract; active connections
// is a SafeUInt JSON number.
type OutboundCounters struct {
	Name              string `json:"name"`
	Kind              string `json:"kind"`
	ActiveConnections uint64 `json:"active_connections"`
	TotalConnections  string `json:"total_connections"`
	UploadBytes       string `json:"upload_bytes"`
	DownloadBytes     string `json:"download_bytes"`
	Errors            string `json:"errors"`
}

// RuntimeMemory is the process, cgroup and kernel memory snapshot.
type RuntimeMemory struct {
	ObservedAt string         `json:"observed_at"`
	Process    *MemoryProcess `json:"process"`
	Cgroup     *MemoryCgroup  `json:"cgroup"`
	Kernel     *MemoryKernel  `json:"kernel"`
}

type MemoryProcess struct {
	RSSBytes *string `json:"rss_bytes"`
}

type MemoryCgroup struct {
	Scope        string              `json:"scope"`
	CurrentBytes *string             `json:"current_bytes"`
	LimitBytes   *string             `json:"limit_bytes"`
	Events       *MemoryCgroupEvents `json:"events"`
}

type MemoryCgroupEvents struct {
	High    *string `json:"high"`
	OOM     *string `json:"oom"`
	OOMKill *string `json:"oom_kill"`
}

type MemoryKernel struct {
	EbpfBytes *string `json:"ebpf_bytes"`
	SampledAt *string `json:"sampled_at"`
}

type MemoryHistory struct {
	ObservedAt          string                `json:"observed_at"`
	WindowSeconds       int                   `json:"window_seconds"`
	SampledEverySeconds float64               `json:"sampled_every_seconds"`
	Samples             []MemoryHistorySample `json:"samples"`
}

type MemoryHistorySample struct {
	SampledAt          string  `json:"sampled_at"`
	RSSBytes           *string `json:"rss_bytes"`
	CgroupCurrentBytes *string `json:"cgroup_current_bytes"`
	KernelEbpfBytes    *string `json:"kernel_ebpf_bytes"`
}

// Datapath is the detailed datapath view.
type Datapath struct {
	ObservedAt string      `json:"observed_at"`
	Kind       string      `json:"kind"`
	State      string      `json:"state"`
	Visibility string      `json:"visibility"`
	Ebpf       *EbpfDetail `json:"ebpf"`
	Errors     []SafeError `json:"errors"`
}

type EbpfSummary struct {
	Backend   string             `json:"backend"`
	Programs  string             `json:"programs"`
	Hooks     string             `json:"hooks"`
	Routing   EbpfRoutingSummary `json:"routing"`
	Health    string             `json:"health"`
	LastError *string            `json:"last_error"`
	CheckedAt string             `json:"checked_at"`
}

type EbpfRoutingSummary struct {
	State        string  `json:"state"`
	GenerationID *string `json:"generation_id"`
	Epoch        *string `json:"epoch"`
}

type EbpfDetail struct {
	EbpfSummary
	Attachments []EbpfAttachment `json:"attachments,omitempty"`
	Maps        *EbpfMaps        `json:"maps"`
}

type EbpfAttachment struct {
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	Interface string `json:"interface,omitempty"`
	Direction string `json:"direction,omitempty"`
	Cgroup    string `json:"cgroup,omitempty"`
	Hook      string `json:"hook,omitempty"`
	State     string `json:"state"`
}

type EbpfMaps struct {
	State     string        `json:"state"`
	ConnState *MapOccupancy `json:"conn_state"`
}

type MapOccupancy struct {
	Occupancy      *uint64 `json:"occupancy"`
	Capacity       uint64  `json:"capacity"`
	OccupancyKnown bool    `json:"occupancy_known"`
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

// DNS cache views.
type DnsCacheCoverage struct {
	Positive   bool `json:"positive"`
	Negative   bool `json:"negative"`
	Persistent bool `json:"persistent"`
}

type DnsCacheEntry struct {
	EntryID    string      `json:"entry_id"`
	Domain     string      `json:"domain"`
	Type       string      `json:"type"`
	Class      string      `json:"class"`
	Status     string      `json:"status"`
	Answers    []DnsAnswer `json:"answers,omitempty"`
	ExpiresAt  string      `json:"expires_at"`
	StaleUntil *string     `json:"stale_until"`
}

type DnsCacheUsage struct {
	Entries       string  `json:"entries"`
	EntryCapacity *string `json:"entry_capacity"`
}

type DnsCacheList struct {
	ObservedAt string           `json:"observed_at"`
	Coverage   DnsCacheCoverage `json:"coverage"`
	Entries    []DnsCacheEntry  `json:"entries"`
	Total      uint64           `json:"total"`
	NextCursor *string          `json:"next_cursor"`
	Usage      *DnsCacheUsage   `json:"usage,omitempty"`
}

type DeleteCount struct {
	Deleted uint64 `json:"deleted"`
}

type DeleteMatchingCount struct {
	Matched uint64 `json:"matched"`
	Deleted uint64 `json:"deleted"`
}

// DNS log views.
type DnsQuestion struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type DnsAnswer struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Class string `json:"class"`
	TTL   uint32 `json:"ttl"`
	Data  string `json:"data"`
}

type DnsRoute struct {
	Source string  `json:"source"`
	Rule   *string `json:"rule"`
}

type DnsLogRecord struct {
	ID         string      `json:"id"`
	ObservedAt string      `json:"observed_at"`
	Src        *string     `json:"src"`
	Question   DnsQuestion `json:"question"`
	Status     string      `json:"status"`
	Cached     bool        `json:"cached"`
	Upstream   *string     `json:"upstream"`
	Route      DnsRoute    `json:"route"`
	ElapsedMs  uint64      `json:"elapsed_ms"`
	Answers    []DnsAnswer `json:"answers"`
}

type DnsLogList struct {
	ObservedAt string         `json:"observed_at"`
	Total      uint64         `json:"total"`
	NextCursor *string        `json:"next_cursor"`
	Records    []DnsLogRecord `json:"records"`
}

// DNS rules views.
type DnsRoutingRule struct {
	RuleID     string      `json:"rule_id"`
	Index      uint64      `json:"index"`
	Expression string      `json:"expression"`
	Action     string      `json:"action"`
	Upstream   *string     `json:"upstream"`
	Source     *RuleSource `json:"source"`
	Kind       string      `json:"kind"`
}

type DnsRuleList struct {
	GenerationID string           `json:"generation_id"`
	Request      []DnsRoutingRule `json:"request"`
	Response     []DnsRoutingRule `json:"response"`
}

// DNS query views.
type DnsQueryRequest struct {
	Domain    string   `json:"domain"`
	Type      []string `json:"type"`
	Upstream  string   `json:"upstream"`
	CacheMode string   `json:"cache_mode"`
}

type DnsQueryResult struct {
	Type         string      `json:"type"`
	Cached       bool        `json:"cached"`
	CacheEntryID *string     `json:"cache_entry_id"`
	Upstream     *string     `json:"upstream"`
	Route        DnsRoute    `json:"route"`
	Status       string      `json:"status"`
	ElapsedMs    uint64      `json:"elapsed_ms"`
	Question     DnsQuestion `json:"question"`
	Answers      []DnsAnswer `json:"answers,omitempty"`
}

type DnsQueryResponse struct {
	Domain    string           `json:"domain"`
	CacheMode string           `json:"cache_mode"`
	QueryTime string           `json:"query_time"`
	Results   []DnsQueryResult `json:"results"`
}

// Connection views.
type Connection struct {
	ID                     string   `json:"id"`
	FlowID                 *string  `json:"flow_id"`
	Pname                  *string  `json:"pname"`
	State                  string   `json:"state"`
	Src                    string   `json:"src,omitempty"`
	Dst                    string   `json:"dst,omitempty"`
	Domain                 *string  `json:"domain,omitempty"`
	Outbound               *string  `json:"outbound"`
	Chain                  []string `json:"chain"`
	ChainSource            string   `json:"chain_source"`
	RuleID                 *string  `json:"rule_id"`
	RuleExpression         *string  `json:"rule_expression"`
	RuleSource             string   `json:"rule_source"`
	Ingress                *string  `json:"ingress"`
	DomainSource           *string  `json:"domain_source"`
	StartedAt              *string  `json:"started_at"`
	ObservedBy             string   `json:"observed_by"`
	UploadBytes            *string  `json:"upload_bytes"`
	DownloadBytes          *string  `json:"download_bytes"`
	UploadBytesPerSecond   *string  `json:"upload_bytes_per_second"`
	DownloadBytesPerSecond *string  `json:"download_bytes_per_second"`
}

type ConnectionList struct {
	ObservedAt string       `json:"observed_at"`
	InstanceID string       `json:"instance_id"`
	Visibility string       `json:"visibility"`
	Truncated  bool         `json:"truncated"`
	TCP        []Connection `json:"tcp"`
	UDP        []Connection `json:"udp"`
	TotalTCP   uint64       `json:"total_tcp"`
	TotalUDP   uint64       `json:"total_udp"`
}

type BulkCloseResult struct {
	Closed  uint64 `json:"closed"`
	Skipped uint64 `json:"skipped"`
}

// Flow views.
type FlowInput struct {
	Src           *string  `json:"src"`
	Dst           *string  `json:"dst"`
	Domain        *string  `json:"domain"`
	DomainSource  *string  `json:"domain_source"`
	Pid           *uint64  `json:"pid"`
	ProcessPath   *string  `json:"process_path"`
	SrcMAC        *string  `json:"src_mac"`
	Ingress       *string  `json:"ingress"`
	DomainRuleIDs []string `json:"domain_rule_ids"`
	Dscp          *uint64  `json:"dscp"`
	Mark          *uint64  `json:"mark"`
}

type FlowTrace struct {
	Status  string   `json:"status"`
	Missing []string `json:"missing"`
	Steps   []any    `json:"steps"`
}

type FlowSummary struct {
	ID               string     `json:"id"`
	InstanceID       string     `json:"instance_id"`
	Revision         uint64     `json:"revision"`
	Network          string     `json:"network"`
	State            string     `json:"state"`
	Pname            *string    `json:"pname"`
	ConnectionID     *string    `json:"connection_id"`
	Outbound         *string    `json:"outbound"`
	Chain            []string   `json:"chain"`
	ChainSource      string     `json:"chain_source"`
	RuleID           *string    `json:"rule_id"`
	RuleGenerationID *string    `json:"rule_generation_id"`
	RuleExpression   *string    `json:"rule_expression"`
	RuleSource       string     `json:"rule_source"`
	Ingress          *string    `json:"ingress"`
	DomainSource     *string    `json:"domain_source"`
	ObservedBy       string     `json:"observed_by"`
	StartedAt        *string    `json:"started_at"`
	EndedAt          *string    `json:"ended_at"`
	TraceStatus      string     `json:"trace_status"`
	Input            *FlowInput `json:"input,omitempty"`
}

type FlowDetail struct {
	FlowSummary
	Input *FlowInput `json:"input"`
	Trace *FlowTrace `json:"trace"`
}

type FlowCoverage struct {
	UserspaceTCP string `json:"userspace_tcp"`
	UserspaceUDP string `json:"userspace_udp"`
	KernelDirect string `json:"kernel_direct"`
	KernelBlock  string `json:"kernel_block"`
	DNSIntercept string `json:"dns_intercept"`
	KernelBypass string `json:"kernel_bypass"`
}

type FlowList struct {
	InstanceID     string        `json:"instance_id"`
	ObservedAt     string        `json:"observed_at"`
	Coverage       FlowCoverage  `json:"coverage"`
	DroppedRecords *string       `json:"dropped_records"`
	Flows          []FlowSummary `json:"flows"`
	NextCursor     *string       `json:"next_cursor"`
}

// LogRecord is one sanitized engine log record.
type LogRecord struct {
	TS      string         `json:"ts"`
	Level   string         `json:"level"`
	Target  *string        `json:"target"`
	Message string         `json:"message"`
	Fields  map[string]any `json:"fields"`
}

// StreamReadyEvent is the first frame of every SSE stream.
type StreamReadyEvent struct {
	InstanceID string `json:"instance_id"`
	ObservedAt string `json:"observed_at"`
}

// SSEFrame is one server-sent event frame.
type SSEFrame struct {
	ID    string
	Event string
	Data  any
}

// SSEStream is an opened resumable event stream.
type SSEStream struct {
	Ready   SSEFrame
	Replay  []SSEFrame
	Updates <-chan SSEFrame
	Cancel  func()
}

// Probe views.
type ProbeTarget struct {
	Type    string `json:"type"`
	NodeID  string `json:"node_id,omitempty"`
	GroupID string `json:"group_id,omitempty"`
}

type ProbeMembers struct {
	Values []string
}

func (m *ProbeMembers) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		m.Values = []string{single}
		return nil
	}
	var list []string
	if err := json.Unmarshal(data, &list); err != nil {
		return err
	}
	m.Values = list
	return nil
}

func (m ProbeMembers) MarshalJSON() ([]byte, error) {
	if len(m.Values) == 1 && (m.Values[0] == "direct" || m.Values[0] == "leaves") {
		return json.Marshal(m.Values[0])
	}
	return json.Marshal(m.Values)
}

type ProbeRequest struct {
	Target    ProbeTarget   `json:"target"`
	Kind      string        `json:"kind"`
	Transport []string      `json:"transport"`
	IPVersion string        `json:"ip_version"`
	Members   *ProbeMembers `json:"members,omitempty"`
	Warmth    string        `json:"warmth"`
}

type ProbeResultItem struct {
	MemberID           string   `json:"member_id"`
	ResolvedLeafNodeID *string  `json:"resolved_leaf_node_id"`
	Kind               string   `json:"kind"`
	Purpose            string   `json:"purpose"`
	Transport          string   `json:"transport"`
	IPVersion          string   `json:"ip_version"`
	Warmth             string   `json:"warmth"`
	State              string   `json:"state"`
	LatencyMs          *float64 `json:"latency_ms"`
	HealthUpdated      bool     `json:"health_updated"`
	Error              *string  `json:"error"`
	ObservedAt         string   `json:"observed_at"`
}

type TransportBooleanMap struct {
	TCP bool `json:"tcp"`
	UDP bool `json:"udp"`
}

type TransportSelectionMap struct {
	TCP *string `json:"tcp"`
	UDP *string `json:"udp"`
}

type ProbeResult struct {
	Target           ProbeTarget           `json:"target"`
	SelectionChanged TransportBooleanMap   `json:"selection_changed"`
	SelectionBefore  TransportSelectionMap `json:"selection_before"`
	SelectionAfter   TransportSelectionMap `json:"selection_after"`
	Results          []ProbeResultItem     `json:"results"`
}
