/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package nativeapi

import (
	"net/http"
	"time"
)

func (s *Server) handleDiscovery(w http.ResponseWriter, r *http.Request, full bool) {
	auth := AuthDiscovery{
		Mode:              "token",
		SetupRequired:     false,
		AnonymousLoopback: s.anonymousLoopbackActive(),
	}
	if !full {
		writeJSON(w, http.StatusOK, PublicDiscovery{
			Name:     APIName,
			APIMajor: APIMajor,
			Links: map[string]any{
				"auth_setup": nil,
				"auth_login": nil,
			},
			Auth: PublicAuthDiscovery{
				Mode:          auth.Mode,
				SetupRequired: auth.SetupRequired,
			},
		})
		return
	}

	writeJSON(w, http.StatusOK, Discovery{
		Name:     APIName,
		Status:   APIStatus,
		APIMajor: APIMajor,
		BasePath: BasePath,
		Links: map[string]any{
			"version":           "/api/v1/version",
			"capabilities":      "/api/v1/capabilities",
			"config":            "/api/v1/config",
			"config_validate":   "/api/v1/config/validate",
			"runtime":           "/api/v1/runtime",
			"runtime_outbounds": "/api/v1/runtime/outbounds",
			"traffic_history":   "/api/v1/runtime/traffic/history",
			"memory_history":    "/api/v1/runtime/memory/history",
			"logs":              "/api/v1/logs",
			"providers":         "/api/v1/providers",
			"rules":             "/api/v1/rules",
			"operations":        "/api/v1/operations/{operation_id}",
			"geodata":           "/api/v1/geodata",
			"auth_setup":        nil,
			"auth_login":        nil,
			"auth_logout":       nil,
		},
		Auth: auth,
	})
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	version := Version{
		API: APIVersion{
			Name:   APIName,
			Major:  APIMajor,
			Status: APIStatus,
		},
		Engine: EngineVersion{
			Name:    s.cfg.EngineName,
			Version: s.cfg.EngineVersion,
		},
	}
	if build := s.buildMetadata(); build != nil {
		version.Build = build
	}
	writeJSON(w, http.StatusOK, version)
}

// buildMetadata reports the build the engine runs, using the same values the
// command line prints. The contract requires all three keys, each nullable, so
// a build without VCS information still answers honestly.
func (s *Server) buildMetadata() *BuildMetadata {
	if s.cfg.BuildRevision == "" && s.cfg.BuildTarget == "" && s.cfg.BuildBuiltAt == "" {
		return nil
	}
	return &BuildMetadata{
		Revision: nonEmpty(s.cfg.BuildRevision),
		Target:   nonEmpty(s.cfg.BuildTarget),
		BuiltAt:  nonEmpty(s.cfg.BuildBuiltAt),
	}
}

func nonEmpty(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func (s *Server) handleCapabilities(w http.ResponseWriter, r *http.Request) {
	resources := map[string]any{
		"runtime": map[string]any{
			"available": true,
		},
		"config": map[string]any{
			"available": false,
		},
		"config_validate": map[string]any{
			"available": false,
		},
	}
	if s.groups != nil {
		resources["groups"] = map[string]any{
			"available":            true,
			"config_patch":         false,
			"selection":            true,
			"max_patch_operations": 1,
		}
	} else {
		resources["groups"] = map[string]any{"available": false}
	}
	if s.nodes != nil {
		resources["nodes"] = map[string]any{
			"available":  true,
			"can_manage": false,
		}
	} else {
		resources["nodes"] = map[string]any{"available": false}
	}
	if s.traffic != nil {
		resources["traffic_history"] = map[string]any{
			"available":          true,
			"max_window_seconds": MaxTrafficHistoryWindowSeconds,
			"max_points":         MaxTrafficHistoryPoints,
		}
	} else {
		resources["traffic_history"] = map[string]any{"available": false}
	}
	if s.outbounds != nil {
		resources["runtime_outbounds"] = map[string]any{"available": true}
	} else {
		resources["runtime_outbounds"] = map[string]any{"available": false}
	}
	if s.memory != nil {
		metrics := s.memory.MemoryMetrics(r.Context())
		if metrics == nil {
			metrics = []string{}
		}
		resources["runtime_memory"] = map[string]any{
			"available": true,
			"metrics":   metrics,
		}
		resources["memory_history"] = map[string]any{
			"available":          true,
			"max_window_seconds": MaxMemoryHistoryWindowSeconds,
			"max_points":         MaxMemoryHistoryPoints,
		}
	} else {
		resources["runtime_memory"] = map[string]any{"available": false}
		resources["memory_history"] = map[string]any{"available": false}
	}
	if s.providers != nil {
		resources["providers"] = map[string]any{
			"available":     true,
			"can_refresh":   false,
			"can_manage":    false,
			"max_page_size": NodeListMaxLimit,
		}
	} else {
		resources["providers"] = map[string]any{"available": false}
	}
	if s.dns != nil {
		resources["dns_cache"] = map[string]any{
			"available":    true,
			"read":         true,
			"delete_entry": true,
			"delete_name":  true,
			"flush":        true,
			"entry_kinds":  []string{"positive", "negative"},
		}
		resources["dns_log"] = map[string]any{
			"available":     true,
			"max_records":   DnsLogMaxRecords,
			"max_page_size": DnsLogMaxPageSize,
		}
		resources["dns_rules"] = map[string]any{
			"available": true,
			"max_rules": DnsRulesMaxCapacity,
		}
		resources["dns_query"] = map[string]any{
			"available": true,
			"record_types": []string{
				"A", "AAAA", "CNAME", "MX", "NS", "PTR", "SOA", "SRV", "TXT", "HTTPS", "SVCB", "CAA",
			},
			"limits": map[string]any{
				"max_types_per_request":             DnsQueryMaxTypes,
				"query_timeout_ms":                  DnsQueryTimeoutMs,
				"max_response_bytes":                65535,
				"per_principal_requests_per_minute": 60,
				"global_requests_per_minute":        600,
			},
		}
	} else {
		resources["dns_cache"] = map[string]any{"available": false}
		resources["dns_log"] = map[string]any{"available": false}
		resources["dns_rules"] = map[string]any{"available": false}
		resources["dns_query"] = map[string]any{"available": false}
	}
	if s.geodata != nil {
		resources["geodata"] = map[string]any{
			"available":  true,
			"can_update": false,
			"assets":     []string{"geoip", "geosite"},
		}
	} else {
		resources["geodata"] = map[string]any{"available": false}
	}
	if s.connections != nil {
		resources["connections"] = map[string]any{
			"available":      true,
			"can_close":      true,
			"max_bulk_close": NodeListMaxLimit,
		}
	} else {
		resources["connections"] = map[string]any{"available": false}
	}
	if s.flows != nil {
		resources["flows"] = map[string]any{
			"available":            true,
			"recording":            "on",
			"scopes":               []string{"userspace_tcp", "userspace_udp"},
			"max_flows":            2048,
			"max_steps_per_flow":   1,
			"retention_seconds":    900,
			"snapshot_ttl_seconds": 30,
			"max_page_size":        NodeListMaxLimit,
		}
	} else {
		resources["flows"] = map[string]any{"available": false}
	}
	if s.logs != nil {
		resources["logs"] = map[string]any{
			"available":            true,
			"levels":               s.logs.LogLevels(),
			"filters":              s.logs.LogFilters(),
			"retention_seconds":    LogRetentionSeconds,
			"max_buffered_records": LogMaxBufferedRecords,
		}
	} else {
		resources["logs"] = map[string]any{"available": false}
	}
	if s.events != nil {
		resources["events"] = map[string]any{
			"available":           true,
			"kinds":               s.events.EventKinds(),
			"retention_seconds":   EventRetentionSeconds,
			"max_buffered_events": EventMaxBufferedEvents,
			"max_clients":         EventMaxClients,
			"heartbeat_seconds":   SSEHeartbeatSeconds,
		}
	} else {
		resources["events"] = map[string]any{"available": false}
	}
	if s.probes != nil {
		resources["probes"] = map[string]any{
			"available":   true,
			"targets":     []string{"node", "group"},
			"kinds":       []string{"tcp_connect", "http", "dns"},
			"transports":  []string{"tcp", "udp"},
			"ip_versions": []string{"ipv4", "ipv6", "any"},
			"limits": map[string]any{
				"max_members_per_job":               ProbeMaxMembersPerJob,
				"max_results_per_job":               ProbeMaxResultsPerJob,
				"max_active_jobs":                   ProbeMaxActiveJobs,
				"max_queued_jobs":                   ProbeMaxQueuedJobs,
				"max_concurrent_per_target":         ProbeMaxActiveJobs,
				"job_timeout_ms":                    ProbeJobTimeoutMs,
				"per_principal_requests_per_minute": ProbeRequestsPerMinute,
				"global_requests_per_minute":        ProbeRequestsPerMinute,
			},
		}
	} else {
		resources["probes"] = map[string]any{"available": false}
	}
	if s.rules != nil {
		resources["rules"] = map[string]any{
			"available": true,
			"max_rules": MaxRuleDictionarySize,
		}
	} else {
		resources["rules"] = map[string]any{"available": false}
	}
	if s.datapath != nil {
		resources["datapath"] = map[string]any{
			"available": true,
			"kinds":     []string{"ebpf"},
			"details":   []string{"attachments", "maps"},
		}
	} else {
		resources["datapath"] = map[string]any{"available": false}
	}
	if s.operations != nil {
		resources["operations"] = map[string]any{
			"available":         true,
			"retention_seconds": OperationRetentionSeconds,
			"max_replay_keys":   MaxOperationReplayKeys,
		}
		resources["reload"] = map[string]any{"available": true}
		resources["suspend"] = map[string]any{"available": true}
		resources["resume"] = map[string]any{"available": true}
	} else {
		resources["operations"] = map[string]any{"available": false}
		resources["reload"] = map[string]any{"available": false}
		resources["suspend"] = map[string]any{"available": false}
		resources["resume"] = map[string]any{"available": false}
	}

	writeJSON(w, http.StatusOK, Capabilities{
		ObservedAt: time.Now().UTC().Format(time.RFC3339),
		Profiles:   []string{"base"},
		Limits: Limits{
			MaxRequestTargetBytes: s.cfg.MaxRequestTargetBytes,
			MaxHeaderBytes:        s.cfg.MaxHeaderBytes,
			MaxJSONBodyBytes:      s.cfg.MaxJSONBodyBytes,
		},
		Resources: resources,
	})
}

func (s *Server) handleRuntime(w http.ResponseWriter, r *http.Request) {
	requestID := requestIDFromContext(r.Context())
	detail := r.URL.Query().Get("detail")
	if detail == "" {
		detail = "summary"
	}
	if detail != "summary" && detail != "full" {
		writeError(w, requestID, http.StatusBadRequest, codeInvalidRequest, "detail must be summary or full")
		return
	}
	runtime, err := s.provider.SnapshotRuntime(r.Context(), detail)
	if err != nil {
		writeError(w, requestID, http.StatusServiceUnavailable, codeTemporarilyUnavailable, "runtime state is unavailable")
		return
	}
	if runtime.ObservedAt == "" {
		runtime.ObservedAt = time.Now().UTC().Format(time.RFC3339)
	}
	writeJSON(w, http.StatusOK, runtime)
}
