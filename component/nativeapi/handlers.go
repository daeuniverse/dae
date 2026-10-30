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
