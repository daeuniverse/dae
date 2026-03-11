/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org
 */

package lifecycle

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/daeuniverse/dae/config"
)

// ConfigHash computes a hash of the configuration for reload type detection.
// Only fields that require full reload are included in the hash.
type ConfigHash struct {
	// TproxyPort changes require full reload (new listener, BPF programs with new port)
	TproxyPort uint16

	// BPF-related constants that require full reload
	// These are implicitly determined by the config structure
}

// ComputeConfigHash computes a hash of the config for determining reload type.
// Returns a hex string that can be compared to detect changes.
func ComputeConfigHash(cfg *config.Config) string {
	h := sha256.New()

	// Port changes require full reload
	fmt.Fprintf(h, "port:%d|", cfg.Global.TproxyPort)

	// Include other fields that require full reload
	// For now, we focus on tproxy_port as the primary trigger

	return hex.EncodeToString(h.Sum(nil))[:16]
}

// NeedsFullReload determines if a reload should be a full reload based on config changes.
// Returns true if:
// - tproxy_port changed
// - BPF constants changed
// - Map schema changed
// - Program bytecode upgrade needed
func NeedsFullReload(oldCfg, newCfg *config.Config) bool {
	if oldCfg == nil || newCfg == nil {
		return true
	}

	// Port change is the primary trigger for full reload
	if oldCfg.Global.TproxyPort != newCfg.Global.TproxyPort {
		return true
	}

	// TODO: Add checks for:
	// - BPF constant changes
	// - Map schema incompatibility
	// - Program version changes

	return false
}

// CompatibleForConfigOnlyReload checks if DNS cache can be preserved during reload.
// Returns false if IP version preference changed (requires cache flush).
func CompatibleForConfigOnlyReload(oldCfg, newCfg *config.Config) bool {
	if oldCfg == nil || newCfg == nil {
		return false
	}

	// DNS cache compatibility depends on IP version preference
	if oldCfg.Dns.IpVersionPrefer != newCfg.Dns.IpVersionPrefer {
		return false
	}

	return true
}

// ReloadLevel represents the level of reload required
type ReloadLevel int

const (
	// ReloadLevelNone means no reload needed (configs are identical)
	ReloadLevelNone ReloadLevel = iota
	// ReloadLevelConfigOnly means only config needs update (no BPF changes)
	ReloadLevelConfigOnly
	// ReloadLevelFull means full reload required (BPF programs need rebuild)
	ReloadLevelFull
)

// ConfigDiff represents the difference between two configs
type ConfigDiff struct {
	Level         ReloadLevel
	ChangedFields []string
	OldHash       string
	NewHash       string
}

// AnalyzeConfigDiff analyzes the difference between old and new configs
// and returns a detailed diff with reload level recommendation.
// This enables fine-grained reload optimization.
func AnalyzeConfigDiff(oldCfg, newCfg *config.Config) *ConfigDiff {
	// TODO: Implement full config diff analysis
	// For now, return simple diff
	return &ConfigDiff{
		Level:         ReloadLevelNone,
		ChangedFields: nil,
	}
}
