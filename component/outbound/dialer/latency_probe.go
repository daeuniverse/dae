/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"fmt"
	"time"
)

// LatencyProbeResult reports the latest ad-hoc latency probe result for a dialer.
type LatencyProbeResult struct {
	Alive     bool
	Latency   time.Duration
	Message   string
	CheckedAt time.Time
}

// FormatLatencyMessage formats a latency probe result for status display.
func FormatLatencyMessage(result *LatencyProbeResult) string {
	if result == nil {
		return "unknown"
	}
	if result.Alive {
		return fmt.Sprintf("%dms", result.Latency.Milliseconds())
	}
	if result.Message != "" {
		return result.Message
	}
	return "unavailable"
}
