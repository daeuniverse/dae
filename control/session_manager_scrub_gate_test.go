/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"testing"
)

// TestCountConnStateScrubErrorCountsAndLogs pins the "no silent degradation"
// contract that replaced the discarded batch-delete errors: failures are
// counted, and a nil error is not counted at all.
func TestCountConnStateScrubErrorCountsAndLogs(t *testing.T) {
	before := connStateScrubErrorCount.Load()
	countConnStateScrubError("primary", nil)
	if got := connStateScrubErrorCount.Load(); got != before {
		t.Fatalf("nil error must not be counted: %d -> %d", before, got)
	}
	countConnStateScrubError("primary", context.Canceled)
	countConnStateScrubError("migrated", context.DeadlineExceeded)
	if got := connStateScrubErrorCount.Load(); got != before+2 {
		t.Fatalf("scrub error count = %d, want %d", got, before+2)
	}
}
