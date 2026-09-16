//go:build linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"os"
	"strings"
	"testing"
)

// TestTCPOffloadFuseEngageIsAllOrNothing is the source contract. A
// partially engaged pause is worse than a failed engage: the caller only drops
// the fds from epoll (delFds) after a successful engage, and the fuse state
// must therefore never be published before both map updates succeeded.
func TestTCPOffloadFuseEngageIsAllOrNothing(t *testing.T) {
	src, err := os.ReadFile("tcp_offload_linux.go")
	if err != nil {
		t.Fatalf("read tcp_offload_linux.go: %v", err)
	}
	text := string(src)

	// The engage branch must be the only place that sets fused, and both
	// updates must precede it.
	leftIdx := strings.Index(text, "s.pauseMap.Update(&s.leftKey, &one, ebpf.UpdateAny)")
	rightIdx := strings.Index(text, "s.pauseMap.Update(&s.rightKey, &one, ebpf.UpdateAny)")
	fusedIdx := strings.Index(text, "\t\ts.fused = true\n")
	if leftIdx < 0 || rightIdx < 0 {
		t.Fatal("engage branch must update both pause keys explicitly")
	}
	if fusedIdx < 0 {
		t.Fatal("engage branch must set fused explicitly")
	}
	if leftIdx >= rightIdx || rightIdx >= fusedIdx {
		t.Fatalf("fused must be set only after both pause updates succeeded (left=%d right=%d fused=%d)", leftIdx, rightIdx, fusedIdx)
	}

	// A failed update must roll back the side already written and report.
	if !strings.Contains(text, `s.reportOffloadMapFailure("pause-rollback"`) {
		t.Fatal("engage failure must roll back the written pause keys")
	}
	if !strings.Contains(text, `s.reportOffloadMapFailure("pause-engage"`) {
		t.Fatal("engage failure must be counted and warned about")
	}
	if !strings.Contains(text, `s.reportOffloadMapFailure("pause-lift"`) {
		t.Fatal("lift failure must be counted and warned about")
	}

	// No fuse-map maintenance may discard its error any more.
	for _, forbidden := range []string{
		"_ = s.pauseMap.Update(",
		"_ = s.pauseMap.Delete(",
		"_ = s.sentMap.Delete(",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("fuse-map maintenance still swallows errors: %s", forbidden)
		}
	}

	// Close must join the fuse-map failures into its error instead of dropping
	// them, and the counter must exist.
	if !strings.Contains(text, "errs = append(errs, s.pendingErrs...)") {
		t.Fatal("Close must join the deferred fuse-map failures into its error")
	}
	if !strings.Contains(text, "tcpOffloadMapFailureCount") {
		t.Fatal("fuse-map failures must be counted")
	}
}
