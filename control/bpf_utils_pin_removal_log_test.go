//go:build !dae_stub_ebpf

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	_ "embed"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
)

// bpfUtilsSource is embedded rather than read at run time. The datapath
// whitelist harness in .github/workflows/bpf-test.yml runs this package's test
// binary from the repository root, so a relative os.ReadFile("bpf_utils.go")
// would not resolve there; go:embed resolves at compile time against this
// file's own directory and therefore works from any working directory (the
// same reason bpf_variables_parity_test.go embeds kern/tproxy.c).
//
//go:embed bpf_utils.go
var bpfUtilsSource string

// TestRemovedIncompatiblePinnedMapWarnsWithConsequence is the Q7 contract.
// Deleting a pinned map because the new object rejects its layout destroys live
// datapath state (the reloaded program starts with an empty map), and it was
// logged at info like a routine loader step. It is a warning, and the message
// must say what was deleted and what it costs, otherwise the only trace of the
// state loss is a name with no consequence attached.
//
// This file carries the real loader's build tag: logRemovedIncompatiblePinnedMap
// lives in bpf_utils.go, which only builds without dae_stub_ebpf.
func TestRemovedIncompatiblePinnedMapWarnsWithConsequence(t *testing.T) {
	logger, hook := test.NewNullLogger()
	logger.SetLevel(logrus.InfoLevel)

	logRemovedIncompatiblePinnedMap(logger, "conn_state_map", "/sys/fs/bpf/dae")

	entry := hook.LastEntry()
	if entry == nil {
		t.Fatal("removing an incompatible pinned map produced no log line")
	}
	if entry.Level != logrus.WarnLevel {
		t.Fatalf("pinned-map removal level = %v, want warn (it is destructive)", entry.Level)
	}
	if got := entry.Data["map"]; got != "conn_state_map" {
		t.Fatalf("removal line map=%v, want conn_state_map", got)
	}
	if got := entry.Data["pin_path"]; got != "/sys/fs/bpf/dae/conn_state_map" {
		t.Fatalf("removal line pin_path=%v, want the removed path", got)
	}
	for _, want := range []string{"incompatible", "lost", "established flows"} {
		if !strings.Contains(entry.Message, want) {
			t.Fatalf("removal message %q does not state %q", entry.Message, want)
		}
	}
}

// TestIncompatiblePinRemovalIsNotAnInfoStep pins the level at the call site: a
// later edit must not put the step notice back.
func TestIncompatiblePinRemovalIsNotAnInfoStep(t *testing.T) {
	src := bpfUtilsSource
	if strings.Contains(src, "Incompatible new map format with existing map") {
		t.Fatal("the pinned-map removal is back to being reported as an info step notice")
	}
	if !strings.Contains(src, "logRemovedIncompatiblePinnedMap(log, mapName, opts.PinPath)") {
		t.Fatal("the pinned-map removal no longer reports the removal")
	}
}
