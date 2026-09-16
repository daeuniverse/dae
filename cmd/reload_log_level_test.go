/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"os"
	"strings"
	"testing"
)

// These are source contracts for the reload lifecycle levels. The reload loop
// runs inside the serve loop, so there is no seam to run it from a test; the
// next best deterministic guard is the source itself.
//
// The rule being pinned: an operator-requested reload is a lifecycle
// milestone, not an anomaly. Its milestones belong at info, which is still
// visible at the default log level, so a user who sets log_level=warn asks for
// "warnings only" and must not receive a warning wall for a reload they asked
// for. Real failures (a failed handoff, a rollback, an ignored request) stay at
// warn/error.

var reloadSourceFiles = []string{
	"run.go",
	"run_reload.go",
	"run_reload_worker.go",
	"run_serve.go",
	"reload_manager.go",
}

// reloadMilestones are emitted on every successful reload, once per reload, and
// describe progress only.
var reloadMilestones = []string{
	"[Reload] Received suspend signal; prepare to suspend",
	"[Reload] Received reload signal; prepare to reload",
	"[Reload] Load new config",
	"[Reload] Prepare staged same-port handoff",
	"[Reload] Prepare fresh datapath handoff",
	"[Reload] Load new control plane",
	"[Reload] Prepared new control plane",
	"[Reload] Retiring old control plane",
	"[Reload] Retired old control plane",
	"[Reload] Re-listening after reload",
	"[Reload] Finished",
	"[Reload] Serve",
}

// reloadFailures describe a reload that did not go through cleanly. They must
// stay at warn or above: demoting a milestone must not demote these too.
var reloadFailures = []string{
	"[Reload] Kernel datapath input changed (interface/somark/map-size); will perform a fresh datapath handoff",
	"[Reload] Reload already in progress or handoff pending; ignoring this signal",
	"[Reload] Last reload request still processing, ignore this one",
	"[Reload] Signal received while current reload is still becoming ready; ignoring it",
	"[Reload] Discarded fresh datapath candidate; previous generation remained active",
	"[Reload] Restored previous generation after fresh datapath handoff failure",
	"[Reload] Restored previous listener generation after staged handoff failure",
	"[Reload] Last reload failed; rolled back configuration",
	"[Reload] Abort requested; aborting stale connections immediately",
}

// TestReloadMilestonesAreNotWarnings asserts every milestone line is emitted
// through an info-level call. A milestone that stays at warn is the regression
// this guards against.
func TestReloadMilestonesAreNotWarnings(t *testing.T) {
	text := readCommandSources(t)
	for _, milestone := range reloadMilestones {
		for _, bad := range []string{
			`Warnln("` + milestone + `")`,
			`Warnf("` + milestone + `"`,
			`Warn("` + milestone + `")`,
		} {
			if strings.Contains(text, bad) {
				t.Fatalf("reload milestone %q is still logged as a warning (%s)", milestone, bad)
			}
		}
		if !strings.Contains(text, `Infoln("`+milestone+`")`) && !strings.Contains(text, `Infof("`+milestone+`"`) {
			t.Fatalf("reload milestone %q is not logged at info level", milestone)
		}
	}
}

// TestReloadFailuresKeepTheirSeverity is the other half of the contract: the
// demotion of the milestones must not have demoted the failures with them.
func TestReloadFailuresKeepTheirSeverity(t *testing.T) {
	text := readCommandSources(t)
	for _, failure := range reloadFailures {
		warned := strings.Contains(text, `Warnln("`+failure+`")`) ||
			strings.Contains(text, `Warnf("`+failure+`"`) ||
			strings.Contains(text, `Warn("`+failure+`")`) ||
			strings.Contains(text, `Errorln("`+failure+`")`) ||
			strings.Contains(text, `Errorf("`+failure+`"`)
		if !warned {
			t.Fatalf("reload failure %q is no longer logged at warn or above", failure)
		}
	}
}

func readCommandSources(t *testing.T) string {
	t.Helper()
	var b strings.Builder
	for _, name := range reloadSourceFiles {
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		b.Write(src)
		b.WriteByte('\n')
	}
	return b.String()
}
