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

// These are source contracts for log levels whose emission needs a live
// datapath (a control-plane build) or a signal, so a unit test cannot drive
// them. They pin the decisions an operator depends on.

// TestNoInterfaceToBindStaysAWarning pins Q10. dae binds interfaces lazily:
// bindLan/bindWan register a pattern with the InterfaceManager and attach when a
// matching link appears, so "no interface at this instant" is recoverable (a
// container whose veth is created after dae starts). Promoting it to error
// would report a fatal startup failure for a daemon that would have bound the
// interface moments later. The comment in the source records the invalidation
// condition that would make an error correct.
func TestNoInterfaceToBindStaysAWarning(t *testing.T) {
	src := readControlPlaneSources(t)
	if strings.Contains(src, `Errorln("No interface to bind.")`) || strings.Contains(src, `Fatalf("No interface to bind.")`) {
		t.Fatal("No interface to bind. became an error; it is recoverable through the link-subscription lazy bind")
	}
	if !strings.Contains(src, `Warnln("No interface to bind.")`) {
		t.Fatal("No interface to bind. is no longer reported at warn")
	}
	// The reasoning must stay attached to the site, because the level is only
	// correct while the lazy-bind path exists.
	if !strings.Contains(src, "binds interfaces lazily") {
		t.Fatal("the lazy-bind justification for keeping this at warn is gone")
	}
	if !strings.Contains(src, "must become an error") {
		t.Fatal("the invalidation condition for the warn level is gone")
	}
}

// TestSoMarkUnsetWarnsOnTheUserVisiblePath pins Q11's cmd half. The auto-selected
// so_mark is resolved here, before control.NewControlPlane sees the config, so
// this is the line a user actually sees when they leave so_mark_from_dae unset.
// It must stay at warn (silently substituting a mark changes which traffic the
// datapath can capture) while the control-side duplicate stays where it is.
func TestSoMarkUnsetWarnsOnTheUserVisiblePath(t *testing.T) {
	src := readControlPlaneSources(t)
	const warn = `log.Warnf("so_mark_from_dae is unset; using internal socket mark %#x to prevent dae UDP self-capture", conf.Global.SoMarkFromDae)`
	if !strings.Contains(src, warn) {
		t.Fatal("the user-visible so_mark auto-selection warning is gone")
	}
	if !strings.Contains(src, "reachable, user-visible report") {
		t.Fatal("the comment explaining why this site keeps the warning is gone")
	}
}

// TestReloadRejectionWarningsAreNotDuplicates pins Q12: the three "ignoring this
// signal" warnings are mutually exclusive conditions (a pending reload, a full
// queue, a reload still becoming ready), not three reports of one event. They
// must stay at warn; folding them together would hide which admission rule
// rejected the signal.
func TestReloadRejectionWarningsAreNotDuplicates(t *testing.T) {
	reload := readReloadSources(t)
	for _, warning := range []string{
		"[Reload] Reload already in progress or handoff pending; ignoring this signal",
		"[Reload] Last reload request still processing, ignore this one",
		"[Reload] Signal received while current reload is still becoming ready; ignoring it",
	} {
		if !strings.Contains(reload, `Warnln("`+warning+`")`) {
			t.Fatalf("reload rejection %q is no longer reported at warn", warning)
		}
	}
}

func readReloadSources(t *testing.T) string {
	t.Helper()
	var b strings.Builder
	for _, name := range []string{"run_reload.go", "run_reload_worker.go", "reload_manager.go"} {
		b.WriteString(readCommandFile(t, name))
		b.WriteByte('\n')
	}
	return b.String()
}

// readControlPlaneSources covers the control-plane construction path, which
// lives in run_controlplane.go (not in readCommandSources' reload file set).
func readControlPlaneSources(t *testing.T) string {
	t.Helper()
	return readCommandFile(t, "run_controlplane.go")
}

func readCommandFile(t *testing.T, name string) string {
	t.Helper()
	src, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(src)
}
