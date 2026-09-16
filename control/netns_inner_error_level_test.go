/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"strings"
	"testing"
)

// TestNetnsInnerFailureDetailIsDebug is the Q9 contract for the dae-netns link
// setup. Each of these sites logged the same failure as the error it returned
// with %w, so one broken dae0 link produced two error lines: the inner one and
// the caller's (With/WithRequired -> "GetDaeNetns.With:" in cmd/run.go, which
// prints the whole chain).
//
// Every inner site here wraps with %w, so the outer line still carries the
// exact cause; the per-site detail stays available at debug. If a site ever
// returns a NEW error instead of wrapping, its inner line must go back to
// error -- CheckNetnsInnerSitesWrapTheirCause guards that.
func TestNetnsInnerFailureDetailIsDebug(t *testing.T) {
	src := readPackageSource(t, "netns_utils.go")
	for _, gone := range []string{
		`ns.log.Errorf("Failed to get link %s: %v", HostVethName, err)`,
		`ns.log.Errorf("Failed to get link %s: %v", NsVethName, err)`,
		`ns.log.Errorf("Failed to set link dae0 up: %v", err)`,
	} {
		if strings.Contains(src, gone) {
			t.Fatalf("inner netns failure is still duplicated at error level: %s", gone)
		}
	}
	for _, want := range []string{
		`ns.log.Debugf("Failed to get link %s: %v", HostVethName, err)`,
		`ns.log.Debugf("Failed to get link %s: %v", NsVethName, err)`,
		`ns.log.Debugf("Failed to set link dae0 up: %v", err)`,
	} {
		if !strings.Contains(src, want) {
			t.Fatalf("inner netns failure detail is gone instead of demoted to debug: %s", want)
		}
	}
}

// CheckNetnsInnerSitesWrapTheirCause is the invalidation condition of the
// demotion above: the inner line may only be debug while the returned error
// wraps the same cause, so the outer report can carry it.
func TestNetnsInnerSitesWrapTheirCause(t *testing.T) {
	src := readPackageSource(t, "netns_utils.go")
	for _, pair := range []struct {
		inner string
		outer string
	}{
		{
			inner: `ns.log.Debugf("Failed to get link %s: %v", HostVethName, err)`,
			outer: `return fmt.Errorf("failed to get link dae0: %w", err)`,
		},
		{
			inner: `ns.log.Debugf("Failed to get link %s: %v", NsVethName, err)`,
			outer: `return fmt.Errorf("failed to get link dae0peer: %w", err)`,
		},
		{
			inner: `ns.log.Debugf("Failed to set link dae0 up: %v", err)`,
			outer: `return fmt.Errorf("failed to set link dae0 up: %w", err)`,
		},
	} {
		if !strings.Contains(src, pair.inner) {
			t.Fatalf("expected demoted detail line is missing: %s", pair.inner)
		}
		if !strings.Contains(src, pair.outer) {
			t.Fatalf("the returned error no longer wraps the inner cause (%s); the inner line must go back to error level", pair.outer)
		}
	}
}
