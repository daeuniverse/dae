/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package config_parser

import (
	"strconv"
	"strings"
	"testing"
)

// TestDisplayStringCollapsesExpandedParams pins the fix for the oversized rules
// response: a geosite-expanded rule must not render every suffix.
func TestDisplayStringCollapsesExpandedParams(t *testing.T) {
	params := make([]*Param, 0, 5000)
	for i := 0; i < 5000; i++ {
		params = append(params, &Param{Key: "suffix", Val: "d" + strconv.Itoa(i) + ".example.com"})
	}
	rule := &RoutingRule{
		AndFunctions: []*Function{{Name: "domain", Params: params}},
		Outbound:     Function{Name: "block"},
	}

	display := rule.DisplayString(false, false)
	if !strings.Contains(display, "+4992 more") {
		t.Fatalf("display = %q, want a '+4992 more' marker", display)
	}
	if n := strings.Count(display, "suffix:"); n != DisplayParamLimit {
		t.Fatalf("rendered params = %d, want %d", n, DisplayParamLimit)
	}
	// The whole point: the display form must be small enough for a UI.
	if len(display) > 512 {
		t.Fatalf("display length = %d, want <= 512", len(display))
	}
	if !strings.HasSuffix(display, "-> block") {
		t.Fatalf("display = %q, want the outbound suffix", display)
	}

	// Lossless forms stay lossless: reload fingerprints and policy hashes must
	// keep seeing every parameter.
	if n := strings.Count(rule.String(false, false, false), "suffix:"); n != len(params) {
		t.Fatalf("String rendered %d params, want all %d", n, len(params))
	}
}
