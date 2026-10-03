/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package metrics

import (
	"testing"
)

func TestDialerMetricNameSuffixesDuplicates(t *testing.T) {
	seen := make(map[string]int)
	got := []string{
		dialerMetricName(seen, "HK 01"),
		dialerMetricName(seen, "JP 01"),
		dialerMetricName(seen, "HK 01"),
		dialerMetricName(seen, "HK 01"),
	}
	want := []string{"HK 01", "JP 01", "HK 01 #2", "HK 01 #3"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("name %d = %q, want %q (all: %q)", i, got[i], want[i], got)
		}
	}
}

// TestDialerMetricNetworkTypesAreDistinct pins one series per health
// collection: tcp4(DNS)/tcp6(DNS) alias tcp4/tcp6 and must not be exported.
func TestDialerMetricNetworkTypesAreDistinct(t *testing.T) {
	want := map[string]bool{
		"tcp4": true, "tcp6": true,
		"udp4(DNS)": true, "udp6(DNS)": true,
		"udp4": true, "udp6": true,
	}
	indexes := make(map[int]string)
	for _, typ := range dialerMetricNetworkTypes {
		label := typ.String()
		if !want[label] {
			t.Fatalf("unexpected network label %q", label)
		}
		delete(want, label)
		if prev, ok := indexes[typ.Index()]; ok {
			t.Fatalf("%q and %q share collection index %d", prev, label, typ.Index())
		}
		indexes[typ.Index()] = label
	}
	if len(want) != 0 {
		t.Fatalf("missing network labels: %v", want)
	}
}
