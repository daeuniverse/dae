/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import "testing"

// dnsControllerOption is called from three places: the initial build, reload
// reuse (ReuseForReload) and the staged DNS handoff. Every config-derived
// tunable must ride along on all of them — a field that is only patched onto
// the option at the build call site silently resets to its zero value on
// reload, which previously turned the DNS cache size limit off.
func TestDnsControllerOptionCarriesRuntimeTunables(t *testing.T) {
	fixedTtl := map[string]int{"example.com.": 60}
	plane := &ControlPlane{
		controlPlaneDNSRuntime: controlPlaneDNSRuntime{
			dnsFixedDomainTtl:     fixedTtl,
			dnsOptimisticCache:    true,
			dnsOptimisticCacheTtl: 600,
			dnsMaxCacheSize:       65536,
			dnsIpVersionPrefer:    4,
		},
	}

	option := plane.dnsControllerOption()
	if option == nil {
		t.Fatal("dnsControllerOption() = nil")
		return
	}

	for _, tc := range []struct {
		field string
		got   any
		want  any
	}{
		{field: "OptimisticCache", got: option.OptimisticCache, want: true},
		{field: "OptimisticCacheTtl", got: option.OptimisticCacheTtl, want: 600},
		{field: "MaxCacheSize", got: option.MaxCacheSize, want: 65536},
		{field: "IpVersionPrefer", got: option.IpVersionPrefer, want: 4},
	} {
		t.Run(tc.field, func(t *testing.T) {
			if tc.got != tc.want {
				t.Fatalf("dnsControllerOption().%s = %v, want %v", tc.field, tc.got, tc.want)
			}
		})
	}
	if len(option.FixedDomainTtl) != 1 || option.FixedDomainTtl["example.com."] != 60 {
		t.Fatalf("dnsControllerOption().FixedDomainTtl = %v, want %v", option.FixedDomainTtl, fixedTtl)
	}
}
