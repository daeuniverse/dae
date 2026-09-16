/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"testing"

	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/stretchr/testify/require"
)

// TestDNSConfigFingerprintKeepsAllFunctionParams is a regression guard: the
// fingerprint used to render functions with Function.String, whose display form
// ellipsizes params from index 5 on, so a DNS fallback or rule function with
// six or more params could fingerprint identical to a different one and the
// reload would skip the domain_routing_map clear+replay.
func TestDNSConfigFingerprintKeepsAllFunctionParams(t *testing.T) {
	params := func(last string) []*config_parser.Param {
		return []*config_parser.Param{
			{Key: "ip_version", Val: "4"},
			{Key: "p1", Val: "1"},
			{Key: "p2", Val: "2"},
			{Key: "p3", Val: "3"},
			{Key: "p4", Val: "4"},
			{Key: "p5", Val: last},
		}
	}
	build := func(last string) config.Dns {
		fn := &config_parser.Function{Name: "asis", Params: params(last)}
		return config.Dns{
			Routing: config.DnsRouting{
				Request:  config.DnsRequestRouting{Fallback: fn},
				Response: config.DnsResponseRouting{Fallback: fn},
			},
		}
	}

	// Sanity: the two functions really are distinct in their last param and the
	// display form cannot tell them apart.
	a := &config_parser.Function{Name: "asis", Params: params("aaa")}
	b := &config_parser.Function{Name: "asis", Params: params("bbb")}
	require.Equal(t, a.String(true, false, true), b.String(true, false, true),
		"fixture is stale: the display form stopped truncating params")
	require.NotEqual(t, a.MarshalString(true, false, true), b.MarshalString(true, false, true))

	require.NotEqual(t, dnsConfigFingerprint(build("aaa")), dnsConfigFingerprint(build("bbb")),
		"distinct DNS fallback params must change the fingerprint")
	require.Equal(t, dnsConfigFingerprint(build("aaa")), dnsConfigFingerprint(build("aaa")),
		"the fingerprint must stay stable for an unchanged config")
}
