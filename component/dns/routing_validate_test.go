/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package dns

import (
	"testing"

	"github.com/daeuniverse/dae/common/assets"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

// TestValidateRoutingMatchesRunPath is the #2 regression: `dae validate` used
// to dry-run the main routing block only, so a DNS routing typo such as
// `qtype(notavalidtype)` exited 0 while `dae run` refused to start on the same
// file. ValidateRouting must now reach the same verdict as the run path for
// every operand the block accepts.
//
// The run side is reproduced here as the exact call chain the run path uses
// (component/dns.New -> NewNormalizedRequestRoutingProgram /
// routing.NewNormalizedProgram -> New{Request,Response}MatcherBuilderFromProgram
// -> Build) plus the shared upstreamName2Id mapping. The assertions are
// two-sided on purpose: validate must reject what run rejects (the bug) AND
// must keep accepting what run accepts (the "validate must never be stricter
// than run" contract this repository has established).
func TestValidateRoutingMatchesRunPath(t *testing.T) {
	parseDns := func(t *testing.T, dnsBlock string) *config.Dns {
		t.Helper()
		sections, err := config_parser.Parse("global {}\ndns {\n" + dnsBlock + "\n}\nrouting {\n fallback: direct\n}\n")
		require.NoError(t, err)
		conf, err := config.New(sections)
		require.NoError(t, err)
		return &conf.Dns
	}

	// runPathErr is the run path's verdict, expressed with the same builders
	// dns.New calls and the same upstream namespace helper dns.New calls.
	runPathErr := func(dnsCfg *config.Dns) error {
		log := logrus.New()
		named := upstreamName2Id(dnsCfg)
		datReader := &routing.DatReaderOptimizer{Logger: log, LocationFinder: assets.NewLocationFinder(nil)}

		requestProgram, err := NewNormalizedRequestRoutingProgram(
			dnsCfg.Routing.Request.Rules, dnsCfg.Routing.Request.Fallback,
			datReader, &routing.MergeAndSortRulesOptimizer{}, &routing.DeduplicateParamsOptimizer{},
		)
		if err != nil {
			return err
		}
		requestBuilder, err := NewRequestMatcherBuilderFromProgram(log, requestProgram, named)
		if err != nil {
			return err
		}
		if _, err = requestBuilder.Build(); err != nil {
			return err
		}

		responseProgram, err := routing.NewNormalizedProgram(
			dnsCfg.Routing.Response.Rules, dnsCfg.Routing.Response.Fallback,
			datReader, &routing.MergeAndSortRulesOptimizer{}, &routing.DeduplicateParamsOptimizer{},
		)
		if err != nil {
			return err
		}
		responseBuilder, err := NewResponseMatcherBuilderFromProgram(log, responseProgram, named)
		if err != nil {
			return err
		}
		_, err = responseBuilder.Build()
		return err
	}

	upstreams := " upstream {\n  alidns: 'udp://dns.alidns.com:53'\n  googledns: 'tcp+udp://dns.google:53'\n }\n"

	cases := map[string]struct {
		body    string
		wantErr bool
	}{
		// The reported defect: `qtype(notavalidtype)` used to exit 0.
		"qtype unknown name": {
			body:    upstreams + " routing {\n  request {\n   qtype(notavalidtype) -> alidns\n   fallback: googledns\n  }\n }",
			wantErr: true,
		},
		"qtype numeric overflow": {
			body:    upstreams + " routing {\n  request {\n   qtype(99999) -> alidns\n   fallback: googledns\n  }\n }",
			wantErr: true,
		},
		"qtype legal names": {
			body: upstreams + " routing {\n  request {\n   qtype(a, aaaa, cname) -> alidns\n   fallback: googledns\n  }\n }",
		},
		"qtype legal numeric": {
			body: upstreams + " routing {\n  request {\n   qtype(1, 28) -> alidns\n   fallback: googledns\n  }\n }",
		},
		"qtype named parameter": {
			body:    upstreams + " routing {\n  request {\n   qtype(bogus_param: a) -> alidns\n   fallback: googledns\n  }\n }",
			wantErr: true,
		},
		"qname unsupported key": {
			body:    upstreams + " routing {\n  request {\n   qname(bogus: a.com) -> alidns\n   fallback: googledns\n  }\n }",
			wantErr: true,
		},
		"qname legal suffix": {
			body: upstreams + " routing {\n  request {\n   qname(suffix: a.com) -> alidns\n   fallback: googledns\n  }\n }",
		},
		"qtype undefined upstream": {
			body:    upstreams + " routing {\n  request {\n   qtype(a) -> nosuchupstream\n   fallback: googledns\n  }\n }",
			wantErr: true,
		},
		"second upstream is addressable": {
			body: upstreams + " routing {\n  request {\n   qtype(a) -> googledns\n   fallback: alidns\n  }\n }",
		},
		"request fallback undefined upstream": {
			body:    upstreams + " routing {\n  request {\n   qtype(a) -> alidns\n   fallback: nosuchupstream\n  }\n }",
			wantErr: true,
		},
		"request fallback rejects mark": {
			body:    upstreams + " routing {\n  request {\n   qtype(a) -> alidns\n   fallback: alidns(mark: 1)\n  }\n }",
			wantErr: true,
		},
		"request fallback asis": {
			body: upstreams + " routing {\n  request {\n   fallback: asis\n  }\n }",
		},
		"unknown function": {
			body:    upstreams + " routing {\n  request {\n   qtypes(a) -> alidns\n   fallback: alidns\n  }\n }",
			wantErr: true,
		},
		"response qtype unknown name": {
			body:    upstreams + " routing {\n  request {\n   fallback: alidns\n  }\n  response {\n   qtype(notavalidtype) -> accept\n   fallback: accept\n  }\n }",
			wantErr: true,
		},
		"response qtype legal": {
			body: upstreams + " routing {\n  request {\n   fallback: alidns\n  }\n  response {\n   qtype(a) -> accept\n   fallback: accept\n  }\n }",
		},
		"response malformed cidr": {
			body:    upstreams + " routing {\n  request {\n   fallback: alidns\n  }\n  response {\n   ip(1.2.3.4/999) -> googledns\n   fallback: accept\n  }\n }",
			wantErr: true,
		},
		"response legal ip and upstream": {
			body: upstreams + " routing {\n  request {\n   fallback: alidns\n  }\n  response {\n   ip(1.2.3.4/24) -> googledns\n   upstream(googledns) -> accept\n   fallback: reject\n  }\n }",
		},
		"response upstream is not a dns upstream": {
			body:    upstreams + " routing {\n  request {\n   fallback: alidns\n  }\n  response {\n   upstream(direct) -> accept\n   fallback: accept\n  }\n }",
			wantErr: true,
		},
		"response upstream named parameter": {
			body:    upstreams + " routing {\n  request {\n   fallback: alidns\n  }\n  response {\n   upstream(bogus: googledns) -> accept\n   fallback: accept\n  }\n }",
			wantErr: true,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			dnsCfg := parseDns(t, tc.body)
			runErr := runPathErr(dnsCfg)
			validateErr := ValidateRouting(logrus.New(), dnsCfg, nil)

			if tc.wantErr {
				require.Error(t, runErr, "run path must reject this configuration")
				require.Error(t, validateErr, "validate must reject what run rejects")
			} else {
				require.NoError(t, runErr, "run path must accept this configuration")
				require.NoError(t, validateErr, "validate must not be stricter than run")
			}
			// The equivalence itself, independent of the table: the two verdicts
			// never disagree.
			require.Equal(t, runErr != nil, validateErr != nil,
				"validate/run verdict diverged: run=%v validate=%v", runErr, validateErr)
		})
	}
}
