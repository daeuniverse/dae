/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package dns

import (
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/assets"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/config"
	"github.com/sirupsen/logrus"
)

// upstreamName2Id maps every dns.upstream tag to the index dns.New assigns it.
// The declared order of dns.Upstream is the only input, so the namespace the
// DNS routing rules resolve against is a function of the configuration alone
// and can be rebuilt outside dns.New without drifting from the run path.
func upstreamName2Id(dnsCfg *config.Dns) map[string]uint8 {
	upstreamName2Id := make(map[string]uint8, len(dnsCfg.Upstream))
	for i, upstreamRaw := range dnsCfg.Upstream {
		tag, _ := common.GetTagFromLinkLikePlaintext(string(upstreamRaw))
		if tag == "" {
			// dns.New rejects an untagged upstream before the routing blocks are
			// parsed, so there is no name to record; the format check itself
			// stays on the run path (see ValidateRouting).
			continue
		}
		upstreamName2Id[tag] = uint8(i)
	}
	return upstreamName2Id
}

// ValidateRouting dry-runs the DNS request/response routing exactly the way
// dns.New builds it, and throws the result away.
//
// The run path parses both blocks through NewNormalizedRequestRoutingProgram /
// routing.NewNormalizedProgram and the RequestMatcherBuilder /
// ResponseMatcherBuilder parser registries, so an operand it rejects -
// `qtype(notavalidtype)`, an unknown qname key, an undefined upstream name, a
// malformed fallback - refused daemon startup. `dae validate` never entered
// that chain: it dry-ran the main routing block only, so every DNS routing
// typo exited 0 while `dae run` refused to start on the same file.
//
// The very same builders are reused here rather than a second copy of the
// checks - the way cmd.validateRoutingRules reuses
// control.RegisterRoutingProgramParsers - and that reuse is what keeps
// validate from ever being stricter than run: a configuration that passes this
// call parses on the run path too. Only the matcher objects are dropped; no
// BPF object, socket or upstream connection is touched, and upstream
// reachability is deliberately not tested because dns.New does not test it
// either.
func ValidateRouting(log *logrus.Logger, dnsCfg *config.Dns, externGeoDataDirs []string) error {
	if dnsCfg == nil {
		return nil
	}
	if log == nil {
		log = logrus.New()
	}

	// Same optimizer set as dns.New: DatReaderOptimizer expands the
	// geosite/geoip operands and reports an unreadable asset, while
	// MergeAndSortRulesOptimizer and DeduplicateParamsOptimizer only reorder
	// and deduplicate. The alias optimizer is not applied because dns.New does
	// not apply it to the DNS blocks.
	datReader := &routing.DatReaderOptimizer{
		Logger:         log,
		LocationFinder: assets.NewLocationFinder(externGeoDataDirs),
	}

	requestProgram, err := NewNormalizedRequestRoutingProgram(
		dnsCfg.Routing.Request.Rules, dnsCfg.Routing.Request.Fallback,
		datReader, &routing.MergeAndSortRulesOptimizer{}, &routing.DeduplicateParamsOptimizer{},
	)
	if err != nil {
		return err
	}
	// Same upstream namespace dns.New hands to the request matcher.
	requestBuilder, err := NewRequestMatcherBuilderFromProgram(log, requestProgram, upstreamName2Id(dnsCfg))
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
	responseBuilder, err := NewResponseMatcherBuilderFromProgram(log, responseProgram, upstreamName2Id(dnsCfg))
	if err != nil {
		return err
	}
	_, err = responseBuilder.Build()
	return err
}
