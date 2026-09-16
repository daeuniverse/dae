/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package dns

import (
	"fmt"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

// TestRequestMatcherBuildRejectsTooManyDomainRules pins the regression where
// more than consts.MaxMatchSetLen domain rules indexed past the per-rule
// slices allocated in the domain matcher and panicked the build. The failure
// must surface as a Build error naming the limit instead.
func TestRequestMatcherBuildRejectsTooManyDomainRules(t *testing.T) {
	b := &RequestMatcherBuilder{log: logrus.New()}
	key := string(consts.RoutingDomainKey_Full)
	for i := 0; i <= consts.MaxMatchSetLen; i++ {
		outbound := &routing.Outbound{Name: consts.DnsRequestOutboundIndex_AsIs.String()}
		err := b.addQName(&config_parser.Function{}, key, []string{fmt.Sprintf("rule-%d.example.com", i)}, outbound)
		require.NoError(t, err)
	}
	b.rules = append(b.rules, requestMatchSet{
		Type:     consts.MatchType_Fallback,
		Upstream: uint8(consts.DnsRequestOutboundIndex_AsIs),
	})

	_, err := b.Build()
	require.Error(t, err)
	require.Contains(t, err.Error(), "out of range")
}
