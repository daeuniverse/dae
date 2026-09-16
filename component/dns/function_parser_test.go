/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package dns

import (
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

// qtype takes bare values (`qtype(1, AAAA)`), so a named parameter is a typo by
// construction: the parser used to fold the value into the operand list and
// build a different matcher with no error.

func TestTypeParserFactoryAcceptsBareValues(t *testing.T) {
	var got []uint16
	parser := TypeParserFactory(func(_ *config_parser.Function, types []uint16, _ *routing.Outbound) error {
		got = types
		return nil
	})
	require.NoError(t, parser(logrus.New(), &config_parser.Function{Name: consts.Function_QType}, "", []string{"1", "AAAA"}, &routing.Outbound{}))
	require.Equal(t, []uint16{1, 28}, got)
}

func TestTypeParserFactoryRejectsNamedParameter(t *testing.T) {
	parser := TypeParserFactory(func(_ *config_parser.Function, _ []uint16, _ *routing.Outbound) error { return nil })
	err := parser(logrus.New(), &config_parser.Function{Name: consts.Function_QType}, "bogus_param", []string{"1"}, &routing.Outbound{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "qtype: unsupported parameter key")
	require.Contains(t, err.Error(), `"bogus_param"`)
}

// TestRequestMatcherBuilderRejectsNamedParameterOnQType drives the run path
// (`dae run` builds its DNS request matchers through this builder) rather than
// the parser alone.
func TestRequestMatcherBuilderRejectsNamedParameterOnQType(t *testing.T) {
	rule := func(key string) []*config_parser.RoutingRule {
		return []*config_parser.RoutingRule{{
			AndFunctions: []*config_parser.Function{{
				Name:   consts.Function_QType,
				Params: []*config_parser.Param{{Key: key, Val: "1"}},
			}},
			Outbound: config_parser.Function{Name: consts.DnsRequestOutboundIndex_Reject.String()},
		}}
	}

	program, err := NewNormalizedRequestRoutingProgram(rule("bogus_param"), consts.DnsRequestOutboundIndex_AsIs.String())
	require.NoError(t, err)
	_, err = NewRequestMatcherBuilderFromProgram(logrus.New(), program, map[string]uint8{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "qtype: unsupported parameter key")

	program, err = NewNormalizedRequestRoutingProgram(rule(""), consts.DnsRequestOutboundIndex_AsIs.String())
	require.NoError(t, err)
	_, err = NewRequestMatcherBuilderFromProgram(logrus.New(), program, map[string]uint8{})
	require.NoError(t, err)
}
