/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/stretchr/testify/require"
)

func TestNewDialerSelectionPolicyFromGroupParamRejectsInvalidPolicyType(t *testing.T) {
	_, err := NewDialerSelectionPolicyFromGroupParam(&config.Group{
		Policy: 123,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported function-list-or-string value type")
}

func TestNewDialerSelectionPolicyFromGroupParamSelect(t *testing.T) {
	policy, err := NewDialerSelectionPolicyFromGroupParam(&config.Group{
		Policy: "select",
	})
	require.NoError(t, err)
	require.Equal(t, consts.DialerSelectionPolicy_Select, policy.Policy)
	require.Equal(t, 0, policy.FixedIndex)

	policy, err = NewDialerSelectionPolicyFromGroupParam(&config.Group{
		Policy: &config_parser.Function{
			Name:   "select",
			Params: []*config_parser.Param{{Val: "2"}},
		},
	})
	require.NoError(t, err)
	require.Equal(t, consts.DialerSelectionPolicy_Select, policy.Policy)
	require.Equal(t, 2, policy.FixedIndex)

	for _, invalid := range []*config_parser.Function{
		{Name: "select", Params: []*config_parser.Param{{Key: "index", Val: "1"}}},
		{Name: "select", Params: []*config_parser.Param{{Val: "x"}}},
		{Name: "select", Params: []*config_parser.Param{{Val: "1"}, {Val: "2"}}},
		{Name: "select", Not: true},
	} {
		_, err := NewDialerSelectionPolicyFromGroupParam(&config.Group{Policy: invalid})
		require.Error(t, err)
	}
}
