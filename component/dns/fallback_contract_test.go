/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dns

import (
	"testing"

	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func TestRequestMatcherBuilderRejectsInvalidFallbackType(t *testing.T) {
	_, err := NewRequestMatcherBuilder(logrus.New(), nil, map[string]uint8{}, 123)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported function-or-string value type")
}

func TestResponseMatcherBuilderRejectsInvalidFallbackType(t *testing.T) {
	_, err := NewResponseMatcherBuilder(logrus.New(), nil, map[string]uint8{}, 123)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported function-or-string value type")
}

func TestRequestMatcherBuilderRejectsInternalSelectorsWithoutExplicitSplit(t *testing.T) {
	_, err := NewRequestMatcherBuilder(logrus.New(), []*config_parser.RoutingRule{
		{
			AndFunctions: []*config_parser.Function{{Name: "sub"}},
		},
	}, map[string]uint8{}, "asis")
	require.Error(t, err)
	require.Contains(t, err.Error(), "explicit request-rule splitting")
}
