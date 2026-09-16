/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package dns

import (
	"testing"

	"github.com/daeuniverse/dae/component/routing"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func TestRequestMatcherBuilderRejectsInvalidFallbackType(t *testing.T) {
	program, err := NewNormalizedRequestRoutingProgram(nil, 123)
	require.NoError(t, err)
	_, err = NewRequestMatcherBuilderFromProgram(logrus.New(), program, map[string]uint8{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported function-or-string value type")
}

func TestResponseMatcherBuilderRejectsInvalidFallbackType(t *testing.T) {
	program, err := routing.NewNormalizedProgram(nil, 123)
	require.NoError(t, err)
	_, err = NewResponseMatcherBuilderFromProgram(logrus.New(), program, map[string]uint8{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported function-or-string value type")
}
