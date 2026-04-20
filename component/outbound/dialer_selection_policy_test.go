/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"testing"

	"github.com/daeuniverse/dae/config"
	"github.com/stretchr/testify/require"
)

func TestNewDialerSelectionPolicyFromGroupParamRejectsInvalidPolicyType(t *testing.T) {
	_, err := NewDialerSelectionPolicyFromGroupParam(&config.Group{
		Policy: 123,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported function-list-or-string value type")
}
