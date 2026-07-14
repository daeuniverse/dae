/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"testing"
	"time"

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

func TestParseDurationWithUnit(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		want    time.Duration
		wantErr bool
	}{
		{"milliseconds", "500ms", 500 * time.Millisecond, false},
		{"seconds with suffix", "5s", 5 * time.Second, false},
		{"minutes", "2m", 2 * time.Minute, false},
		{"no suffix defaults to seconds", "10", 10 * time.Second, false},
		{"zero no suffix", "0", 0, false},
		{"float seconds", "1.5s", 1500 * time.Millisecond, false},
		{"float minutes", "0.5m", 30 * time.Second, false},
		{"whitespace tolerated", "  3s  ", 3 * time.Second, false},
		{"empty string errors", "", 0, true},
		{"bare s errors", "s", 0, true},
		{"non numeric errors", "abc", 0, true},
		{"garbage with ms errors", "abcms", 0, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := parseDurationWithUnit(c.input)
			if c.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, c.want, got)
		})
	}
}
