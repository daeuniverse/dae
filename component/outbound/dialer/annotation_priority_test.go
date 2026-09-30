/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/stretchr/testify/require"
)

func TestNewAnnotationPriority(t *testing.T) {
	anno, err := NewAnnotation([]*config_parser.Param{
		{Key: AnnotationKey_Priority, Val: "2"},
		{Key: AnnotationKey_AddLatency, Val: "-500ms"},
	})
	require.NoError(t, err)
	require.True(t, anno.HasPriority)
	require.Equal(t, 2, anno.Priority)
	require.Equal(t, -500*time.Millisecond, anno.AddLatency)

	_, err = NewAnnotation([]*config_parser.Param{{Key: AnnotationKey_Priority, Val: "x"}})
	require.Error(t, err)

	plain, err := NewAnnotation(nil)
	require.NoError(t, err)
	require.False(t, plain.HasPriority)
}
