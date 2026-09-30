/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"context"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"
)

func subtagFilter(tag string) []*config_parser.Function {
	return []*config_parser.Function{
		{Name: "subtag", Params: []*config_parser.Param{{Key: "", Val: tag}}},
	}
}

// TestFilterAndAnnotatePriorityOrdering pins the priority order: annotated
// dialers first, ascending by priority, then unannotated dialers in node order.
func TestFilterAndAnnotatePriorityOrdering(t *testing.T) {
	logger, _ := test.NewNullLogger()
	logger.SetLevel(logrus.WarnLevel)
	option := &dialer.GlobalOption{Log: logger, CheckInterval: time.Minute}
	set := NewDialerSetFromLinksContext(context.Background(), option, map[string][]string{
		"ta": {"socks5://u:p@203.0.113.1:1080"},
		"tb": {"socks5://u:p@203.0.113.2:1080"},
		"tc": {"socks5://u:p@203.0.113.3:1080"},
	})
	t.Cleanup(func() { _ = set.Close() })

	// Tags sort alphabetically, so the node order is ta, tb, tc.
	dialers, annos, err := set.FilterAndAnnotate(
		[][]*config_parser.Function{subtagFilter("ta"), subtagFilter("tb"), subtagFilter("tc")},
		[][]*config_parser.Param{
			{{Key: "priority", Val: "3"}},
			{{Key: "priority", Val: "1"}},
			{},
		},
	)
	require.NoError(t, err)
	require.Len(t, dialers, 3)

	got := make([]string, len(dialers))
	for i, d := range dialers {
		got[i] = set.nodeToTagMap[d]
	}
	require.Equal(t, []string{"tb", "ta", "tc"}, got)
	require.True(t, annos[0].HasPriority && annos[0].Priority == 1)
	require.True(t, annos[1].HasPriority && annos[1].Priority == 3)
	require.False(t, annos[2].HasPriority)
}
