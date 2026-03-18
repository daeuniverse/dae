/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"io"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	ob "github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	D "github.com/daeuniverse/outbound/dialer"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func TestUdpFailover_StickyExclusion(t *testing.T) {
	log := logrus.New()
	log.SetOutput(io.Discard)

	checkInterval := 10 * time.Second
	opts := &dialer.GlobalOption{
		Log:           log,
		CheckInterval: checkInterval,
	}

	d1 := dialer.NewDialer(nil, opts, dialer.InstanceOption{}, &dialer.Property{Property: D.Property{Name: "node-1"}})
	d2 := dialer.NewDialer(nil, opts, dialer.InstanceOption{}, &dialer.Property{Property: D.Property{Name: "node-2"}})

	group := ob.NewDialerGroup(opts, "test-group", []*dialer.Dialer{d1, d2}, []*dialer.Annotation{{}, {}}, ob.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_MinLastLatency}, func(alive bool, networkType *dialer.NetworkType, isInit bool) {})
	defer group.Close()

	nt := &dialer.NetworkType{L4Proto: consts.L4ProtoStr_UDP, IpVersion: consts.IpVersionStr_4}
	d1.MustGetLatencies10(nt).AppendLatency(10 * time.Millisecond)
	group.MustGetAliveDialerSet(nt).NotifyLatencyChange(d1, true)
	d2.MustGetLatencies10(nt).AppendLatency(100 * time.Millisecond)
	group.MustGetAliveDialerSet(nt).NotifyLatencyChange(d2, true)

	// 1. Normal selection
	sel1, _, err := group.Select(nt, true)
	require.NoError(t, err)
	require.NotNil(t, sel1)

	// 2. Mark sel1 as zombie
	sel1.NotifyZombie()
	require.True(t, sel1.LastZombieAt() > 0)

	// 3. Selection should now strictly avoid sel1 even if no 'excluded' is passed
	for i := 0; i < 10; i++ {
		sel2, _, err := group.Select(nt, true)
		require.NoError(t, err)
		require.NotEqual(t, sel1.Property().Name, sel2.Property().Name, "Should NOT select zombied node within check_interval")
	}

	// 4. Test immediate exclusion override
	// If we pass d2 as excluded, it should fallback to d1 even if d1 is zombied (since d1 is still 'alive' by failCount)
	var other *dialer.Dialer
	if sel1 == d1 {
		other = d2
	} else {
		other = d1
	}

	sel3, _, err := group.SelectWithExclusion(nt, true, other)
	require.NoError(t, err)
	require.Equal(t, sel1.Property().Name, sel3.Property().Name, "Should fallback to zombied node if all others are excluded")

	// 5. Test Fixed policy: should NOT switch even if excluded
	fixedGroup := ob.NewDialerGroup(opts, "fixed-group", []*dialer.Dialer{d1, d2}, []*dialer.Annotation{{}, {}}, ob.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fixed, FixedIndex: 0}, func(alive bool, networkType *dialer.NetworkType, isInit bool) {})
	defer fixedGroup.Close()

	selFixed, _, err := fixedGroup.SelectWithExclusion(nt, true, d1)
	require.NoError(t, err)
	require.Equal(t, d1.Property().Name, selFixed.Property().Name, "Fixed policy should ignore 'excluded' and return the manually selected node")
}
