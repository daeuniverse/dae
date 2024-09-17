/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2024, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"testing"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/stretchr/testify/require"
)

func TestUdpEndpointPool(t *testing.T) {
	isTest = true
	c, err := cpu.Times(false)
	require.NoError(t, err)
	t.Log(c)
	DefaultNatTimeout = 1000 * time.Microsecond
	for i := 0; i < 100; i++ {
		DefaultUdpTaskPool.EmitTask("testkey", func() {
		})
		time.Sleep(99 * time.Microsecond)
	}
	time.Sleep(5 * time.Second)
	c, err = cpu.Times(false)
	require.NoError(t, err)
	t.Log(c)
}
