/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"sync"
	"sync/atomic"
)

type ConnMetricKey struct {
	Protocol string
	Group    string
}

func incrementConnectionTotal(counters *sync.Map, protocol string, group string) {
	if counters == nil || protocol == "" || group == "" {
		return
	}
	key := ConnMetricKey{
		Protocol: protocol,
		Group:    group,
	}

	if val, ok := counters.Load(key); ok {
		if counter, ok := val.(*atomic.Uint64); ok {
			counter.Add(1)
			return
		}
	}

	counter := new(atomic.Uint64)
	counter.Store(1)
	actual, loaded := counters.LoadOrStore(key, counter)
	if loaded {
		if existing, ok := actual.(*atomic.Uint64); ok {
			existing.Add(1)
		}
	}
}

func snapshotConnectionTotals(counters *sync.Map) map[ConnMetricKey]uint64 {
	snapshot := make(map[ConnMetricKey]uint64)
	if counters == nil {
		return snapshot
	}
	counters.Range(func(key, value interface{}) bool {
		metricKey, ok := key.(ConnMetricKey)
		if !ok {
			return true
		}
		counter, ok := value.(*atomic.Uint64)
		if !ok {
			return true
		}
		snapshot[metricKey] = counter.Load()
		return true
	})
	return snapshot
}

func (c *ControlPlane) AddTcpConnectionTotal(protocol string, group string) {
	incrementConnectionTotal(&c.tcpConnectionTotals, protocol, group)
}

func (c *ControlPlane) AddUdpConnectionTotal(protocol string, group string) {
	incrementConnectionTotal(&c.udpConnectionTotals, protocol, group)
}

func (c *ControlPlane) TcpConnectionTotalsSnapshot() map[ConnMetricKey]uint64 {
	return snapshotConnectionTotals(&c.tcpConnectionTotals)
}

func (c *ControlPlane) UdpConnectionTotalsSnapshot() map[ConnMetricKey]uint64 {
	return snapshotConnectionTotals(&c.udpConnectionTotals)
}
