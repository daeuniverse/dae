/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"sync"
	"time"
)

type LatenciesN struct {
	N             int
	latencies     []time.Duration
	head          int
	SumNLatencies time.Duration

	mu sync.Mutex
}

func NewLatenciesN(n int) *LatenciesN {
	return &LatenciesN{
		N:         n,
		latencies: make([]time.Duration, 0, n),
	}
}

// AppendLatency appends a new latency to the back and keep the number in the list. Appending a fixed duration for
// failed or timeout situation is recommended.
//
// It is thread-safe.
func (ln *LatenciesN) AppendLatency(l time.Duration) {
	ln.mu.Lock()
	defer ln.mu.Unlock()

	if len(ln.latencies) >= ln.N {
		ln.SumNLatencies -= ln.latencies[ln.head]
		ln.latencies[ln.head] = l
		ln.head = (ln.head + 1) % ln.N
	} else {
		ln.latencies = append(ln.latencies, l)
	}
	ln.SumNLatencies += l
}

func (ln *LatenciesN) LastLatency() (time.Duration, bool) {
	ln.mu.Lock()
	defer ln.mu.Unlock()
	cnt := len(ln.latencies)
	if cnt == 0 {
		return 0, false
	}
	if cnt < ln.N {
		return ln.latencies[cnt-1], true
	}
	lastIdx := (ln.head + ln.N - 1) % ln.N
	return ln.latencies[lastIdx], true
}

func (ln *LatenciesN) AvgLatency() (time.Duration, bool) {
	ln.mu.Lock()
	defer ln.mu.Unlock()
	cnt := len(ln.latencies)
	if cnt == 0 {
		return 0, false
	}
	return ln.SumNLatencies / time.Duration(cnt), true
}

func (ln *LatenciesN) Len() int {
	ln.mu.Lock()
	defer ln.mu.Unlock()
	return len(ln.latencies)
}
