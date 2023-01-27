/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2023, mzz2017 <mzz@tuta.io>
 */

package dialer

import (
	"container/list"
	"sync"
	"time"
)

type LatenciesN struct {
	N              int
	LastNLatencies *list.List
	SumNLatencies  time.Duration

	mu sync.Mutex
}

func NewLatenciesN(n int) *LatenciesN {
	return &LatenciesN{
		N:              n,
		LastNLatencies: list.New(),
		SumNLatencies:  0,
	}
}

// AppendLatency appends a new latency to the back and keep the number in the list. Appending a fixed duration for
// failed or timeout situation is recommended.
//
// It is thread-safe.
func (ln *LatenciesN) AppendLatency(l time.Duration) {
	ln.mu.Lock()
	defer ln.mu.Unlock()
	if ln.LastNLatencies.Len() >= ln.N {
		ln.SumNLatencies -= ln.LastNLatencies.Front().Value.(time.Duration)
		ln.LastNLatencies.Remove(ln.LastNLatencies.Front())
	}
	ln.SumNLatencies += l
	ln.LastNLatencies.PushBack(l)
}

func (ln *LatenciesN) LastLatency() (time.Duration, bool) {
	ln.mu.Lock()
	defer ln.mu.Unlock()
	if ln.LastNLatencies.Len() == 0 {
		return 0, false
	}
	return ln.LastNLatencies.Back().Value.(time.Duration), true
}

func (ln *LatenciesN) AvgLatency() (time.Duration, bool) {
	ln.mu.Lock()
	defer ln.mu.Unlock()
	if ln.LastNLatencies.Len() == 0 {
		return 0, false
	}
	return ln.SumNLatencies / time.Duration(ln.LastNLatencies.Len()), true
}
