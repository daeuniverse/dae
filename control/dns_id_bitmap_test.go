/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIdBitmap_ConcurrentUniqueAllocation(t *testing.T) {
	alloc := newIdBitmap()
	const n = 512

	ids := make([]uint16, n)
	errCh := make(chan error, n)
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(n)

	for i := 0; i < n; i++ {
		i := i
		go func() {
			defer wg.Done()
			<-start
			id, err := alloc.Allocate()
			if err != nil {
				errCh <- err
				return
			}
			ids[i] = id
		}()
	}

	close(start)
	wg.Wait()
	close(errCh)

	for err := range errCh {
		require.NoError(t, err)
	}

	seen := make(map[uint16]struct{}, n)
	for _, id := range ids {
		if _, ok := seen[id]; ok {
			t.Fatalf("duplicate id allocated: %d", id)
		}
		seen[id] = struct{}{}
	}
	for _, id := range ids {
		alloc.Release(id)
	}
}

func TestIdBitmap_FullAndReuse(t *testing.T) {
	alloc := newIdBitmap()
	ids := make([]uint16, 0, 4096)

	for i := 0; i < 4096; i++ {
		id, err := alloc.Allocate()
		require.NoError(t, err)
		ids = append(ids, id)
	}

	_, err := alloc.Allocate()
	require.Error(t, err)

	alloc.Release(ids[0])
	_, err = alloc.Allocate()
	require.NoError(t, err)
}
