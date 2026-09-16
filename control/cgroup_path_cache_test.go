//go:build !dae_stub_ebpf

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"sync"
	"testing"
)

func TestDetectCgroupPathCaching(t *testing.T) {
	const concurrency = 16
	var wg sync.WaitGroup
	paths := make([]string, concurrency)
	errs := make([]error, concurrency)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			paths[idx], errs[idx] = detectCgroupPath()
		}(i)
	}
	wg.Wait()

	basePath, baseErr := paths[0], errs[0]
	for i := 1; i < concurrency; i++ {
		if paths[i] != basePath {
			t.Errorf("path[%d] = %q, want %q", i, paths[i], basePath)
		}
		if (errs[i] == nil) != (baseErr == nil) {
			t.Errorf("err[%d] = %v, want %v", i, errs[i], baseErr)
		}
	}
}
