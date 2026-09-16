/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"strconv"
	"testing"
)

func TestRealDomainSetBoundedFIFO(t *testing.T) {
	rt := newControlPlaneRealDomainRuntime()
	if rt.realDomainSet == nil {
		t.Fatal("realDomainSet not initialized")
	}

	first := "first.example"
	last := "last.example"
	rt.muRealDomainSet.Lock()
	rt.rememberRealDomain(first)
	for i := range realDomainSetCapacity - 1 {
		rt.rememberRealDomain("d" + strconv.Itoa(i) + ".test")
	}
	if len(rt.realDomainSet) != realDomainSetCapacity {
		t.Fatalf("set size %d, want %d before overflow", len(rt.realDomainSet), realDomainSetCapacity)
	}
	rt.rememberRealDomain(first) // existing confirmation must not re-append
	rt.rememberRealDomain(last)
	rt.muRealDomainSet.Unlock()

	if len(rt.realDomainSet) > realDomainSetCapacity {
		t.Fatalf("set size %d exceeds capacity %d", len(rt.realDomainSet), realDomainSetCapacity)
	}
	if _, ok := rt.realDomainSet[first]; ok {
		t.Fatal("oldest confirmation was not FIFO-evicted")
	}
	if _, ok := rt.realDomainSet[last]; !ok {
		t.Fatal("newest confirmation missing after overflow")
	}
	if rt.realDomainOrd[0] == first {
		t.Fatal("FIFO order still starts at the evicted name")
	}
	if rt.realDomainOrd[len(rt.realDomainOrd)-1] != last {
		t.Fatalf("FIFO tail = %q, want %q", rt.realDomainOrd[len(rt.realDomainOrd)-1], last)
	}
}
