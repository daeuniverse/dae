//go:build !dae_stub_ebpf

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	stderrors "errors"
	"reflect"
	"slices"
	"testing"

	"github.com/cilium/ebpf"
)

func TestBatchDeleteIgnoringMissingResumesSuffix(t *testing.T) {
	keys := []uint32{1, 2, 3}
	present := map[uint32]bool{1: true, 3: true}
	var calls [][]uint32

	deleted, err := batchDeleteIgnoringMissing(reflect.ValueOf(keys), func(raw any) (int, error) {
		suffix := slices.Clone(raw.([]uint32))
		calls = append(calls, suffix)
		for i, key := range suffix {
			if !present[key] {
				return i, ebpf.ErrKeyNotExist
			}
			delete(present, key)
		}
		return len(suffix), nil
	})
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if deleted != 2 {
		t.Fatalf("deleted=%d, want 2", deleted)
	}
	if present[1] || present[3] {
		t.Fatalf("processed suffix was left behind: %v", present)
	}
	wantCalls := [][]uint32{{1, 2, 3}, {3}}
	if !reflect.DeepEqual(calls, wantCalls) {
		t.Fatalf("calls=%v, want %v", calls, wantCalls)
	}
}

func TestBpfMapBatchDeleteRealMapResumesAfterMissingKey(t *testing.T) {
	m := newJanitorTestMap(t, "cookie_pid_map")
	for _, key := range []uint64{1, 3} {
		if err := m.Put(key, bpfPidPname{}); err != nil {
			t.Fatalf("put key %d: %v", key, err)
		}
	}

	deleted, err := BpfMapBatchDelete(m, []uint64{1, 2, 3})
	if err != nil {
		t.Fatalf("batch delete: %v", err)
	}
	if deleted != 2 {
		t.Fatalf("deleted=%d, want 2", deleted)
	}
	for _, key := range []uint64{1, 3} {
		var value bpfPidPname
		if err := m.Lookup(key, &value); !stderrors.Is(err, ebpf.ErrKeyNotExist) {
			t.Fatalf("lookup key %d after delete: %v, want %v", key, err, ebpf.ErrKeyNotExist)
		}
	}
}

func TestBatchDeleteIgnoringMissingAllAbsent(t *testing.T) {
	keys := []uint32{1, 2, 3}
	calls := 0
	deleted, err := batchDeleteIgnoringMissing(reflect.ValueOf(keys), func(raw any) (int, error) {
		calls++
		return 0, ebpf.ErrKeyNotExist
	})
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if deleted != 0 || calls != len(keys) {
		t.Fatalf("deleted=%d calls=%d, want 0/%d", deleted, calls, len(keys))
	}
}

func TestBatchDeleteIgnoringMissingPreservesPartialCountOnError(t *testing.T) {
	keys := []uint32{1, 2, 3}
	wantErr := stderrors.New("batch transport failed")
	deleted, err := batchDeleteIgnoringMissing(reflect.ValueOf(keys), func(raw any) (int, error) {
		return 1, wantErr
	})
	if deleted != 1 || !stderrors.Is(err, wantErr) {
		t.Fatalf("deleted=%d err=%v, want 1/%v", deleted, err, wantErr)
	}
}

func TestBatchDeleteIgnoringMissingRejectsSilentPartialProgress(t *testing.T) {
	keys := []uint32{1, 2, 3}
	deleted, err := batchDeleteIgnoringMissing(reflect.ValueOf(keys), func(raw any) (int, error) {
		return 0, nil
	})
	if deleted != 0 || err == nil {
		t.Fatalf("deleted=%d err=%v, want a no-progress error", deleted, err)
	}
}
