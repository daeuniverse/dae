/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package nativeapi

import (
	"testing"
	"time"
)

func TestOperationStoreReplayBeforeSideEffects(t *testing.T) {
	store := NewOperationStore(time.Hour, 8)
	accepted, replayed, err := store.Accept(OperationKindReload, "source\x00sha", "key")
	if err != nil || replayed {
		t.Fatalf("accept: accepted=%#v replayed=%v err=%v", accepted, replayed, err)
	}
	// A reserved key is still being admitted; a second request must not get a
	// replay body for work the first may never queue.
	if _, replayed, err := store.Replay(OperationKindReload, "source\x00sha", "key"); err == nil || replayed {
		t.Fatalf("reserved key replay = %v, %v; want a conflict", replayed, err)
	}
	store.CommitReplayKey("key")
	previous, replayed, err := store.Replay(OperationKindReload, "source\x00sha", "key")
	if err != nil || !replayed || previous.OperationID != accepted.OperationID {
		t.Fatalf("replay = %#v, %v, %v; want %s", previous, replayed, err, accepted.OperationID)
	}
	if _, replayed, err := store.Replay(OperationKindReload, "other", "key"); err == nil || replayed {
		t.Fatalf("mismatched replay = %v, %v; want a conflict", replayed, err)
	}
}

func TestOperationStoreBoundsRetainedRecords(t *testing.T) {
	store := NewOperationStore(time.Hour, 8)
	for i := 0; i < MaxOperationRecords+64; i++ {
		accepted, _, err := store.Accept(OperationKindReload, "scope", "")
		if err != nil {
			t.Fatal(err)
		}
		store.Fail(accepted.OperationID, &SafeError{Code: "test", Message: "done"})
	}
	store.pruneLocked()
	if got := len(store.operations); got > MaxOperationRecords {
		t.Fatalf("retained operations = %d, want <= %d", got, MaxOperationRecords)
	}
}
