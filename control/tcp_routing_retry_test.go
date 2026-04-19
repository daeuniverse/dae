/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	stderrors "errors"
	"testing"
	"time"

	"github.com/cilium/ebpf"
)

func TestRetryRetrieveRoutingResult_RetriesTransientMiss(t *testing.T) {
	t.Helper()

	want := &bpfRoutingResult{Dscp: 46, Outbound: 7}
	calls := 0

	got, err := retryRetrieveRoutingResult(context.Background(), func() (*bpfRoutingResult, error) {
		calls++
		if calls < 3 {
			return nil, ebpf.ErrKeyNotExist
		}
		return want, nil
	}, 3, 0)
	if err != nil {
		t.Fatalf("retryRetrieveRoutingResult() error = %v", err)
	}
	if got == nil {
		t.Fatal("retryRetrieveRoutingResult() = nil, want routing result")
		return
	}
	if *got != *want {
		t.Fatalf("retryRetrieveRoutingResult() = %+v, want %+v", *got, *want)
	}
	if calls != 3 {
		t.Fatalf("retryRetrieveRoutingResult() calls = %d, want 3", calls)
	}
}

func TestRetryRetrieveRoutingResult_StopsOnNonRetryableError(t *testing.T) {
	t.Helper()

	wantErr := stderrors.New("boom")
	calls := 0

	got, err := retryRetrieveRoutingResult(context.Background(), func() (*bpfRoutingResult, error) {
		calls++
		return nil, wantErr
	}, 3, 0)
	if !stderrors.Is(err, wantErr) {
		t.Fatalf("retryRetrieveRoutingResult() error = %v, want %v", err, wantErr)
	}
	if got != nil {
		t.Fatalf("retryRetrieveRoutingResult() = %+v, want nil", *got)
		return
	}
	if calls != 1 {
		t.Fatalf("retryRetrieveRoutingResult() calls = %d, want 1", calls)
	}
}

func TestRetryRetrieveRoutingResult_RespectsContextCancellation(t *testing.T) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0

	got, err := retryRetrieveRoutingResult(ctx, func() (*bpfRoutingResult, error) {
		calls++
		return nil, ebpf.ErrKeyNotExist
	}, 3, time.Second)
	if !stderrors.Is(err, context.Canceled) {
		t.Fatalf("retryRetrieveRoutingResult() error = %v, want %v", err, context.Canceled)
	}
	if got != nil {
		t.Fatalf("retryRetrieveRoutingResult() = %+v, want nil", *got)
		return
	}
	if calls != 1 {
		t.Fatalf("retryRetrieveRoutingResult() calls = %d, want 1", calls)
	}
}
