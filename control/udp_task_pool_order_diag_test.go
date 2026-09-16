/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// This file is the diagnostic for issue #8. The sibling
// TestUdpTaskPoolPreservesPerFlowOrderAcrossOverflow fails intermittently
// under -race, and the two candidate explanations - "the assertion is too
// timing-sensitive" vs "the pool really does reorder one flow" - are told
// apart only by the queue's own tier timeline, not by opinion.
//
// The diagnostic therefore re-runs the same strict submission on a single
// flow, records every enqueue/pop with the tier it touched, and on the first
// ordering violation dumps that timeline. It runs one round per `-count`;
// reproduce with:
//
//	DAE_UDP_TASK_POOL_DIAG=1 go test -race \
//	  -run TestUdpTaskPoolOverflowOrderDiagnostic -count=200 ./control/
//
// The trace is armed only under that environment variable, so the default
// race job neither allocates nor records anything.
func TestUdpTaskPoolOverflowOrderDiagnostic(t *testing.T) {
	if os.Getenv("DAE_UDP_TASK_POOL_DIAG") == "" {
		t.Skip("set DAE_UDP_TASK_POOL_DIAG=1 to run the overflow-order diagnostic")
	}

	pool := NewUdpTaskPool()
	t.Cleanup(pool.Close)
	key := udpTaskPoolTestKey()
	trace := &udpTaskQueueTrace{}
	pool.trace.Store(trace)

	total := UdpTaskQueueLength + 64
	execOrder := make([]int, 0, total)
	// Serialize the recorder so appending cannot itself reorder observations.
	recorderMu := make(chan struct{}, 1)
	recorderMu <- struct{}{}
	done := make(chan struct{})

	for i := range total {
		index := i
		if !pool.EmitTask(key, &diagnosticTask{seq: index, run: func() {
			<-recorderMu
			execOrder = append(execOrder, index)
			if len(execOrder) == total {
				close(done)
			}
			recorderMu <- struct{}{}
		}}) {
			t.Fatalf("EmitTask rejected task %d", i)
		}
	}

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatalf("only %d of %d tasks executed", len(execOrder), total)
	}

	firstBad := -1
	for i := range total {
		if execOrder[i] != i {
			firstBad = i
			break
		}
	}
	if firstBad < 0 {
		return
	}
	t.Logf("first ordering violation at execution %d: expected task %d, executed task %d",
		firstBad, firstBad, execOrder[firstBad])
	head := min(len(execOrder), 40)
	t.Logf("first %d executions: %v", head, execOrder[:head])
	t.Logf("tier timeline:\n%s", trace.text(firstBad))
	if path := os.Getenv("DAE_UDP_TASK_POOL_DIAG_DUMP"); path != "" {
		if err := os.WriteFile(path, []byte(trace.dump(execOrder)), 0o600); err != nil {
			t.Logf("dump failed: %v", err)
		} else {
			t.Logf("dumped full timeline to %s", path)
		}
	}
	t.Fatalf("flow reordered: execution %d ran task %d, not task %d", firstBad, execOrder[firstBad], firstBad)
}

// diagnosticTask carries its submission index so the queue's tier timeline
// lines up with the execution order observed here.
type diagnosticTask struct {
	seq int
	run func()
}

func (d *diagnosticTask) Run() { d.run() }

func (d *diagnosticTask) traceSeq() int { return d.seq }

// text renders the timeline around the violating execution: enqueues and pops
// with the tier lengths observed before each operation.
func (tr *udpTaskQueueTrace) text(execIndex int) string {
	events := tr.snapshot()
	var b strings.Builder
	fmt.Fprintf(&b, "events=%d (seq = submission index; ch/ovf = tier lengths observed before the op)\n", len(events))
	// The violating execution is successful pop number execIndex+1.
	wantPop := execIndex + 1
	popSeen := 0
	lo := 0
	for i, e := range events {
		if strings.HasPrefix(e.op, "pop-") && e.op != "pop-none" {
			popSeen++
			if popSeen == wantPop {
				lo = max(i-24, 0)
				break
			}
		}
	}
	fmt.Fprintf(&b, "-- window ending at pop #%d (execution %d) --\n", wantPop, execIndex)
	for i := lo; i < len(events); i++ {
		e := events[i]
		fmt.Fprintf(&b, "%-8s seq=%-4d ch=%-4d ovf=%-4d overflowMode=%-5v poppedFromCh=%v\n",
			e.op, e.seq, e.chLen, e.ovfLen, e.overflowMode, e.poppedFromCh)
		if i-lo > 70 {
			fmt.Fprintf(&b, "... (%d more events)\n", len(events)-i)
			break
		}
	}
	return b.String()
}

// dump renders every recorded event plus the observed execution order, for
// offline analysis of a reproduction.
func (tr *udpTaskQueueTrace) dump(execOrder []int) string {
	var b strings.Builder
	events := tr.snapshot()
	fmt.Fprintf(&b, "exec_order %v\n", execOrder)
	for _, e := range events {
		fmt.Fprintf(&b, "%d %s seq=%d ch=%d ovf=%d overflowMode=%v poppedFromCh=%v\n",
			e.ord, e.op, e.seq, e.chLen, e.ovfLen, e.overflowMode, e.poppedFromCh)
	}
	return b.String()
}
