/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"testing"
	"unsafe"
)

// TestRoutingEpochBPFABI locks the Go side of the slot-carrying BPF ABI to
// the layouts in control/kern/tproxy.c. The generated bindings and the
// no-BPF stub intentionally expose the same field offsets.
func TestRoutingEpochBPFABI(t *testing.T) {
	if routingEpochSlotCount != 2 {
		t.Fatalf("routing epoch slot count = %d, want C ROUTING_EPOCH_SLOT_NUM 2", routingEpochSlotCount)
	}
	if bpfRoutingEpochSlotUnknown != 0 || bpfRoutingEpochSlot0Encoded != 1 || bpfRoutingEpochSlot1Encoded != 2 {
		t.Fatalf(
			"routing epoch slot encodings = (%d,%d,%d), want (0,1,2)",
			bpfRoutingEpochSlotUnknown,
			bpfRoutingEpochSlot0Encoded,
			bpfRoutingEpochSlot1Encoded,
		)
	}

	if got, want := unsafe.Sizeof(bpfRoutingResult{}), uintptr(36); got != want {
		t.Fatalf("sizeof(bpfRoutingResult) = %d, want %d", got, want)
	}
	if got, want := unsafe.Offsetof(bpfRoutingResult{}.RoutingEpochSlot), uintptr(33); got != want {
		t.Fatalf("bpfRoutingResult.RoutingEpochSlot offset = %d, want %d", got, want)
	}
	if got, want := unsafe.Offsetof(bpfRoutingResult{}.DatapathGeneration), uintptr(34); got != want {
		t.Fatalf("bpfRoutingResult.DatapathGeneration offset = %d, want %d", got, want)
	}

	if got, want := unsafe.Sizeof(bpfRoutingHandoffEntry{}), uintptr(48); got != want {
		t.Fatalf("sizeof(bpfRoutingHandoffEntry) = %d, want %d", got, want)
	}
	if got, want := unsafe.Offsetof(bpfRoutingHandoffEntry{}.Result), uintptr(8); got != want {
		t.Fatalf("bpfRoutingHandoffEntry.Result offset = %d, want %d", got, want)
	}

	if got, want := unsafe.Sizeof(bpfConnState{}), uintptr(56); got != want {
		t.Fatalf("sizeof(bpfConnState) = %d, want %d", got, want)
	}
	if got, want := unsafe.Offsetof(bpfConnState{}.RoutingEpochSlot), uintptr(52); got != want {
		t.Fatalf("bpfConnState.RoutingEpochSlot offset = %d, want %d", got, want)
	}
	if got, want := unsafe.Offsetof(bpfConnState{}.DatapathGeneration), uintptr(54); got != want {
		t.Fatalf("bpfConnState.DatapathGeneration offset = %d, want %d", got, want)
	}

	if got, want := unsafe.Offsetof(bpfDaeParam{}.DatapathGeneration), uintptr(26); got != want {
		t.Fatalf("bpfDaeParam.DatapathGeneration offset = %d, want %d", got, want)
	}

	if got, want := unsafe.Sizeof(bpfRoutingEpochIp{}), uintptr(20); got != want {
		t.Fatalf("sizeof(bpfRoutingEpochIp) = %d, want %d", got, want)
	}
	if got, want := unsafe.Offsetof(bpfRoutingEpochIp{}.Slot), uintptr(0); got != want {
		t.Fatalf("bpfRoutingEpochIp.Slot offset = %d, want %d", got, want)
	}
}
