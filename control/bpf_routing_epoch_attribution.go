/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

const (
	bpfRoutingEpochSlotUnknown uint8 = iota
	bpfRoutingEpochSlot0Encoded
	bpfRoutingEpochSlot1Encoded
)

// decodeBpfRoutingEpochSlot translates the BPF wire encoding to a routing
// epoch slot. Zero is deliberately unknown so an older pinned map cannot be
// mistaken for slot zero during a reload.
func decodeBpfRoutingEpochSlot(encoded uint8) (uint32, bool) {
	switch encoded {
	case bpfRoutingEpochSlot0Encoded:
		return 0, true
	case bpfRoutingEpochSlot1Encoded:
		return 1, true
	default:
		return 0, false
	}
}

func canonicalBpfRoutingEpochSlot(encoded uint8) uint8 {
	if _, ok := decodeBpfRoutingEpochSlot(encoded); !ok {
		return bpfRoutingEpochSlotUnknown
	}
	return encoded
}
