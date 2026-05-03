/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

type packetSnifferFlowFamilyEntry struct {
	key     PacketSnifferKey
	sniffer *PacketSniffer
}

func (ref *packetSnifferFlowFamilyRef) snapshotMembers() []packetSnifferFlowFamilyEntry {
	if ref == nil {
		return nil
	}
	ref.mu.RLock()
	defer ref.mu.RUnlock()

	entries := make([]packetSnifferFlowFamilyEntry, 0, len(ref.members))
	for key, sniffer := range ref.members {
		entries = append(entries, packetSnifferFlowFamilyEntry{
			key:     key,
			sniffer: sniffer,
		})
	}
	return entries
}

func (p *PacketSnifferPool) retainFlowFamily(key PacketSnifferKey) {
	_ = p.retainFlowFamilyRef(key)
}
