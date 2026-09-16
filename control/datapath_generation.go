/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"sync"
	"sync/atomic"
)

var (
	datapathGenerationCounter atomic.Uint32
	bpfDatapathGenerations    sync.Map // map[*bpfObjects]uint16
)

// nextDatapathGeneration returns a non-zero process-local token. A uint16 can
// only wrap after more fresh reloads than can occur during one live UDP flow.
func nextDatapathGeneration() uint16 {
	for {
		generation := uint16(datapathGenerationCounter.Add(1))
		if generation != 0 {
			return generation
		}
	}
}

func registerBpfDatapathGeneration(bpf *bpfObjects, generation uint16) {
	if bpf == nil || generation == 0 {
		return
	}
	bpfDatapathGenerations.Store(bpf, generation)
}

func bpfDatapathGeneration(bpf *bpfObjects) uint16 {
	if bpf == nil {
		return 0
	}
	value, ok := bpfDatapathGenerations.Load(bpf)
	if !ok {
		return 0
	}
	generation, _ := value.(uint16)
	return generation
}

func unregisterBpfDatapathGeneration(bpf *bpfObjects) {
	if bpf != nil {
		bpfDatapathGenerations.Delete(bpf)
	}
}
