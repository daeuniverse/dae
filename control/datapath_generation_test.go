/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"testing"

	"github.com/daeuniverse/dae/component"
	"github.com/sirupsen/logrus"
)

func newDatapathGenerationTestCore(bpf *bpfObjects, owned bool) *controlPlaneCore {
	ctx, cancel := context.WithCancel(context.Background())
	log := logrus.New()
	core := &controlPlaneCore{
		log:      log,
		closed:   ctx,
		close:    cancel,
		ifmgr:    component.NewInterfaceManager(log),
		bpfOwned: owned,
	}
	core.bpf.Store(bpf)
	return core
}

func TestDatapathGenerationSurvivesSharedBPFGenerationRetirement(t *testing.T) {
	bpf := &bpfObjects{}
	registerBpfDatapathGeneration(bpf, 37)
	t.Cleanup(func() { unregisterBpfDatapathGeneration(bpf) })

	previous := newDatapathGenerationTestCore(bpf, true)
	previous.datapathGeneration.Store(37)
	successor := newDatapathGenerationTestCore(nil, false)

	transferred := previous.EjectBpf()
	successor.InjectBpf(transferred)
	if err := previous.Close(); err != nil {
		t.Fatalf("previous Close() error = %v", err)
	}
	if got := bpfDatapathGeneration(bpf); got != 37 {
		t.Fatalf("shared BPF generation after previous retirement = %d, want 37", got)
	}
	if got := uint16(successor.datapathGeneration.Load()); got != 37 {
		t.Fatalf("successor datapath generation = %d, want 37", got)
	}

	_ = successor.EjectBpf()
	if err := successor.Close(); err != nil {
		t.Fatalf("successor Close() error = %v", err)
	}
}
