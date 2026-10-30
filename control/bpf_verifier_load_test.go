//go:build !dae_stub_ebpf

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

var verifierProcessedInsns = regexp.MustCompile(`processed \d+ insns \(limit \d+\)`)

// TestProductionProgramsLoad loads every program of the production object once
// for each combination of the .rodata switches that change which code the
// verifier walks. It checks that the verifier accepts each program, not a
// particular processed-instruction count, because that count moves with the
// clang and kernel versions; the counts are logged so growth stays visible.
func TestProductionProgramsLoad(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("loading BPF programs requires root")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("remove memlock limit: %v", err)
	}
	for _, redirectPeer := range []uint8{0, 1} {
		for _, currentTask := range []uint8{0, 1} {
			name := fmt.Sprintf("redirect_peer=%d,current_task=%d", redirectPeer, currentTask)
			t.Run(name, func(t *testing.T) {
				loadProductionProgramsForTest(t, redirectPeer, currentTask)
			})
		}
	}
}

func loadProductionProgramsForTest(t *testing.T, useRedirectPeer, hasBpfGetCurrentTask uint8) {
	t.Helper()
	spec, err := loadBpf()
	if err != nil {
		t.Fatalf("load spec: %v", err)
	}
	for _, m := range spec.Maps {
		m.Pinning = ebpf.PinNone
	}
	param := struct {
		tproxyPort           uint32
		controlPlanePid      uint32
		dae0Ifindex          uint32
		daeNetnsId           uint32
		dae0peerMac          [6]byte
		paddingAfterMac      [2]uint8
		useRedirectPeer      uint8
		hasBpfGetCurrentTask uint8
		datapathGeneration   uint16
		daeSocketMark        uint32
	}{
		useRedirectPeer:      useRedirectPeer,
		hasBpfGetCurrentTask: hasBpfGetCurrentTask,
	}
	if err := spec.Variables["PARAM"].Set(param); err != nil {
		t.Fatalf("set PARAM: %v", err)
	}
	if err := spec.Variables["EVENT_RATE"].Set(eventRateValue()); err != nil {
		t.Fatalf("set EVENT_RATE: %v", err)
	}
	if err := tuneEventRateMap(spec); err != nil {
		t.Fatalf("tune event rate map: %v", err)
	}

	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{LogLevel: ebpf.LogLevelStats},
	})
	if err != nil {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			t.Fatalf("load programs: %+v", verr)
		}
		t.Fatalf("load programs: %v", err)
	}
	defer coll.Close()

	names := make([]string, 0, len(coll.Programs))
	for name := range coll.Programs {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		t.Logf("%s: %s", name, verifierProcessedInsns.FindString(coll.Programs[name].VerifierLog))
	}
}
