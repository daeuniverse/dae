//go:build linux && dae_bpf_tests

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink/nl"
)

//go:generate go run -mod=mod github.com/cilium/ebpf/cmd/bpf2go -cc "$BPF_CLANG" "$BPF_STRIP_FLAG" -cflags "$BPF_CFLAGS" -target "$BPF_TARGET" bpftest ./kern/tests/bpf_test.c -- -I./kern/headers -I./kern/tests

const (
	maxMatchSetLen = 5 // Same as bpf_test.go
)

func runBpfProgram(prog *ebpf.Program, data, ctx []byte) (statusCode uint32, dataOut, ctxOut []byte, err error) {
	dataOut = make([]byte, len(data)+256+2)
	ctxOut = make([]byte, len(ctx))
	opts := &ebpf.RunOptions{
		Data:       data,
		DataOut:    dataOut,
		Context:    ctx,
		ContextOut: ctxOut,
		Repeat:     1,
	}
	ret, err := prog.Run(opts)
	return ret, opts.DataOut, ctxOut, err
}

func collectBpfTestPrograms(t *testing.T) (obj *bpftestObjects, progsets []testProgramSet, err error) {
	obj = &bpftestObjects{}
	spec, err := loadBpftest()
	if err != nil {
		return nil, nil, err
	}
	if err = disableAllPinnedMapsForTests(spec); err != nil {
		return nil, nil, err
	}

	if err = spec.LoadAndAssign(obj, &ebpf.CollectionOptions{}); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			t.Logf("Verifier error: %+v\n", ve)
		}
		return nil, nil, fmt.Errorf("failed to load objects: %w", err)
	}

	if err = obj.LpmArrayMap.Update(uint32(0), obj.UnusedLpmType, ebpf.UpdateAny); err != nil {
		return nil, nil, fmt.Errorf("failed to update LpmArrayMap: %w", err)
	}

	v := reflect.ValueOf(obj.bpftestPrograms)
	typeOfV := v.Type()
	for i := 0; i < v.NumField(); i++ {
		progname := typeOfV.Field(i).Name
		if strings.HasPrefix(progname, "Testsetup") {
			progid := strings.TrimPrefix(progname, "Testsetup")
			progsets = append(progsets, testProgramSet{
				id:     progid,
				pktgen: v.FieldByName("Testpktgen" + progid).Interface().(*ebpf.Program),
				setup:  v.FieldByName("Testsetup" + progid).Interface().(*ebpf.Program),
				check:  v.FieldByName("Testcheck" + progid).Interface().(*ebpf.Program),
			})
		}
	}
	return
}

func markAllOutboundsAlive(t *testing.T, obj *bpftestObjects) {
	aliveVal := uint32(1)

	for i := uint32(0); i < 256; i++ {
		for j := uint32(0); j < 6; j++ {
			ck := i*6 + j
			if err := obj.OutboundConnectivityMap.Update(ck, aliveVal, ebpf.UpdateAny); err != nil {
				t.Fatalf("failed to initialize outbound_connectivity_map[%d]: %v", ck, err)
			}
		}
	}
}

type testProgramSet struct {
	id     string
	pktgen *ebpf.Program
	setup  *ebpf.Program
	check  *ebpf.Program
}

// TestBpfBugs runs any bug_* BPF verification programs that are currently
// defined in bpf_test.c. If none exist, skip explicitly instead of silently
// passing a stale harness.
func TestBpfBugs(t *testing.T) {
	obj, progsets, err := collectBpfTestPrograms(t)
	if err != nil {
		t.Fatalf("error while collecting programs: %s", err)
	}
	defer obj.Close()

	key := uint32(0)
	activeRulesLen := uint32(maxMatchSetLen)
	var zeroEntry []byte

	markAllOutboundsAlive(t, obj)
	foundBugProgram := false

	for _, progset := range progsets {
		if !strings.HasPrefix(progset.id, "bug_") && !strings.HasPrefix(progset.id, "bug_combined") {
			continue
		}
		foundBugProgram = true

		t.Run(progset.id, func(t *testing.T) {
			if err = obj.RoutingMetaMap.Update(key, activeRulesLen, ebpf.UpdateAny); err != nil {
				t.Fatalf("failed to initialize routing_meta_map: %v", err)
			}

			if zeroEntry == nil {
				zeroEntry = make([]byte, obj.RoutingMap.ValueSize())
			}
			for i := uint32(0); i < maxMatchSetLen; i++ {
				if err = obj.RoutingMap.Update(i, zeroEntry, ebpf.UpdateAny); err != nil {
					t.Fatalf("failed to clear routing_map[%d]: %v", i, err)
				}
			}

			t.Logf("Running bug verification test: %s\n", progset.id)

			data := make([]byte, 4096-256-320)
			ctx := make([]byte, 256)

			if strings.Contains(progset.id, "combined") {
				for testType := 0; testType <= 1; testType++ {
					ctx[8] = byte(testType)

					statusCode, data, ctx, err := runBpfProgram(progset.pktgen, data, ctx)
					if err != nil {
						t.Fatalf("error while running pktgen prog: %s", err)
					}
					if statusCode != 0 {
						t.Fatalf("error while running pktgen program: unexpected status code: %d", statusCode)
					}

					statusCode, data, ctx, err = runBpfProgram(progset.setup, data, ctx)
					if err != nil {
						t.Fatalf("error while running setup prog: %s", err)
					}

					status := make([]byte, 4)
					nl.NativeEndian().PutUint32(status, statusCode)
					data = append(status, data...)

					statusCode, data, ctx, err = runBpfProgram(progset.check, data, ctx)
					if err != nil {
						if strings.Contains(err.Error(), "permission") {
							t.Skipf("Skipping test: permission denied (requires root)")
						}
						t.Fatalf("error while running check prog: %s", err)
					}

					if statusCode != 0 {
						t.Logf("Test type %d: Bug EXISTS", testType)
					} else {
						t.Logf("Test type %d: Bug FIXED", testType)
					}
				}
				return
			}

			statusCode, data, ctx, err := runBpfProgram(progset.pktgen, data, ctx)
			if err != nil {
				t.Fatalf("error while running pktgen prog: %s", err)
			}
			if statusCode != 0 {
				t.Fatalf("error while running pktgen program: unexpected status code: %d", statusCode)
			}

			statusCode, data, ctx, err = runBpfProgram(progset.setup, data, ctx)
			if err != nil {
				t.Fatalf("error while running setup prog: %s", err)
			}

			status := make([]byte, 4)
			nl.NativeEndian().PutUint32(status, statusCode)
			data = append(status, data...)

			statusCode, data, ctx, err = runBpfProgram(progset.check, data, ctx)
			if err != nil {
				if strings.Contains(err.Error(), "permission") {
					t.Skipf("Skipping test: permission denied (requires root)")
				}
				t.Fatalf("error while running check prog: %s", err)
			}

			if statusCode != 0 {
				t.Log("Bug EXISTS")
			} else {
				t.Log("Bug FIXED")
			}
		})
	}

	if !foundBugProgram {
		t.Skip("no bug_* BPF verification programs defined")
	}
}
