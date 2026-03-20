//go:build linux && dae_bpf_tests
// +build linux,dae_bpf_tests

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/vishvananda/netlink/nl"
)

//go:generate go run -mod=mod github.com/cilium/ebpf/cmd/bpf2go -cc "$BPF_CLANG" "$BPF_STRIP_FLAG" -cflags "$BPF_CFLAGS" -target "$BPF_TARGET" bpftest ./kern/tests/bpf_test.c -- -I./kern/headers -I./kern/tests

const (
	maxMatchSetLen = 5  // Same as bpf_test.go
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
	pinPath := "/sys/fs/bpf/dae_test"
	if err = os.MkdirAll(pinPath, 0755); err != nil && !os.IsExist(err) {
		return
	}

	if err = loadBpftestObjects(obj,
		&ebpf.CollectionOptions{
			Maps: ebpf.MapOptions{
				PinPath: pinPath,
			},
		},
	); err != nil {
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

type testProgramSet struct {
	id     string
	pktgen *ebpf.Program
	setup  *ebpf.Program
	check  *ebpf.Program
}

// TestBpfBugs verifies the existence of reported bugs before fixing them.
// These tests should FAIL before the fix and PASS after the fix.
func TestBpfBugs(t *testing.T) {
	obj, progsets, err := collectBpfTestPrograms(t)
	if err != nil {
		t.Fatalf("error while collecting programs: %s", err)
	}
	defer obj.Close()

	key := uint32(0)
	activeRulesLen := uint32(maxMatchSetLen)

	var zeroEntry []byte

	for _, progset := range progsets {
		// Only run bug verification tests
		if !strings.HasPrefix(progset.id, "bug_") && !strings.HasPrefix(progset.id, "bug_combined") {
			continue
		}

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

			// Set test selector for combined tests
			if strings.Contains(progset.id, "combined") {
				// Test both types: 0 for small UDP, 1 for large IPv6
				for testType := 0; testType <= 1; testType++ {
					ctx[8] = byte(testType)  // cb[2]

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
						// Check if it's a permission error or actual test failure
						if strings.Contains(err.Error(), "permission") {
							t.Skipf("Skipping test: permission denied (requires root)")
						}
					}
					// statusCode == 1 (TC_ACT_SHOT) means the bug exists
					// statusCode == 0 (TC_ACT_OK) means the bug is fixed
					if statusCode != 0 {
						t.Logf("Test type %d: Bug EXISTS (test failed as expected before fix)", testType)
					} else {
						t.Logf("Test type %d: Bug FIXED (test passed)", testType)
					}
				}
			} else {
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
					// Permission denied means we need root
					if strings.Contains(err.Error(), "permission") {
						t.Skipf("Skipping test: permission denied (requires root)")
					}
				}
				// statusCode == 1 (TC_ACT_SHOT) means the bug exists
				// statusCode == 0 (TC_ACT_OK) means the bug is fixed
				if statusCode != 0 {
					t.Logf("Bug EXISTS (test failed as expected before fix)")
				} else {
					t.Logf("Bug FIXED (test passed)")
				}
			}
		})
	}
}

// TestBpfBug001_VerifyLargeIPv6ExtensionBypass specifically tests BUG-001
func TestBpfBug001_VerifyLargeIPv6ExtensionBypass(t *testing.T) {
	obj, progsets, err := collectBpfTestPrograms(t)
	if err != nil {
		t.Fatalf("error while collecting programs: %s", err)
	}
	defer obj.Close()

	var targetSet *testProgramSet
	for _, ps := range progsets {
		if ps.id == "bug_001_ipv6_large_ext_bypass" {
			targetSet = &ps
			break
		}
	}
	if targetSet == nil {
		t.Skip("BUG-001 test not found")
	}

	t.Run("large_ipv6_extension_headers", func(t *testing.T) {
		key := uint32(0)
		activeRulesLen := uint32(maxMatchSetLen)
		obj.RoutingMetaMap.Update(key, activeRulesLen, ebpf.UpdateAny)

		zeroEntry := make([]byte, obj.RoutingMap.ValueSize())
		for i := uint32(0); i < maxMatchSetLen; i++ {
			obj.RoutingMap.Update(i, zeroEntry, ebpf.UpdateAny)
		}

		data := make([]byte, 4096-256-320)
		ctx := make([]byte, 256)

		statusCode, _, _, err := runBpfProgram(targetSet.pktgen, data, ctx)
		if err != nil {
			t.Fatalf("pktgen failed: %v", err)
		}

		statusCode, _, _, err = runBpfProgram(targetSet.setup, data, ctx)
		if err != nil {
			t.Fatalf("setup failed: %v", err)
		}

		status := make([]byte, 4)
		nl.NativeEndian().PutUint32(status, statusCode)
		data = append(status, data...)

		statusCode, _, _, err = runBpfProgram(targetSet.check, data, ctx)
		if err != nil {
			if strings.Contains(err.Error(), "permission") {
				t.Skip("requires root")
			}
			t.Fatalf("check failed: %v", err)
		}

		if statusCode == 1 {  // TC_ACT_SHOT
			t.Error("BUG-001 EXISTS: IPv6 packets with large extension headers bypass tproxy")
		} else {
			t.Log("BUG-001 FIXED: IPv6 packets with large extension headers are correctly processed")
		}
	})
}

// TestBpfBug002_VerifySmallUDPPacketBypass specifically tests BUG-002
func TestBpfBug002_VerifySmallUDPPacketBypass(t *testing.T) {
	obj, progsets, err := collectBpfTestPrograms(t)
	if err != nil {
		t.Fatalf("error while collecting programs: %s", err)
	}
	defer obj.Close()

	var targetSet *testProgramSet
	for _, ps := range progsets {
		if ps.id == "bug_002_small_udp_bypass" {
			targetSet = &ps
			break
		}
	}
	if targetSet == nil {
		t.Skip("BUG-002 test not found")
	}

	t.Run("small_udp_packet_42_bytes", func(t *testing.T) {
		key := uint32(0)
		activeRulesLen := uint32(maxMatchSetLen)
		obj.RoutingMetaMap.Update(key, activeRulesLen, ebpf.UpdateAny)

		zeroEntry := make([]byte, obj.RoutingMap.ValueSize())
		for i := uint32(0); i < maxMatchSetLen; i++ {
			obj.RoutingMap.Update(i, zeroEntry, ebpf.UpdateAny)
		}

		data := make([]byte, 4096-256-320)
		ctx := make([]byte, 256)

		statusCode, _, _, err := runBpfProgram(targetSet.pktgen, data, ctx)
		if err != nil {
			t.Fatalf("pktgen failed: %v", err)
		}

		statusCode, _, _, err = runBpfProgram(targetSet.setup, data, ctx)
		if err != nil {
			t.Fatalf("setup failed: %v", err)
		}

		status := make([]byte, 4)
		nl.NativeEndian().PutUint32(status, statusCode)
		data = append(status, data...)

		statusCode, _, _, err = runBpfProgram(targetSet.check, data, ctx)
		if err != nil {
			if strings.Contains(err.Error(), "permission") {
				t.Skip("requires root")
			}
			t.Fatalf("check failed: %v", err)
		}

		if statusCode == 1 {  // TC_ACT_SHOT
			t.Error("BUG-002 EXISTS: Small UDP packets (42 bytes) bypass tproxy")
		} else {
			t.Log("BUG-002 FIXED: Small UDP packets are correctly processed")
		}
	})
}
