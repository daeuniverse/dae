//go:build linux && dae_bpf_tests
// +build linux,dae_bpf_tests

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package tests

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink/nl"
)

//go:generate go run -mod=mod github.com/cilium/ebpf/cmd/bpf2go -cc "$BPF_CLANG" "$BPF_STRIP_FLAG" -cflags "$BPF_CFLAGS" -target "$BPF_TARGET" bpftest ./bpf_test.c -- -I../headers -I.

type programSet struct {
	id     string
	pktgen *ebpf.Program
	setup  *ebpf.Program
	check  *ebpf.Program
}

const maxMatchSetLen = 32 * 32

// testMaxMatchSetLen is the number of routing_map slots the routing engine
// should iterate during BPF unit tests.  The most rule-intensive test
// (and_match_1) uses 5 slots (indices 0–4).  Using maxMatchSetLen (1024) here
// causes the engine to iterate over 1019+ zero-initialized entries after the
// real rules; each zeroed entry has MatchType_DomainSet (= 0), triggering a
// domain-routing-map lookup per iteration.  For tests whose fallback uses
// must=false (e.g. IpsetMatch), the engine never exits the loop early and the
// 1022 extra domain lookups cause the test to run for multiple minutes.
const testMaxMatchSetLen = 5

func runBpfProgram(prog *ebpf.Program, data, ctx []byte) (statusCode uint32, dataOut, ctxOut []byte, err error) {
	dataOut = make([]byte, len(data))
	if len(dataOut) > 0 {
		// See comments at https://github.com/cilium/ebpf/blob/20c4d8896bdde990ce6b80d59a4262aa3ccb891d/prog.go#L563-L567
		dataOut = make([]byte, len(data)+256+2)
	}
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

func collectPrograms(t *testing.T) (obj *bpftestObjects, progset []programSet, err error) {
	obj = &bpftestObjects{}
	pinPath := "/sys/fs/bpf/dae"
	if err = os.MkdirAll(pinPath, 0755); err != nil && !os.IsExist(err) {
		return
	}

	if err = loadBpftestObjects(obj,
		&ebpf.CollectionOptions{
			Maps: ebpf.MapOptions{
				PinPath: pinPath,
			},
			Programs: ebpf.ProgramOptions{},
		},
	); err != nil {
		var (
			ve          *ebpf.VerifierError
			verifierLog string
		)
		if errors.As(err, &ve) {
			verifierLog = fmt.Sprintf("Verifier error: %+v\n", ve)
		}

		t.Fatalf("Failed to load objects: %s\n%+v", verifierLog, err)

		return nil, nil, err
	}

	if err = obj.LpmArrayMap.Update(uint32(0), obj.UnusedLpmType, ebpf.UpdateAny); err != nil {
		t.Fatalf("Failed to update LpmArrayMap: %s", err)
		return
	}

	v := reflect.ValueOf(obj.bpftestPrograms)
	typeOfV := v.Type()
	for i := 0; i < v.NumField(); i++ {
		progname := typeOfV.Field(i).Name
		if strings.HasPrefix(progname, "Testsetup") {
			progid := strings.TrimPrefix(progname, "Testsetup")
			progset = append(progset, programSet{
				id:     progid,
				pktgen: v.FieldByName("Testpktgen" + progid).Interface().(*ebpf.Program),
				setup:  v.FieldByName("Testsetup" + progid).Interface().(*ebpf.Program),
				check:  v.FieldByName("Testcheck" + progid).Interface().(*ebpf.Program),
			})
		}
	}
	return
}

func consumeBpfDebugLog(t *testing.T) {
	readBpfDebugLog(t)
}

func printBpfDebugLog(t *testing.T) {
	fmt.Print(readBpfDebugLog(t))
}

func readBpfDebugLog(t *testing.T) string {
	fd, err := syscall.Open("/sys/kernel/tracing/trace_pipe", syscall.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatalf("Failed to open trace_pipe: %v", err)
	}
	defer syscall.Close(fd)

	buffer := make([]byte, 1024*64)
	var logs strings.Builder

	for {
		n, err := syscall.Read(fd, buffer)
		if err != nil {
			if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
				break
			}
			t.Fatalf("Failed to read from trace_pipe: %v", err)
		}
		if n == 0 {
			break
		}
		logs.Write(buffer[:n])
	}

	return logs.String()
}

// TestBpfBugsVerification runs bug verification tests and reports which bugs exist.
// Unlike the main Test() function, this function continues running all tests
// even if some bugs are detected, providing a complete report.
func TestBpfBugsVerification(t *testing.T) {
	obj, progsets, err := collectPrograms(t)
	if err != nil {
		t.Fatalf("error while collecting programs: %s", err)
	}
	defer obj.Close()

	key := uint32(0)
	activeRulesLen := uint32(testMaxMatchSetLen)
	var zeroEntry []byte

	// Track bug detection results
	bugResults := make(map[string]bool)

	for _, progset := range progsets {
		// Only run bug verification tests
		if !strings.HasPrefix(strings.ToLower(progset.id), "bug_") &&
			!strings.HasPrefix(strings.ToLower(progset.id), "bugcombined") {
			continue
		}

		if err = obj.RoutingMetaMap.Update(key, activeRulesLen, ebpf.UpdateAny); err != nil {
			t.Fatalf("failed to initialize routing_meta_map: %v", err)
		}

		if zeroEntry == nil {
			zeroEntry = make([]byte, obj.RoutingMap.ValueSize())
		}
		for i := uint32(0); i < testMaxMatchSetLen; i++ {
			if err = obj.RoutingMap.Update(i, zeroEntry, ebpf.UpdateAny); err != nil {
				t.Fatalf("failed to clear routing_map[%d]: %v", i, err)
			}
		}

		t.Logf("Running bug verification: %s\n", progset.id)

		data := make([]byte, 4096-256-320)
		ctx := make([]byte, 256)

		statusCode, data, ctx, err := runBpfProgram(progset.pktgen, data, ctx)
		if err != nil {
			t.Logf("  [%s] pktgen error: %s", progset.id, err)
			bugResults[progset.id] = true // Assume bug exists on error
			continue
		}
		if statusCode != 0 {
			t.Logf("  [%s] pktgen unexpected status: %d", progset.id, statusCode)
			bugResults[progset.id] = true
			continue
		}

		statusCode, data, ctx, err = runBpfProgram(progset.setup, data, ctx)
		if err != nil {
			t.Logf("  [%s] setup error: %s", progset.id, err)
			bugResults[progset.id] = true
			continue
		}

		status := make([]byte, 4)
		nl.NativeEndian().PutUint32(status, statusCode)
		data = append(status, data...)

		statusCode, data, ctx, err = runBpfProgram(progset.check, data, ctx)
		if err != nil {
			t.Logf("  [%s] check error: %s", progset.id, err)
			bugResults[progset.id] = true
			continue
		}

		// statusCode == 1 (TC_ACT_SHOT) means bug EXISTS
		// statusCode == 0 (TC_ACT_OK) means bug is FIXED
		bugExists := (statusCode != 0)
		bugResults[progset.id] = bugExists

		// Log the actual status code for debugging
		t.Logf("  [%s] statusCode=%d, data_len=%d", progset.id, statusCode, len(data))

		// Print BPF debug logs if any
		debugLog := readBpfDebugLog(t)
		if debugLog != "" {
			t.Logf("  [%s] BPF debug:\n%s", progset.id, debugLog)
		}

		if bugExists {
			t.Logf("  [%s] BUG DETECTED (packet bypassed tproxy)", progset.id)
		} else {
			t.Logf("  [%s] OK (bug is fixed)", progset.id)
		}

		consumeBpfDebugLog(t)
	}

	// Print summary
	t.Log("\n=== BUG VERIFICATION SUMMARY ===")
	bugCount := 0
	for id, exists := range bugResults {
		if exists {
			bugCount++
			t.Logf("  [X] %s: BUG EXISTS", id)
		} else {
			t.Logf("  [✓] %s: FIXED", id)
		}
	}
	t.Logf("Total bugs detected: %d/%d", bugCount, len(bugResults))

	// Don't fail the test - this is informational
}

func Test(t *testing.T) {
	obj, progsets, err := collectPrograms(t)
	if err != nil {
		t.Fatalf("error while collecting programs: %s", err)
	}

	key := uint32(0)
	activeRulesLen := uint32(testMaxMatchSetLen)

	// zeroEntry is used to clear routing_map slots between tests.
	// Stale entries from a previous test (e.g. and_match writes to slots 0–4)
	// would corrupt later tests that only write slots 0–1 if not cleared.
	// We lazily initialise the slice from the map's actual value-size so there
	// is no hard-coded dependency on the C struct layout.
	var zeroEntry []byte

	for _, progset := range progsets {
		if err = obj.RoutingMetaMap.Update(key, activeRulesLen, ebpf.UpdateAny); err != nil {
			t.Fatalf("failed to initialize routing_meta_map: %v", err)
		}

		// Zero routing_map[0..testMaxMatchSetLen-1] before running the test so
		// leftover data from the previous test cannot affect this one.
		if zeroEntry == nil {
			zeroEntry = make([]byte, obj.RoutingMap.ValueSize())
		}
		for i := uint32(0); i < testMaxMatchSetLen; i++ {
			if err = obj.RoutingMap.Update(i, zeroEntry, ebpf.UpdateAny); err != nil {
				t.Fatalf("failed to clear routing_map[%d]: %v", i, err)
			}
		}

		t.Logf("Running test: %s\n", progset.id)
		// create ctx with the max allowed size(4k - head room - tailroom)
		data := make([]byte, 4096-256-320)

		// sizeof(struct __sk_buff) < 256, let's make it 256
		ctx := make([]byte, 256)

		statusCode, data, ctx, err := runBpfProgram(progset.pktgen, data, ctx)
		if err != nil {
			t.Fatalf("error while running pktgen prog: %s", err)
		}
		if statusCode != 0 {
			printBpfDebugLog(t)
			t.Fatalf("error while running pktgen program: unexpected status code: %d", statusCode)
		}

		statusCode, data, ctx, err = runBpfProgram(progset.setup, data, ctx)
		if err != nil {
			printBpfDebugLog(t)
			t.Fatalf("error while running setup prog: %s", err)
		}

		status := make([]byte, 4)
		nl.NativeEndian().PutUint32(status, statusCode)
		data = append(status, data...)

		statusCode, data, ctx, err = runBpfProgram(progset.check, data, ctx)
		if err != nil {
			t.Fatalf("error while running check program: %+v", err)
		}
		if statusCode != 0 {
			printBpfDebugLog(t)
			t.Fatalf("error while running check program: unexpected status code: %d", statusCode)
		}

		consumeBpfDebugLog(t)
	}
}
