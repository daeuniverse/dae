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

func collectPrograms(t *testing.T) (progset []programSet, err error) {
	obj := &bpftestObjects{}
	pinPath := "/sys/fs/bpf/dae"
	if err = os.MkdirAll(pinPath, 0755); err != nil && !os.IsExist(err) {
		return
	}

	if err = loadBpftestObjects(obj,
		&ebpf.CollectionOptions{
			Maps: ebpf.MapOptions{
				PinPath: pinPath,
			},
			Programs: ebpf.ProgramOptions{
				LogSize: ebpf.DefaultVerifierLogSize * 10,
			},
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

		return nil, err
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
	file, err := os.Open("/sys/kernel/tracing/trace_pipe")
	if err != nil {
		t.Fatalf("Failed to open trace_pipe: %v", err)
	}
	defer file.Close()

	buffer := make([]byte, 1024*64)
	n, err := file.Read(buffer)
	if err != nil {
		t.Fatalf("Failed to read from trace_pipe: %v", err)
	}

	return string(buffer[:n])
}

func Test(t *testing.T) {
	progsets, err := collectPrograms(t)
	if err != nil {
		t.Fatalf("error while collecting programs: %s", err)
	}

	for _, progset := range progsets {
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
