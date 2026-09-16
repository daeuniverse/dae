/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// These are source contracts for log sites whose level cannot be exercised in
// a unit test because the surrounding path needs kernel privileges (netns
// setup) or a live packet path. They pin the decision so a later edit cannot
// silently put the noise back.

// TestNetkitFailureIsReportedOncePerLevel is the duplicate-report contract: one
// Netkit creation failure used to be printed by the iproute2 layer, again by
// tryCreateNetkit and again by the veth fallback, so a single failure produced
// three lines and the two detail lines sat at info level where they competed
// with lifecycle milestones. The failure is still reported once, with its
// cause, by the fallback warning.
func TestNetkitFailureIsReportedOncePerLevel(t *testing.T) {
	netkit := readPackageSource(t, "netkit_linux.go")
	if strings.Contains(netkit, `log.Infof("Failed to create Netkit device via ip command`) {
		t.Fatal("the iproute2 failure is reported at info level again; it is returned and reported by the caller")
	}
	if !strings.Contains(netkit, `log.Debugf("Failed to create Netkit device via ip command`) {
		t.Fatal("the iproute2 failure detail must stay available at debug")
	}

	netns := readPackageSource(t, "netns_utils.go")
	if strings.Contains(netns, `ns.log.Infof("createNetkitDevice failed`) {
		t.Fatal("tryCreateNetkit reports its own failure at info level again; the wrapped error is reported by the fallback warning")
	}
	if !strings.Contains(netns, `ns.log.Debugf("createNetkitDevice failed`) {
		t.Fatal("the tryCreateNetkit failure detail must stay available at debug")
	}
	if strings.Contains(netns, `ns.log.Info("Falling back to veth device creation")`) {
		t.Fatal("the veth fallback is announced at info level twice: the fallback warning already says it")
	}
	if !strings.Contains(netns, `Warn("Failed to create Netkit device, falling back to veth")`) {
		t.Fatal("the Netkit failure must still be reported once, with its cause, at warning level")
	}
}

// TestPerPacketUdpWarningsGoThroughThePace is the per-packet regression
// contract: the UDP ingress plane must not call the logger directly for a
// condition that holds for every packet of a flow. Each such condition reports
// through its own paced helper, which carries the packet count.
func TestPerPacketUdpWarningsGoThroughThePace(t *testing.T) {
	src := readPackageSource(t, "udp_ingress_task.go")
	for _, unpaced := range []string{
		`c.log.Warnf("No AddrPort presented: %v", retrieveErr)`,
		`}).Warn("UDP routing tuple lookup failed for DNS; fallback to userspace routing")`,
	} {
		if strings.Contains(src, unpaced) {
			t.Fatalf("per-packet warning %q is back on the unpaced path", unpaced)
		}
	}
	for _, paced := range []string{
		"c.logUdpRoutingTupleFailure(retrieveErr)",
		"c.logUdpDNSRoutingTupleFailure(convergeSrc, realDst, retrieveErr)",
		"c.logUdpHandlePktFailure(e)",
	} {
		if !strings.Contains(src, paced) {
			t.Fatalf("per-packet warning must go through %q", paced)
		}
	}

	// The expected reload-window epoch loss keeps its own wording, but only
	// behind the pace that was already there. An unguarded occurrence would
	// put one line per packet back on the datapath.
	const epochWarn = `c.log.Warnln("handlePkt:", e)`
	for offset := 0; ; {
		idx := strings.Index(src[offset:], epochWarn)
		if idx < 0 {
			break
		}
		idx += offset
		guard := src[:idx]
		if len(guard) > 200 {
			guard = guard[len(guard)-200:]
		}
		if !strings.Contains(guard, "c.allowHandlePktEpochWarn(time.Now())") {
			t.Fatalf("epoch handlePkt warning is not paced:\n%s", guard+epochWarn)
		}
		offset = idx + len(epochWarn)
	}
}

// readPackageSource reads one file of this package for a source contract.
//
// The path is resolved against this helper's own directory (via runtime.Caller)
// rather than the process working directory. `go test ./control` runs with the
// package as the working directory, but the datapath whitelist harness in
// .github/workflows/bpf-test.yml compiles this package's tests and runs the
// binary from the repository root, where a bare file name does not resolve.
// Source-contract tests inherit whichever harness runs them, so the helper must
// not depend on the working directory.
func readPackageSource(t *testing.T, name string) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("cannot locate the test source directory to read %s", name)
	}
	src, err := os.ReadFile(filepath.Join(filepath.Dir(thisFile), name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(src)
}
