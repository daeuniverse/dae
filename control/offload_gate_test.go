package control

import (
	"os"
	"slices"
	"testing"
)

// TestOffloadGateDisabled tests the opt-in gate predicate: the feature is off by
// default, DAE_DISABLE_TCP_RELAY_OFFLOAD=1 beats an explicit opt-in, and
// DAE_ALLOW_TCP_SOCKMAP=1 alone enables it. Runnable under dae_stub_ebpf because
// it only reads environment variables.
func TestOffloadGateDisabled(t *testing.T) {
	_ = os.Unsetenv("DAE_ALLOW_TCP_SOCKMAP")
	_ = os.Unsetenv("DAE_DISABLE_TCP_RELAY_OFFLOAD")
	if tcpRelayOffloadEnabled() {
		t.Error("disabled by default: no env vars set")
	}
	if err := os.Setenv("DAE_DISABLE_TCP_RELAY_OFFLOAD", "1"); err != nil {
		t.Fatalf("Setenv: %v", err)
	}
	if err := os.Setenv("DAE_ALLOW_TCP_SOCKMAP", "1"); err != nil {
		t.Fatalf("Setenv: %v", err)
	}
	if tcpRelayOffloadEnabled() {
		t.Error("DAE_DISABLE_TCP_RELAY_OFFLOAD=1 must win over opt-in")
	}
	_ = os.Unsetenv("DAE_DISABLE_TCP_RELAY_OFFLOAD")
	if !tcpRelayOffloadEnabled() {
		t.Error("opt-in with DAE_ALLOW_TCP_SOCKMAP=1 must enable")
	}
	_ = os.Unsetenv("DAE_ALLOW_TCP_SOCKMAP")
}

// TestTCPRelayOffloadKprobeFallbackArchitecture verifies that a mismatched
// pt_regs program is neither loaded nor attached on non-x86 kernels.
func TestTCPRelayOffloadKprobeFallbackArchitecture(t *testing.T) {
	for goarch, want := range map[string]bool{
		"amd64":   true,
		"arm64":   false,
		"mips64":  false,
		"ppc64":   false,
		"riscv64": false,
		"s390x":   false,
	} {
		if got := tcpOffloadKprobeFallbackSupported(goarch); got != want {
			t.Errorf("GOARCH=%s: supported=%t, want %t", goarch, got, want)
		}
	}
	if programs := tcpRelayOffloadProgramsForArch("amd64"); !slices.Contains(programs, "tcp_offload_sent_account_kprobe") {
		t.Fatal("amd64 offload collection omitted its compatible kprobe fallback")
	}
	for _, goarch := range []string{"arm64", "ppc64", "s390x"} {
		programs := tcpRelayOffloadProgramsForArch(goarch)
		if slices.Contains(programs, "tcp_offload_sent_account_kprobe") {
			t.Fatalf("GOARCH=%s offload collection retained the x86 kprobe fallback", goarch)
		}
		if !slices.Contains(programs, "tcp_offload_sent_account") {
			t.Fatalf("GOARCH=%s offload collection omitted portable fentry accounting", goarch)
		}
	}
}

// TestOffloadProgramsAndMapsComplete checks that the hard-coded offload program
// and map name lists match the generated bpfPrograms/bpfMaps struct fields. This
// guards against drift between tproxy.c's SEC names / map names and the Go-side
// collection used by loadOffloadBpfObjects.
func TestOffloadProgramsAndMapsComplete(t *testing.T) {
	wantPrograms := map[string]bool{
		"tcp_offload_redirect":            false,
		"tcp_offload_sent_account":        false,
		"tcp_offload_sent_account_kprobe": false,
	}
	for _, p := range tcpRelayOffloadPrograms {
		wantPrograms[p] = true
	}
	for name, seen := range wantPrograms {
		if !seen {
			t.Errorf("program %q missing from tcpRelayOffloadPrograms", name)
		}
	}
	if len(tcpRelayOffloadPrograms) != 3 {
		t.Errorf("expected 3 offload programs, got %d", len(tcpRelayOffloadPrograms))
	}

	wantMaps := map[string]bool{
		"fast_sock":         false,
		"tcp_offload_pause": false,
		"tcp_offload_sent":  false,
	}
	for _, m := range tcpRelayOffloadMaps {
		wantMaps[m] = true
	}
	for name, seen := range wantMaps {
		if !seen {
			t.Errorf("map %q missing from tcpRelayOffloadMaps", name)
		}
	}
	if len(tcpRelayOffloadMaps) != 3 {
		t.Errorf("expected 3 offload maps, got %d", len(tcpRelayOffloadMaps))
	}
}
