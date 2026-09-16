//go:build !dae_stub_ebpf

package control

import (
	"testing"
)

// TestOffloadObjectsInSpec verifies that the hard-coded offload program and map
// name lists correspond to objects that actually exist in the real eBPF
// collection (bpf_bpfel.o, embedded via loadBpf). If a tproxy.c SEC name or map
// name drifts from the Go-side list, loadOffloadBpfObjects would report an
// incomplete spec and the offload feature would silently never enable — this test
// catches that drift. Only runnable in the !dae_stub_ebpf build where the real
// .o is embedded.
func TestOffloadObjectsInSpec(t *testing.T) {
	spec, err := loadBpf()
	if err != nil {
		t.Fatalf("loadBpf: %v", err)
	}
	for _, name := range tcpRelayOffloadPrograms {
		if spec.Programs[name] == nil {
			t.Errorf("offload program %q missing from embedded spec", name)
		}
	}
	for _, name := range tcpRelayOffloadMaps {
		if spec.Maps[name] == nil {
			t.Errorf("offload map %q missing from embedded spec", name)
		}
	}
}
