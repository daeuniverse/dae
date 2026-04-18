//go:build linux && dae_bpf_tests

package control

import (
	"fmt"

	"github.com/cilium/ebpf"
)

func disableAllPinnedMapsForTests(spec *ebpf.CollectionSpec) error {
	if spec == nil {
		return fmt.Errorf("nil collection spec")
	}
	for _, m := range spec.Maps {
		if m == nil {
			continue
		}
		m.Pinning = ebpf.PinNone
	}
	return nil
}
