//go:build linux && dae_bpf_tests

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package tests

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
