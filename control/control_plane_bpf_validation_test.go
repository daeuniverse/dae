/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"testing"

	"github.com/cilium/ebpf"
)

func TestValidateRequiredBpfMapsLoaded(t *testing.T) {
	t.Run("nil_object", func(t *testing.T) {
		if err := validateRequiredBpfMapsLoaded(nil); err == nil {
			t.Fatal("expected error for nil bpf object")
		}
	})

	t.Run("missing_required_map", func(t *testing.T) {
		b := &bpfObjects{}
		if err := validateRequiredBpfMapsLoaded(b); err == nil {
			t.Fatal("expected error for missing required map")
		}
	})

	t.Run("all_required_maps_present", func(t *testing.T) {
		b := &bpfObjects{
			bpfMaps: bpfMaps{
				DomainRoutingMap: &ebpf.Map{},
				UdpConnStateMap:  &ebpf.Map{},
				RoutingMap:       &ebpf.Map{},
				RoutingMetaMap:   &ebpf.Map{},
			},
		}
		if err := validateRequiredBpfMapsLoaded(b); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}
