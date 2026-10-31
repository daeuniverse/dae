/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import "testing"

func TestSnapshotDatapathWithoutBpf(t *testing.T) {
	plane := &ControlPlane{}
	snapshot := plane.SnapshotDatapath()
	if snapshot.Ebpf.Backend != "unknown" {
		t.Fatalf("backend = %q, want unknown", snapshot.Ebpf.Backend)
	}
	if snapshot.Ebpf.Programs != "not_loaded" || snapshot.Ebpf.Hooks != "detached" {
		t.Fatalf("programs/hooks = %q/%q", snapshot.Ebpf.Programs, snapshot.Ebpf.Hooks)
	}
	if snapshot.Ebpf.RoutingState != "not_published" || snapshot.Ebpf.GenerationID != "" {
		t.Fatalf("routing = %q/%q", snapshot.Ebpf.RoutingState, snapshot.Ebpf.GenerationID)
	}
	if snapshot.Ebpf.Epoch != "" {
		t.Fatalf("epoch = %q, want empty when there is no policy identity", snapshot.Ebpf.Epoch)
	}
	if snapshot.Ebpf.ConnStateOccupancy != nil {
		t.Fatalf("occupancy = %#v, want nil without a map", snapshot.Ebpf.ConnStateOccupancy)
	}
}

func TestTCHookAttachmentsMapScopes(t *testing.T) {
	hooks := &tcHookSet{groups: map[tcHookGroupKey]*tcHookGroup{
		{scope: tcHookScopeHost, ifindex: 2, direction: tcHookIngress}: {
			entries: map[uint16]*tcHookEntry{
				10: {spec: tcHookSpec{Name: "tproxy_ingress", Ifname: "eth0"}},
			},
		},
		{scope: tcHookScopeDae, ifindex: 3, direction: tcHookEgress}: {
			entries: map[uint16]*tcHookEntry{
				10: {spec: tcHookSpec{Name: "wan_egress"}},
			},
		},
	}}
	plane := &ControlPlane{core: &controlPlaneCore{tcHooks: hooks}}

	attachments := plane.tcHookAttachments()
	if len(attachments) != 2 {
		t.Fatalf("attachments = %d, want 2", len(attachments))
	}
	// Sorted by interface first, so the dae-netns "other" attachment leads.
	other := attachments[0]
	if other.Kind != "other" || other.Hook != "dae-netns" || other.Direction != "egress" || other.Name != "wan_egress" {
		t.Fatalf("other attachment = %#v", other)
	}
	iface := attachments[1]
	if iface.Kind != "interface" || iface.Interface != "eth0" || iface.Direction != "ingress" || iface.Name != "tproxy_ingress" {
		t.Fatalf("interface attachment = %#v", iface)
	}
}

func TestConnStateOccupancyWithoutMap(t *testing.T) {
	if got := connStateOccupancy(nil); got != nil {
		t.Fatalf("occupancy = %#v, want nil", got)
	}
	if got := connStateOccupancy(&bpfObjects{}); got != nil {
		t.Fatalf("occupancy without a map = %#v, want nil", got)
	}
}
