/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"testing"

	"github.com/daeuniverse/dae/common/consts"
)

func TestNetworkTypeHealthKeyMapsTcpDnsToSharedTcpCollection(t *testing.T) {
	typ := &NetworkType{
		L4Proto:   consts.L4ProtoStr_TCP,
		IpVersion: consts.IpVersionStr_4,
		IsDns:     true,
	}
	if got := typ.HealthDomain(); got != HealthDomainTCP {
		t.Fatalf("HealthDomain() = %v, want %v", got, HealthDomainTCP)
	}
	if got := typ.HealthKey().CollectionIndex(); got != IdxTcp4 {
		t.Fatalf("CollectionIndex() = %d, want %d", got, IdxTcp4)
	}
}

func TestStandardHealthKeysCoverCanonicalCollections(t *testing.T) {
	keys := StandardHealthKeys()
	want := []int{IdxDnsUdp4, IdxDnsUdp6, IdxTcp4, IdxTcp6, IdxUdp4, IdxUdp6}
	for i, key := range keys {
		if got := key.CollectionIndex(); got != want[i] {
			t.Fatalf("keys[%d].CollectionIndex() = %d, want %d", i, got, want[i])
		}
		if key.NetworkType() == nil {
			t.Fatalf("keys[%d].NetworkType() = nil", i)
		}
	}
}

func TestHealthKeyFromCollectionIndexUsesDirectCanonicalMapping(t *testing.T) {
	for _, idx := range []int{IdxDnsUdp4, IdxDnsUdp6, IdxTcp4, IdxTcp6, IdxUdp4, IdxUdp6} {
		key, ok := HealthKeyFromCollectionIndex(idx)
		if !ok {
			t.Fatalf("HealthKeyFromCollectionIndex(%d) ok = false, want true", idx)
		}
		if got := key.CollectionIndex(); got != idx {
			t.Fatalf("HealthKeyFromCollectionIndex(%d).CollectionIndex() = %d", idx, got)
		}
	}
	if _, ok := HealthKeyFromCollectionIndex(IdxDnsTcp4); ok {
		t.Fatal("HealthKeyFromCollectionIndex(IdxDnsTcp4) ok = true, want false for TCP DNS alias")
	}
}
