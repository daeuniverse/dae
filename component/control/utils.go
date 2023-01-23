/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2022, mzz2017 (mzz@tuta.io). All rights reserved.
 */

package control

import (
	"github.com/v2rayA/dae/common"
	"github.com/cilium/ebpf"
	"net/netip"
)

type bpfLpmKey struct {
	PrefixLen uint32
	Data      [4]uint32
}

func (o *bpfObjects) NewLpmMap(keys []bpfLpmKey, values []uint32) (m *ebpf.Map, err error) {
	m, err = o.UnusedLpmType.Clone()
	if err != nil {
		return nil, err
	}
	if _, err = m.BatchUpdate(keys, values, &ebpf.BatchOptions{
		ElemFlags: uint64(ebpf.UpdateAny),
	}); err != nil {
		return nil, err
	}
	return m, nil
}

func swap16(a uint16) uint16 {
	return (a >> 8) + ((a & 0xFF) << 8)
}

func cidrToBpfLpmKey(prefix netip.Prefix) bpfLpmKey {
	bits := prefix.Bits()
	ip := prefix.Addr().As16()
	if prefix.Addr().Is4() {
		bits += 96
	}
	return bpfLpmKey{
		PrefixLen: uint32(bits),
		Data:      common.Ipv6ByteSliceToUint32Array(ip[:]),
	}
}
