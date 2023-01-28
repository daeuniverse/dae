/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2022, mzz2017 <mzz@tuta.io>
 */

package control

import (
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/v2rayA/dae/common"
	"github.com/v2rayA/dae/pkg/ebpf_internal"
	"net/netip"
	"reflect"
)

type _bpfLpmKey struct {
	PrefixLen uint32
	Data      [4]uint32
}

func (o *bpfObjects) newLpmMap(keys []_bpfLpmKey, values []uint32) (m *ebpf.Map, err error) {
	m, err = ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.LPMTrie,
		Flags:      o.UnusedLpmType.Flags(),
		MaxEntries: o.UnusedLpmType.MaxEntries(),
		KeySize:    o.UnusedLpmType.KeySize(),
		ValueSize:  o.UnusedLpmType.ValueSize(),
	})
	if err != nil {
		return nil, err
	}
	if _, err = BatchUpdate(m, keys, values, &ebpf.BatchOptions{
		ElemFlags: uint64(ebpf.UpdateAny),
	}); err != nil {
		return nil, err
	}
	return m, nil
}

func swap16(a uint16) uint16 {
	return (a >> 8) + ((a & 0xFF) << 8)
}

func cidrToBpfLpmKey(prefix netip.Prefix) _bpfLpmKey {
	bits := prefix.Bits()
	if prefix.Addr().Is4() {
		bits += 96
	}
	ip := prefix.Addr().As16()
	return _bpfLpmKey{
		PrefixLen: uint32(bits),
		Data:      common.Ipv6ByteSliceToUint32Array(ip[:]),
	}
}

// A utility to convert the values to proper strings.
func int8ToStr(arr []int8) string {
	b := make([]byte, 0, len(arr))
	for _, v := range arr {
		if v == 0x00 {
			break
		}
		b = append(b, byte(v))
	}
	return string(b)
}
func BatchUpdate(m *ebpf.Map, keys interface{}, values interface{}, opts *ebpf.BatchOptions) (n int, err error) {
	var old bool
	version, e := internal.KernelVersion()
	if e != nil || version.Less(internal.Version{5, 6, 0}) {
		old = true
	}
	if !old {
		return m.BatchUpdate(keys, values, opts)
	} else {
		vKeys := reflect.ValueOf(keys)
		if vKeys.Kind() != reflect.Slice {
			return 0, fmt.Errorf("keys must be slice")
		}
		vVals := reflect.ValueOf(values)
		if vVals.Kind() != reflect.Slice {
			return 0, fmt.Errorf("values must be slice")
		}
		length := vKeys.Len()
		if vVals.Len() != length {
			return 0, fmt.Errorf("keys and values must have same length")
		}

		for i := 0; i < length; i++ {
			vKey := vKeys.Index(i)
			vVal := vVals.Index(i)
			if err = m.Update(vKey.Interface(), vVal.Interface(), ebpf.MapUpdateFlags(opts.ElemFlags)); err != nil {
				return i, err
			}
		}
		return vKeys.Len(), nil
	}
}
