/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2022, v2rayA Organization <team@v2raya.org>
 */

package control

import (
	"encoding/binary"
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

type _bpfPortRange struct {
	PortStart uint16
	PortEnd   uint16
}

func (r _bpfPortRange) Encode() uint32 {
	var b [4]byte
	binary.BigEndian.PutUint16(b[:2], r.PortStart)
	binary.BigEndian.PutUint16(b[2:], r.PortEnd)
	return binary.BigEndian.Uint32(b[:])
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

type bpfObjectsLan struct {
	// NOTICE: Consider to update me if any program added.
	//bpfPrograms
	TproxyEgress  *ebpf.Program `ebpf:"tproxy_egress"`
	TproxyIngress *ebpf.Program `ebpf:"tproxy_ingress"`

	bpfMaps
}

type bpfObjectsWan struct {
	// NOTICE: Consider to update me if any program added.
	//bpfPrograms
	Inet6Bind        *ebpf.Program `ebpf:"inet6_bind"`
	InetAutobind     *ebpf.Program `ebpf:"inet_autobind"`
	InetBind         *ebpf.Program `ebpf:"inet_bind"`
	InetRelease      *ebpf.Program `ebpf:"inet_release"`
	InetSendPrepare  *ebpf.Program `ebpf:"inet_send_prepare"`
	TcpConnect       *ebpf.Program `ebpf:"tcp_connect"`
	TproxyWanEgress  *ebpf.Program `ebpf:"tproxy_wan_egress"`
	TproxyWanIngress *ebpf.Program `ebpf:"tproxy_wan_ingress"`

	bpfMaps
}

func AssignBpfObjects(to *bpfObjects, from interface{}) {
	vTo := reflect.Indirect(reflect.ValueOf(to))
	vFrom := reflect.Indirect(reflect.ValueOf(from))
	tFrom := vFrom.Type()
	// programs
	for i := 0; i < vFrom.NumField(); i++ {
		fieldFrom := vFrom.Field(i)
		structFieldFrom := tFrom.Field(i)
		if structFieldFrom.Type != reflect.TypeOf(&ebpf.Program{}) {
			continue
		}
		fieldTo := vTo.FieldByName(structFieldFrom.Name)
		fieldTo.Set(fieldFrom)
	}

	// bpfMaps
	vFrom = vFrom.FieldByName("bpfMaps")
	tFrom = vFrom.Type()
	for i := 0; i < vFrom.NumField(); i++ {
		fieldFrom := vFrom.Field(i)
		structFieldFrom := tFrom.Field(i)
		fieldTo := vTo.FieldByName(structFieldFrom.Name)
		fieldTo.Set(fieldFrom)
	}
}
