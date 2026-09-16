/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"encoding/binary"

	internal "github.com/daeuniverse/dae/pkg/ebpf_internal"
)

// bpfHostABI owns scalar encoding for structs shared with eBPF C. Packet
// fields declared in network byte order must continue to use explicit
// big-endian conversion at their call sites.
type bpfHostABI struct {
	order binary.ByteOrder
}

var nativeBpfABI = bpfHostABI{order: internal.NativeEndian}

func (a bpfHostABI) uint16(b []byte) uint16 {
	return a.order.Uint16(b)
}

func (a bpfHostABI) uint32(b []byte) uint32 {
	return a.order.Uint32(b)
}

func (a bpfHostABI) uint64(b []byte) uint64 {
	return a.order.Uint64(b)
}

func (a bpfHostABI) putUint16(b []byte, value uint16) {
	a.order.PutUint16(b, value)
}

func (a bpfHostABI) putUint32(b []byte, value uint32) {
	a.order.PutUint32(b, value)
}

func (a bpfHostABI) putUint64(b []byte, value uint64) {
	a.order.PutUint64(b, value)
}

func (a bpfHostABI) encodePortRange(r bpfPortRange) (b [16]byte) {
	a.putUint16(b[:2], r.PortStart)
	a.putUint16(b[2:4], r.PortEnd)
	return b
}

func (r bpfPortRange) Encode() [16]byte {
	return nativeBpfABI.encodePortRange(r)
}

func (a bpfHostABI) parsePortRange(b []byte) (portStart, portEnd uint16) {
	if len(b) < 4 {
		return 0, 0
	}
	return a.uint16(b[:2]), a.uint16(b[2:4])
}

func ParsePortRange(b []byte) (portStart, portEnd uint16) {
	return nativeBpfABI.parsePortRange(b)
}
