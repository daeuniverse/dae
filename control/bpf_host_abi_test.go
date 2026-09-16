/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"bytes"
	"encoding/binary"
	"runtime"
	"testing"
)

func TestNativeBpfABIForTargetArchitecture(t *testing.T) {
	want := []byte{0x02, 0x01}
	switch runtime.GOARCH {
	case "mips", "mips64", "ppc", "ppc64", "s390x":
		want = []byte{0x01, 0x02}
	}
	var encoded [2]byte
	nativeBpfABI.putUint16(encoded[:], 0x0102)
	if !bytes.Equal(encoded[:], want) {
		t.Fatalf("GOARCH=%s native order encoded %x, want %x", runtime.GOARCH, encoded, want)
	}
}

func TestBpfHostABIPortRangeBothByteOrders(t *testing.T) {
	rangeValue := bpfPortRange{PortStart: 80, PortEnd: 443}
	tests := []struct {
		name string
		abi  bpfHostABI
		want []byte
	}{
		{name: "little", abi: bpfHostABI{order: binary.LittleEndian}, want: []byte{0x50, 0x00, 0xbb, 0x01}},
		{name: "big", abi: bpfHostABI{order: binary.BigEndian}, want: []byte{0x00, 0x50, 0x01, 0xbb}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := tt.abi.encodePortRange(rangeValue)
			if !bytes.Equal(encoded[:4], tt.want) {
				t.Fatalf("unexpected bytes: got %x want %x", encoded[:4], tt.want)
			}
			start, end := tt.abi.parsePortRange(encoded[:])
			if start != rangeValue.PortStart || end != rangeValue.PortEnd {
				t.Fatalf("round trip failed: got %d-%d", start, end)
			}
		})
	}
}

func TestBpfHostABILpmIndexBothByteOrders(t *testing.T) {
	for name, order := range map[string]binary.ByteOrder{
		"little": binary.LittleEndian,
		"big":    binary.BigEndian,
	} {
		t.Run(name, func(t *testing.T) {
			abi := bpfHostABI{order: order}
			var value [16]byte
			abi.putUint32(value[:4], 1)
			if got := abi.uint32(value[:4]); got != 1 {
				t.Fatalf("LPM index round trip: got %d", got)
			}
			if name == "big" && !bytes.Equal(value[:4], []byte{0, 0, 0, 1}) {
				t.Fatalf("big-endian index bytes: %x", value[:4])
			}
		})
	}
}
