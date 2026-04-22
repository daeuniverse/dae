//go:build linux

package internal

import (
	"encoding/binary"
	"testing"
)

func TestHtonsUsesNetworkByteOrder(t *testing.T) {
	const v uint16 = 0x0003 // ETH_P_ALL

	got := Htons(v)

	if NativeEndian == binary.LittleEndian {
		if got != 0x0300 {
			t.Fatalf("little-endian host: Htons(0x0003) = %#04x, want %#04x", got, uint16(0x0300))
		}
		return
	}

	if got != 0x0003 {
		t.Fatalf("big-endian host: Htons(0x0003) = %#04x, want %#04x", got, uint16(0x0003))
	}
}
