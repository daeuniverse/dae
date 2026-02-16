/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"encoding/binary"
	"math/bits"
	"net/netip"
)

const (
	hashMix1 = uint64(0xff51afd7ed558ccd)
	hashMix2 = uint64(0xc4ceb9fe1a85ec53)
)

func hashAddrPort(ap netip.AddrPort) uint64 {
	addr := ap.Addr()
	p := uint64(ap.Port())

	var hi, lo uint64
	if addr.Is4() {
		// Fast path for IPv4 traffic.
		a4 := addr.As4()
		lo = uint64(binary.BigEndian.Uint32(a4[:]))
	} else {
		a16 := addr.As16()
		hi = binary.BigEndian.Uint64(a16[:8])
		lo = binary.BigEndian.Uint64(a16[8:])
	}

	// 低开销混合：避免逐字节循环，减少 hot path 指令数。
	h := hi ^ bits.RotateLeft64(lo, 17) ^ (p << 48) ^ p
	h ^= h >> 33
	h *= hashMix1
	h ^= h >> 33
	h *= hashMix2
	h ^= h >> 33
	return h
}

func hashPacketSnifferKey(k PacketSnifferKey) uint64 {
	h1 := hashAddrPort(k.LAddr)
	h2 := hashAddrPort(k.RAddr)
	return h1 ^ bits.RotateLeft64(h2, 1)
}
