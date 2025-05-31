/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package quicutils

import "io"

// BigEndianUvarint decodes a uint64 from buf and returns that value and the
// number of bytes read (> 0).
func BigEndianUvarint(buf []byte) (uint64, int, error) {
	if len(buf) == 0 {
		return 0, 0, io.ErrUnexpectedEOF
	}
	length := 1 << (buf[0] >> 6)
	if length == 0 {
		return 0, 0, io.ErrUnexpectedEOF
	}
	x := uint64(buf[0] & 0x3f)
	for i := 1; i < length; i++ {
		x = x<<8 | uint64(buf[i])
	}
	return x, length, nil
}
