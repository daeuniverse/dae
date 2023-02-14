/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2023, v2rayA Organization <team@v2raya.org>
 */

package quicutils

// BigEndianUvarint decodes a uint64 from buf and returns that value and the
// number of bytes read (> 0). If an error occurred, the value is 0
// and the number of bytes n is <= 0 meaning:
//
// 	n == 0: buf too small
// 	n  < 0: value larger than 64 bits (overflow)
// 	        and -n is the number of bytes read
//
func BigEndianUvarint(buf []byte) (uint64, int) {
	if len(buf) == 0 {
		panic(buf)
	}
	length := 1 << (buf[0] >> 6)
	x := uint64(buf[0] & 0x3f)
	for i := 1; i < length; i++ {
		x = x<<8 | uint64(buf[i])
	}
	return x, length
}
