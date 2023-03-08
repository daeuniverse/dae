//go:build arm || arm64 || arm64be || armbe || riscv64

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2023, v2rayA Organization <team@v2raya.org>
 */

package internal

// utsnameToString converts the utsname to a string and returns it.
func utsnameToString(unameArray [65]uint8) string {
	var byteString [65]byte
	var indexLength int
	for ; unameArray[indexLength] != 0; indexLength++ {
		byteString[indexLength] = unameArray[indexLength]
	}
	return string(byteString[:indexLength])
}
