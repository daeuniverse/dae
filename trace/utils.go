/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package trace

import (
	"encoding/binary"
	"strings"
)

func Htons(x uint16) uint16 {
	data := make([]byte, 2)
	nativeEndian.PutUint16(data, x)
	return binary.BigEndian.Uint16(data)
}

func Ntohs(x uint16) uint16 {
	data := make([]byte, 2)
	binary.BigEndian.PutUint16(data, x)
	return nativeEndian.Uint16(data)
}

func TrimNull(s string) string {
	return strings.TrimRight(s, "\x00")
}

func TcpFlags(data uint8) string {
	flags := []string{}
	if data&0b00100000 != 0 {
		flags = append(flags, "U")
	}
	if data&0b00010000 != 0 {
		flags = append(flags, ".")
	}
	if data&0b00001000 != 0 {
		flags = append(flags, "P")
	}
	if data&0b00000100 != 0 {
		flags = append(flags, "R")
	}
	if data&0b00000010 != 0 {
		flags = append(flags, "S")
	}
	if data&0b00000001 != 0 {
		flags = append(flags, "F")
	}
	return strings.Join(flags, "")
}
