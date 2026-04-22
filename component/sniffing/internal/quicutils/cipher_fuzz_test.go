/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package quicutils

import (
	"testing"

	"github.com/daeuniverse/dae/common"
)

func FuzzNewKeys(f *testing.F) {
	f.Add([]byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08})
	f.Add([]byte{})
	f.Add([]byte{0x01})
	f.Add(make([]byte, 256))
	f.Add([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	f.Fuzz(func(t *testing.T, connId []byte) {
		keys, err := NewKeys(connId, Version_V1, common.NewGcm)
		if err != nil {
			return
		}
		_ = keys.Close()
	})
}

func FuzzBigEndianUvarint(f *testing.F) {
	f.Add([]byte{0x44, 0xd0})
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	f.Add([]byte{0x01, 0x02, 0x03, 0x04})

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = BigEndianUvarint(data)
	})
}
