/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2022, mzz2017 <mzz@tuta.io>
 */

// modified from https://github.com/nadoo/glider/blob/master/pool/buffer.go

package pool

import (
	"math/bits"
	"sync"
)

const (
	// number of pools.
	num     = 17
	maxsize = 1 << (num - 1)
)

var (
	sizes [num]int
	pools [num]sync.Pool
)

func init() {
	for i := 0; i < num; i++ {
		size := 1 << i
		sizes[i] = size
		pools[i].New = func() interface{} {
			return make([]byte, size)
		}
	}
}

func GetClosestN(need int) (n int) {
	// if need is exactly 2^n, return n-1
	if need&(need-1) == 0 {
		return bits.Len32(uint32(need)) - 1
	}
	// or return its closest n
	return bits.Len32(uint32(need))
}

// Get gets a buffer from pool, size should in range: [1, 65536],
// otherwise, this function will call make([]byte, size) directly.
func Get(size int) []byte {
	if size >= 1 && size <= maxsize {
		i := GetClosestN(size)
		return pools[i].Get().([]byte)[:size]
	}
	return make([]byte, size)
}

// GetZero returns buffer and set all the values to 0
func GetZero(size int) []byte {
	b := Get(size)
	for i := range b {
		b[i] = 0
	}
	return b
}

// Put puts a buffer into pool.
func Put(buf []byte) {
	if size := cap(buf); size >= 1 && size <= maxsize {
		i := GetClosestN(size)
		if i < num {
			pools[i].Put(buf)
		}
	}
}
