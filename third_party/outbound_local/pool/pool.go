// modified from https://github.com/nadoo/glider/blob/master/pool/buffer.go

package pool

import (
	"math/bits"
	"sync"
)

const (
	// number of pools.
	num          = 17
	maxsize      = 1 << (num - 1)
	minsizePower = 6
	minsize      = 1 << minsizePower
)

var (
	pools [num]sync.Pool
)

func init() {
	for i := minsizePower; i < num; i++ {
		size := 1 << i
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

func GetBiggerClosestN(need int) (n int) {
	n = bits.Len32(uint32(need))
	// bits.Len32 returns the number of bits needed to represent the number.
	// For a power of 2, it returns exponent+1, so we subtract 1.
	// For other numbers, we need the next power of 2, which is what bits.Len32 gives.
	// Examples:
	//   need=1024 (2^10): bits.Len32=11 → return 10
	//   need=1025: bits.Len32=11 → return 11 (need 2^11=2048)
	//   need=2048 (2^11): bits.Len32=12 → return 11
	//   need=2049: bits.Len32=12 → return 12 (need 2^12=4096)
	if need == (1 << (n - 1)) {
		// need is exactly a power of 2
		return n - 1
	}
	return n
}

// Get gets a buffer from pool, size should in range: [1, 65536],
// otherwise, this function will call make([]byte, size) directly.
// IMPORTANT: Returns a buffer with capacity >= size to prevent slice bounds panic.
func Get(size int) PB {
	if size >= 1 && size <= maxsize {
		i := GetBiggerClosestN(size) // Fixed: Use GetBiggerClosestN to ensure capacity >= size
		if i < minsizePower {
			i = minsizePower
		}
		return pools[i].Get().([]byte)[:size]
	}
	return make([]byte, size)
}

func GetFullCap(size int) PB {
	a := Get(size)
	a = a[:cap(a)]
	return a
}

func GetMustBigger(size int) PB {
	if size >= 1 && size <= maxsize {
		i := GetBiggerClosestN(size)
		if i < minsizePower {
			i = minsizePower
		}
		return pools[i].Get().([]byte)[:size]
	}
	return make([]byte, size)
}

func GetZero(size int) []byte {
	b := Get(size)
	for i := range b {
		b[i] = 0
	}
	return b
}

func Put(buf []byte) {
	size := cap(buf)
	if size < minsize || size > maxsize {
		// Strictly avoid returning oversize huge buffers to prevent memory leak/retention.
		// Small buffers are also directly discarded.
		return
	}
	
	// For non-power-of-2 sizes, use GetBiggerClosestN to round up to the next bucket.
	// This ensures capacity is not wasted and buffers go to the correct bucket.
	// Examples:
	//   - size=1536 -> i=11 (bucket for 2048) instead of 10 (bucket for 1024)
	//   - size=1024 -> i=10 (bucket for 1024)
	i := GetBiggerClosestN(size)
	if i < minsizePower {
		i = minsizePower
	}
	if i < num {
		pools[i].Put(buf) // nolint:staticcheck
	}
}
