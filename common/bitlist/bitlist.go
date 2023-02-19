/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2023, v2rayA Organization <team@v2raya.org>
 */

package bitlist

import (
	"fmt"
	"github.com/mzz2017/softwind/common"
	"github.com/mzz2017/softwind/pkg/zeroalloc/buffer"
	"github.com/mzz2017/softwind/pool"
	"math/bits"
)

// CompactBitList allows your units to be of arbitrary bit size.
type CompactBitList struct {
	unitBitSize int
	size        int
	b           *buffer.Buffer
	unitNum     int
}

func NewCompactBitList(unitBitSize int) *CompactBitList {
	return &CompactBitList{
		unitBitSize: unitBitSize,
		size:        0,
		b:           buffer.NewBuffer(1),
	}
}

// Set is not optimized yet.
func (m *CompactBitList) Set(iUnit int, v uint64) {
	if bits.Len64(v) > m.unitBitSize {
		panic(fmt.Sprintf("value %v exceeds unit bit size", v))
	}
	m.growByUnitIndex(iUnit)
	b := m.b.Bytes()
	i := iUnit * m.unitBitSize / 8
	j := iUnit * m.unitBitSize % 8
	for unitToTravel := m.unitBitSize; unitToTravel > 0; unitToTravel -= 8 {
		k := 0
		for ; k < unitToTravel && j+k < 8; k++ {
			b[i] &= ^(1 << (k + j)) // clear bit.
			val := uint8((v & (1 << k)) << j)
			b[i] |= val // set bit.
		}
		// Now unitBitSize is traveled and we should break the loop,
		// OR we did not travel the byte and we need to travel the next byte.
		if k >= unitToTravel {
			break
		}
		i++
		bakJ := j
		j = k
		for ; k < unitToTravel && k < 8; k++ {
			b[i] &= ^(1 << (k - j)) // clear bit.
			val := uint8((v & (1 << k)) >> j)
			b[i] |= val // set bit.
		}
		v >>= 8
		j = (bakJ + 8) % 8
	}
	m.unitNum = common.Max(m.unitNum, iUnit+1)
}

func (m *CompactBitList) Get(iUnit int) (v uint64) {
	bitBoundary := (iUnit + 1) * m.unitBitSize
	if m.b.Len()*8 < bitBoundary {
		return 0
	}

	b := m.b.Bytes()
	i := iUnit * m.unitBitSize / 8
	j := iUnit * m.unitBitSize % 8

	var val uint8
	byteSpace := 8 - j
	// 11111111
	//      |
	//      j   byteSpace = 6, unitBitSize = 2
	//     11   We only copy those 2 bits, so we left shift 4 and right shift 4+2.
	if byteSpace > m.unitBitSize {
		toTrimLeft := byteSpace - m.unitBitSize
		return uint64((b[i] << toTrimLeft) >> (toTrimLeft + j))
	} else {
		// Trim right only.
		val = b[i] >> j
	}
	v |= uint64(val)

	offset := 8 - j
	i++
	// Now we have multiple of 8 bits spaces to move.
	unitToTravel := m.unitBitSize - offset
	for ; unitToTravel >= 8; unitToTravel, i, offset = unitToTravel-8, i+1, offset+8 {
		// 11111111
		//        |
		//        p
		// 11111111 We copy whole 8 bits
		v |= uint64(b[i]) << offset
	}
	if unitToTravel == 0 {
		return v
	}

	// 11111111
	//        |
	//        p   unitToTravel = 3
	//      111   We only copy those 3 bits, so we left shift 5 and right shift 5.
	toTrimLeft := 8 - unitToTravel
	if offset > toTrimLeft {
		v |= uint64(b[i]<<toTrimLeft) << (offset - toTrimLeft)
	} else {
		v |= uint64(b[i]<<toTrimLeft) >> (toTrimLeft - offset)
	}
	return v
}

func (m *CompactBitList) Append(v uint64) {
	m.Set(m.unitNum, v)
}

func (m *CompactBitList) growByUnitIndex(i int) {
	if bitBoundary := (i + 1) * m.unitBitSize; m.b.Len()*8 < bitBoundary {
		needBytes := bitBoundary / 8
		if bitBoundary%8 != 0 {
			needBytes++
		}
		m.b.Extend(needBytes - m.b.Len())
	}
}

func (m *CompactBitList) Tighten() {
	a := pool.B(make([]byte, m.b.Len()))
	copy(a, m.b.Bytes())
	m.b.Put()
	m.b = buffer.NewBufferFrom(a)
}

func (m *CompactBitList) Put() {
	m.b.Put()
}
