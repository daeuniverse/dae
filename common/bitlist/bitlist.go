/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2023, v2rayA Organization <team@v2raya.org>
 */

package bitlist

import (
	"fmt"
	"github.com/mzz2017/softwind/common"
	"github.com/v2rayA/dae/pkg/anybuffer"
	"math/bits"
)

// CompactBitList allows your units to be of arbitrary bit size.
type CompactBitList struct {
	unitBitSize int
	size        int
	b           *anybuffer.Buffer[uint16]
	unitNum     int
}

func NewCompactBitList(unitBitSize int) *CompactBitList {
	return &CompactBitList{
		unitBitSize: unitBitSize,
		size:        0,
		b:           anybuffer.NewBuffer[uint16](1),
	}
}

// Set is not optimized yet.
func (m *CompactBitList) Set(iUnit int, v uint64) {
	if bits.Len64(v) > m.unitBitSize {
		panic(fmt.Sprintf("value %v exceeds unit bit size", v))
	}
	m.growByUnitIndex(iUnit)
	b := m.b.Slice()
	i := iUnit * m.unitBitSize / 16
	j := iUnit * m.unitBitSize % 16
	for unitToTravel := m.unitBitSize; unitToTravel > 0; unitToTravel -= 16 {
		k := 0
		for ; k < unitToTravel && j+k < 16; k++ {
			b[i] &= ^(1 << (k + j)) // clear bit.
			val := uint16((v & (1 << k)) << j)
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
		for ; k < unitToTravel && k < 16; k++ {
			b[i] &= ^(1 << (k - j)) // clear bit.
			val := uint16((v & (1 << k)) >> j)
			b[i] |= val // set bit.
		}
		v >>= 16
		j = (bakJ + 16) % 16
	}
	m.unitNum = common.Max(m.unitNum, iUnit+1)
}

func (m *CompactBitList) Get(iUnit int) (v uint64) {
	bitBoundary := (iUnit + 1) * m.unitBitSize
	if m.b.Len()*16 < bitBoundary {
		return 0
	}

	b := m.b.Slice()
	i := iUnit * m.unitBitSize / 16
	j := iUnit * m.unitBitSize % 16

	var val uint16
	byteSpace := 16 - j
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

	offset := 16 - j
	i++
	// Now we have multiple of 16 bits spaces to move.
	unitToTravel := m.unitBitSize - offset
	for ; unitToTravel >= 16; unitToTravel, i, offset = unitToTravel-16, i+1, offset+16 {
		// 11111111
		//        |
		//        p
		// 11111111 We copy whole 16 bits
		v |= uint64(b[i]) << offset
	}
	if unitToTravel == 0 {
		return v
	}

	// 11111111
	//        |
	//        p   unitToTravel = 3
	//      111   We only copy those 3 bits, so we left shift 5 and right shift 5.
	toTrimLeft := 16 - unitToTravel
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
	if bitBoundary := (i + 1) * m.unitBitSize; m.b.Len()*16 < bitBoundary {
		needBytes := bitBoundary / 16
		if bitBoundary%16 != 0 {
			needBytes++
		}
		m.b.Extend(needBytes - m.b.Len())
	}
}

func (m *CompactBitList) Tighten() {
	a := make([]uint16, m.b.Len())
	copy(a, m.b.Slice())
	m.b = anybuffer.NewBufferFrom(a)
}
