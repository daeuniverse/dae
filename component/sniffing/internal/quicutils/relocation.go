/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2023, v2rayA Organization <team@v2raya.org>
 */

package quicutils

import (
	"fmt"
	"github.com/mzz2017/softwind/pool"
	"io/fs"
	"sort"
)

var (
	UnknownFrameTypeError = fmt.Errorf("unknown frame type")
	OutOfRangeError       = fmt.Errorf("index out of range")
)

const (
	Quic_FrameType_Padding          = 0
	Quic_FrameType_Ping             = 1
	Quic_FrameType_Crypto           = 6
	Quic_FrameType_ConnectionClose  = 0x1c
	Quic_FrameType_ConnectionClose2 = 0x1d
)

type CryptoFrameOffset struct {
	UpperAppOffset int
	// Offset of data in quic payload.
	Data []byte
}

type CryptoFrameRelocation struct {
	payload []byte
	o       []*CryptoFrameOffset
	length  int
}

func NewCryptoFrameRelocation(plaintextPayload []byte) (cryptoRelocation *CryptoFrameRelocation, err error) {
	var frameSize int
	var offset *CryptoFrameOffset
	cryptoRelocation = &CryptoFrameRelocation{
		payload: plaintextPayload,
		o:       nil,
	}

	// Extract crypto frames.
	for iNextFrame := 0; iNextFrame < len(plaintextPayload); iNextFrame += frameSize {
		offset, frameSize, err = ExtractCryptoFrameOffset(plaintextPayload[iNextFrame:], iNextFrame)
		if err != nil {
			return nil, err
		}
		if offset == nil {
			continue
		}
		cryptoRelocation.o = append(cryptoRelocation.o, offset)
	}

	// Sort offsets by UpperAppOffset.
	sort.Slice(cryptoRelocation.o, func(i, j int) bool {
		return cryptoRelocation.o[i].UpperAppOffset < cryptoRelocation.o[j].UpperAppOffset
	})

	// Store length.
	left := cryptoRelocation.o[0]
	right := cryptoRelocation.o[len(cryptoRelocation.o)-1]
	cryptoRelocation.length = right.UpperAppOffset + len(right.Data) - left.UpperAppOffset

	return cryptoRelocation, nil
}

func ReassembleCryptoToBytesFromPool(plaintextPayload []byte) (b []byte, err error) {
	var frameSize int
	var offset *CryptoFrameOffset
	var boundary int
	b = pool.Get(len(plaintextPayload))
	// Extract crypto frames.
	for iNextFrame := 0; iNextFrame < len(plaintextPayload); iNextFrame += frameSize {
		offset, frameSize, err = ExtractCryptoFrameOffset(plaintextPayload[iNextFrame:], iNextFrame)
		if err != nil {
			pool.Put(b)
			return nil, err
		}
		if offset == nil {
			continue
		}
		copy(b[offset.UpperAppOffset:], offset.Data)
		if offset.UpperAppOffset+len(offset.Data) > boundary {
			boundary = offset.UpperAppOffset + len(offset.Data)
		}
	}
	return b[:boundary], nil
}

func ExtractCryptoFrameOffset(remainder []byte, transportOffset int) (offset *CryptoFrameOffset, frameSize int, err error) {
	if len(remainder) == 0 {
		return nil, 0, fmt.Errorf("frame has no length: %w", OutOfRangeError)
	}
	frameType, nextField, err := BigEndianUvarint(remainder[:])
	if err != nil {
		return nil, 0, err
	}
	switch frameType {
	case Quic_FrameType_Ping:
		return nil, nextField, nil
	case Quic_FrameType_Padding:
		for ; nextField < len(remainder) && remainder[nextField] == 0; nextField++ {
		}
		return nil, nextField, nil
	case Quic_FrameType_Crypto:
		offset, n, err := BigEndianUvarint(remainder[nextField:])
		if err != nil {
			return nil, 0, err
		}
		nextField += n

		length, n, err := BigEndianUvarint(remainder[nextField:])
		if err != nil {
			return nil, 0, err
		}
		nextField += n

		return &CryptoFrameOffset{
			UpperAppOffset: int(offset),
			Data:           remainder[nextField : nextField+int(length)],
		}, nextField + int(length), nil
	case Quic_FrameType_ConnectionClose, Quic_FrameType_ConnectionClose2:
		return nil, 0, fmt.Errorf("connection closed: %w", fs.ErrClosed)
	default:
		return nil, 0, fmt.Errorf("%w: %v", UnknownFrameTypeError, frameType)
	}
}

func (r *CryptoFrameRelocation) BinarySearch(iUpper int, leftOuter, rightOuter int) (iOuter int, iInner int, err error) {
	rightOuterInstance := r.o[rightOuter]
	if iUpper < r.o[leftOuter].UpperAppOffset || iUpper >= rightOuterInstance.UpperAppOffset+len(rightOuterInstance.Data) {
		return 0, 0, fmt.Errorf("%w: %v is not in [%v, %v)", OutOfRangeError, iUpper, r.o[leftOuter].UpperAppOffset, rightOuterInstance.UpperAppOffset+len(rightOuterInstance.Data))
	}
	for leftOuter < rightOuter {
		mid := leftOuter + ((rightOuter - leftOuter) >> 1)
		if iUpper < r.o[mid].UpperAppOffset {
			rightOuter = mid - 1
		} else if iUpper >= r.o[mid].UpperAppOffset {
			if iUpper < r.o[mid].UpperAppOffset+len(r.o[mid].Data) {
				return mid, iUpper - r.o[mid].UpperAppOffset, nil
			} else {
				leftOuter = mid + 1
			}
		}
	}
	return leftOuter, iUpper - r.o[leftOuter].UpperAppOffset, nil
}

func (r *CryptoFrameRelocation) BytesFromPool() []byte {
	if len(r.o) == 0 {
		return pool.Get(0)
	}
	right := r.o[len(r.o)-1]
	return r.copyBytes(0, 0, len(r.o)-1, len(right.Data)-1, r.length)
}

// RangeFromPool copy bytes from iUpperAppOffset to jUpperAppOffset.
// It is not suggested to use it for large range and frequent copy.
func (r *CryptoFrameRelocation) RangeFromPool(i, j int) []byte {
	if i > j {
		panic(fmt.Sprintf("i > j: %v > %v", i, j))
	}
	// We find bytes including i and j, so we should sub j with 1.
	j--

	// Find i.
	iOuter, iInner, err := r.BinarySearch(i, 0, len(r.o)-1)
	if err != nil {
		panic(err)
	}
	// Check if j and i is in the same outer or adjacent outers.
	// It is very common because we usually have small access range.
	var jOuter, jInner int
	if iInner+j-i < len(r.o[iOuter].Data) {
		jOuter = iOuter
		jInner = iInner + j - i
	} else if iOuter+1 < len(r.o) && j < r.o[iOuter+1].UpperAppOffset+len(r.o[iOuter+1].Data) {
		jOuter = iOuter + 1
		jInner = (j - i) + (len(r.o[iOuter].Data) - iInner)
	} else {
		// We have searched iOuter and iOuter+1
		jOuter, jInner, err = r.BinarySearch(j, iOuter+2, len(r.o)-1)
		if err != nil {
			panic(err)
		}
	}

	return r.copyBytes(iOuter, iInner, jOuter, jInner, j-i+1)
}

// copyBytes copy bytes including i and j.
func (r *CryptoFrameRelocation) copyBytes(iOuter, iInner, jOuter, jInner, size int) []byte {
	b := pool.Get(size)
	//io := r.o[iOuter]
	k := 0
	for {
		// Most accesses are small range accesses.
		base := r.o[iOuter].Data
		if iOuter == jOuter {
			k += copy(b[k:], base[iInner:jInner+1])
			if k != size {
				panic("unmatched size")
			}
			return b
		} else {
			k += copy(b[k:], base[iInner:])
			if iInner != 0 {
				iInner = 0
			}
			iOuter++
		}
	}
}
func (r *CryptoFrameRelocation) At(i int) byte {
	iOuter, iInner, err := r.BinarySearch(i, 0, len(r.o)-1)
	if err != nil {
		panic(err)
	}
	return r.o[iOuter].Data[iInner]
}

func (r *CryptoFrameRelocation) Len() int {
	return r.length
}

type Locator interface {
	Range(i, j int) []byte
	Slice(i, j int) Locator
	At(i int) byte
	Len() int
}

// LinearLocator only searches forward and have no boundary check.
type LinearLocator struct {
	left      int
	length    int
	iOuter    int
	baseEnd   int
	baseStart int
	baseData  []byte
	cfr       *CryptoFrameRelocation
}

func NewLinearLocator(cfr *CryptoFrameRelocation) (linearLocator *LinearLocator) {
	return &LinearLocator{
		left:      0,
		length:    cfr.length,
		iOuter:    0,
		baseData:  cfr.o[0].Data,
		baseStart: cfr.o[0].UpperAppOffset,
		baseEnd:   cfr.o[0].UpperAppOffset + len(cfr.o[0].Data),
		cfr:       cfr,
	}
}

func (ll *LinearLocator) relocate(i int) {
	// Relocate ll.iOuter.
	for i >= ll.baseEnd {
		ll.iOuter++
		ll.baseData = ll.cfr.o[ll.iOuter].Data
		ll.baseStart = ll.cfr.o[ll.iOuter].UpperAppOffset
		ll.baseEnd = ll.baseStart + len(ll.baseData)
	}
}

func (ll *LinearLocator) Range(i, j int) []byte {
	if i == j {
		return []byte{}
	}
	size := j - i

	// We find bytes including i and j, so we should sub j with 1.
	i += ll.left
	j += ll.left - 1
	ll.relocate(i)

	// Linearly copy.

	if j < ll.baseEnd {
		// In the same block, no copy needed.
		return ll.baseData[i-ll.baseStart : j-ll.baseStart+1]
	}

	b := make([]byte, size)
	k := 0
	for j >= ll.baseEnd {
		n := copy(b[k:], ll.baseData[i-ll.baseStart:])
		k += n
		i += n
		ll.iOuter++
		ll.baseData = ll.cfr.o[ll.iOuter].Data
		ll.baseStart = ll.cfr.o[ll.iOuter].UpperAppOffset
		ll.baseEnd = ll.baseStart + len(ll.baseData)
	}
	copy(b[k:], ll.baseData[i-ll.baseStart:j-ll.baseStart+1])
	return b
}

func (ll *LinearLocator) At(i int) byte {
	i += ll.left

	ll.relocate(i)
	b := ll.baseData[i-ll.baseStart]
	return b
}

func (ll *LinearLocator) Slice(i, j int) Locator {
	// We do not care about right.
	newLL := *ll
	newLL.left += i
	newLL.length = j - i + 1
	return &newLL
}

func (ll *LinearLocator) Len() int {
	return ll.length
}

type BuiltinBytesLocator []byte

func (l BuiltinBytesLocator) Range(i, j int) []byte {
	return l[i:j]
}
func (l BuiltinBytesLocator) At(i int) byte {
	return l[i]
}
func (l BuiltinBytesLocator) Slice(i, j int) Locator {
	return l[i:j]
}
func (l BuiltinBytesLocator) Len() int {
	return len(l)
}
