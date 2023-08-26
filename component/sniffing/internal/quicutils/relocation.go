/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2023, daeuniverse Organization <dae@v2raya.org>
 */

package quicutils

import (
	"fmt"
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

func ReassembleCryptos(offsets []*CryptoFrameOffset, newPayload []byte) (newOffsets []*CryptoFrameOffset, err error) {
	oldLen := len(offsets)
	var frameSize int
	var offset *CryptoFrameOffset
	var boundary int
	// Extract crypto frames.
	for iNextFrame := 0; iNextFrame < len(newPayload); iNextFrame += frameSize {
		offset, frameSize, err = ExtractCryptoFrameOffset(newPayload[iNextFrame:], iNextFrame)
		if err != nil {
			return nil, err
		}
		if offset == nil {
			continue
		}
		offsets = append(offsets, offset)
		if offset.UpperAppOffset+len(offset.Data) > boundary {
			boundary = offset.UpperAppOffset + len(offset.Data)
		}
	}
	// Sort the new part.
	newPart := offsets[oldLen:]
	sort.Slice(newPart, func(i, j int) bool {
		return newPart[i].UpperAppOffset < newPart[j].UpperAppOffset
	})

	// Insertion sort.
	for i := oldLen; i < len(offsets); i++ {
		item := offsets[i]
		j := i - 1
		for ; j >= 0; j-- {
			if item.UpperAppOffset < offsets[j].UpperAppOffset {
				offsets[j+1] = offsets[j]
			} else {
				if offsets[j+1] != item {
					offsets[j+1] = item
				}
				break
			}
		}
		if j < 0 {
			offsets[0] = item
		}
	}
	return offsets, nil
}

func ExtractCryptoFrameOffset(remainder []byte, transportOffset int) (offset *CryptoFrameOffset, frameSize int, err error) {
	if len(remainder) == 0 {
		return nil, 0, fmt.Errorf("frame has no length: %w", OutOfRangeError)
	}
	frameType, nextField, err := BigEndianUvarint(remainder)
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

var (
	ErrMissingCrypto = fmt.Errorf("missing crypto frame")
)

type Locator interface {
	Range(i, j int) ([]byte, error)
	Slice(i, j int) (Locator, error)
	At(i int) (byte, error)
	Len() int
	Bytes() ([]byte, error)
}

// LinearLocator only searches forward and have no boundary check.
type LinearLocator struct {
	left      int
	length    int
	iOuter    int
	baseEnd   int
	baseStart int
	baseData  []byte
	o         []*CryptoFrameOffset
}

func NewLinearLocator(o []*CryptoFrameOffset) *LinearLocator {
	if len(o) == 0 {
		return &LinearLocator{}
	}
	return &LinearLocator{
		left:      0,
		length:    o[len(o)-1].UpperAppOffset + len(o[len(o)-1].Data),
		iOuter:    0,
		baseData:  o[0].Data,
		baseStart: o[0].UpperAppOffset,
		baseEnd:   o[0].UpperAppOffset + len(o[0].Data),
		o:         o,
	}
}

func (l *LinearLocator) relocate(i int) error {
	// Relocate ll.iOuter.
	for i >= l.baseEnd {
		if l.iOuter+1 >= len(l.o) {
			return ErrMissingCrypto
		}
		l.iOuter++
		l.baseData = l.o[l.iOuter].Data
		l.baseStart = l.o[l.iOuter].UpperAppOffset
		l.baseEnd = l.baseStart + len(l.baseData)
	}
	if i < l.baseStart {
		return ErrMissingCrypto
	}
	return nil
}

func (l *LinearLocator) Range(i, j int) ([]byte, error) {
	if i == j {
		return []byte{}, nil
	}
	if len(l.o) == 0 {
		return nil, ErrMissingCrypto
	}
	size := j - i

	// We find bytes including i and j, so we should sub j with 1.
	i += l.left
	j += l.left - 1
	if err := l.relocate(i); err != nil {
		return nil, err
	}

	// Linearly copy.

	if j < l.baseEnd {
		// In the same block, no copy needed.
		return l.baseData[i-l.baseStart : j-l.baseStart+1], nil
	}

	b := make([]byte, size)
	k := 0
	for j >= l.baseEnd {
		n := copy(b[k:], l.baseData[i-l.baseStart:])
		k += n
		i += n
		if l.iOuter+1 >= len(l.o) || l.o[l.iOuter].UpperAppOffset+len(l.o[l.iOuter+1].Data) != l.o[l.iOuter].UpperAppOffset {
			// Some crypto is missing.
			return nil, ErrMissingCrypto
		}
		l.iOuter++
		l.baseData = l.o[l.iOuter].Data
		l.baseStart = l.o[l.iOuter].UpperAppOffset
		l.baseEnd = l.baseStart + len(l.baseData)
	}
	copy(b[k:], l.baseData[i-l.baseStart:j-l.baseStart+1])
	return b, nil
}

func (l *LinearLocator) At(i int) (byte, error) {
	if len(l.o) == 0 {
		return 0, ErrMissingCrypto
	}
	i += l.left

	if err := l.relocate(i); err != nil {
		return 0, err
	}
	b := l.baseData[i-l.baseStart]
	return b, nil
}

func (l *LinearLocator) Slice(i, j int) (Locator, error) {
	// We do not care about right.
	newLL := *l
	newLL.left += i
	newLL.length = j - i + 1
	return &newLL, nil
}

func (l *LinearLocator) Bytes() ([]byte, error) {
	return l.Range(0, l.length)
}

var _ Locator = &LinearLocator{}

func (l *LinearLocator) Len() int {
	return l.length
}

type BuiltinBytesLocator []byte

func (l BuiltinBytesLocator) Range(i, j int) ([]byte, error) {
	return l[i:j], nil
}
func (l BuiltinBytesLocator) At(i int) (byte, error) {
	return l[i], nil
}
func (l BuiltinBytesLocator) Slice(i, j int) (Locator, error) {
	return l[i:j], nil
}
func (l BuiltinBytesLocator) Len() int {
	return len(l)
}
func (l BuiltinBytesLocator) Bytes() ([]byte, error) {
	return l, nil
}

var _ Locator = BuiltinBytesLocator{}
