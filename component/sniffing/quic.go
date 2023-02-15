/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2023, v2rayA Organization <team@v2raya.org>
 */

package sniffing

import (
	"errors"
	"github.com/mzz2017/softwind/pool"
	"github.com/v2rayA/dae/component/sniffing/internal/quicutils"
	"io/fs"
)

const (
	QuicFlag_PacketNumberLength = iota
	QuicFlag_PacketNumberLength1
	QuicFlag_Reserved
	QuicFlag_Reserved1
	QuicFlag_LongPacketType
	QuicFlag_LongPacketType1
	QuicFlag_FixedBit
	QuicFlag_HeaderForm
)
const (
	QuicFlag_HeaderForm_LongHeader  = 1
	QuicFlag_LongPacketType_Initial = 0
)

var (
	QuicReassemble = QuicReassemblePolicy_ReassembleCryptoToBytesFromPool
)

type QuicReassemblePolicy int

const (
	QuicReassemblePolicy_ReassembleCryptoToBytesFromPool QuicReassemblePolicy = iota
	QuicReassemblePolicy_LinearLocator
	QuicReassemblePolicy_Slow
)

func (s *Sniffer) SniffQuic() (d string, err error) {
	nextBlock := s.buf
	isQuic := false
	for {
		d, nextBlock, err = sniffQuicBlock(nextBlock)
		if err == nil {
			return d, nil
		}
		// If block is not a quic block, return it.
		if errors.Is(err, NotApplicableError) {
			// But if we have found quic block before, correct it.
			if isQuic {
				return "", NotFoundError
			}
			return "", err
		}
		if errors.Is(err, fs.ErrClosed) {
			// ConnectionClose sniffed.
			return "", NotFoundError
		}
		// Error is not NotApplicableError, should be quic block.
		isQuic = true
		if len(nextBlock) == 0 {
			return "", NotFoundError
		}
	}
}

func sniffQuicBlock(buf []byte) (d string, next []byte, err error) {
	// QUIC: A UDP-Based Multiplexed and Secure Transport
	// https://datatracker.ietf.org/doc/html/rfc9000#name-initial-packet
	const dstConnIdPos = 6
	boundary := dstConnIdPos
	if len(buf) < boundary {
		return "", nil, NotApplicableError
	}
	// Check flag.
	// Long header: 4 bits masked
	// High 4 bits are not protected, so we can access QuicFlag_HeaderForm and QuicFlag_LongPacketType without decryption.
	protectedFlag := buf[0]
	if ((protectedFlag >> QuicFlag_HeaderForm) & 0b11) != QuicFlag_HeaderForm_LongHeader {
		return "", nil, NotApplicableError
	}
	if ((protectedFlag >> QuicFlag_LongPacketType) & 0b11) != QuicFlag_LongPacketType_Initial {
		return "", nil, NotApplicableError
	}

	// Skip version.

	destConnIdLength := int(buf[boundary-1])
	boundary += destConnIdLength + 1 // +1 because next field has 1B length
	if len(buf) < boundary {
		return "", nil, NotApplicableError
	}
	destConnId := buf[dstConnIdPos : dstConnIdPos+destConnIdLength]

	srcConnIdLength := int(buf[boundary-1])
	boundary += srcConnIdLength + quicutils.MaxVarintLen64 // The next fields may have quic.MaxVarintLen64 bytes length
	if len(buf) < boundary {
		return "", nil, NotApplicableError
	}
	tokenLength, n, err := quicutils.BigEndianUvarint(buf[boundary-quicutils.MaxVarintLen64:])
	if err != nil {
		return "", nil, NotApplicableError
	}
	boundary = boundary - quicutils.MaxVarintLen64 + n      // Correct boundary.
	boundary += int(tokenLength) + quicutils.MaxVarintLen64 // Next fields may have quic.MaxVarintLen64 bytes length
	if len(buf) < boundary {
		return "", nil, NotApplicableError
	}
	// https://datatracker.ietf.org/doc/html/rfc9000#name-variable-length-integer-enc
	length, n, err := quicutils.BigEndianUvarint(buf[boundary-quicutils.MaxVarintLen64:])
	if err != nil {
		return "", nil, NotApplicableError
	}
	boundary = boundary - quicutils.MaxVarintLen64 + n // Correct boundary.
	blockEnd := boundary + int(length)
	if len(buf) < blockEnd {
		return "", nil, NotApplicableError
	}
	boundary += quicutils.MaxPacketNumberLength
	if len(buf) < boundary {
		return "", nil, NotApplicableError
	}
	header := buf[:boundary]
	// Decrypt protected Packets.
	// https://datatracker.ietf.org/doc/html/rfc9000#packet-protected

	// This function will modify the packet in place, thus we should save the first byte and MaxPacketNumberLength
	// and recover it later.
	firstByte := header[0]
	rawPacketNumber := pool.Get(quicutils.MaxPacketNumberLength)
	copy(rawPacketNumber, header[boundary-quicutils.MaxPacketNumberLength:])
	defer func() {
		header[0] = firstByte
		copy(header[boundary-quicutils.MaxPacketNumberLength:], rawPacketNumber)
		pool.Put(rawPacketNumber)
	}()
	plaintext, err := quicutils.DecryptQuicFromPool_(header, blockEnd, destConnId)
	if err != nil {
		return "", nil, NotApplicableError
	}
	defer pool.Put(plaintext)
	// Now, we confirm it is exact a quic frame.
	// After here, we should not return NotApplicableError.
	// And we should return nextFrame.
	if d, err = extractSniFromQuicPayload(plaintext); err != nil {
		if errors.Is(err, fs.ErrClosed) {
			return "", nil, err
		}
		return "", buf[blockEnd:], NotFoundError
	}
	return d, buf[blockEnd:], nil
}

func extractSniFromQuicPayload(payload []byte) (sni string, err error) {
	// One payload may have multiple frames.
	// Reassemble Crypto frames.

	// Choose locator.
	var locator quicutils.Locator
	switch QuicReassemble {
	case QuicReassemblePolicy_LinearLocator:
		relocation, err := quicutils.NewCryptoFrameRelocation(payload)
		if err != nil {
			return "", err
		}
		locator = quicutils.NewLinearLocator(relocation)
	case QuicReassemblePolicy_Slow:
		relocation, err := quicutils.NewCryptoFrameRelocation(payload)
		if err != nil {
			return "", err
		}
		b := relocation.BytesFromPool()
		defer pool.Put(b)
		locator = quicutils.BuiltinBytesLocator(b)
	case QuicReassemblePolicy_ReassembleCryptoToBytesFromPool:
		b, err := quicutils.ReassembleCryptoToBytesFromPool(payload)
		if err != nil {
			return "", err
		}
		defer pool.Put(b)
		locator = quicutils.BuiltinBytesLocator(b)
	}
	sni, err = extractSniFromTls(locator)
	if err == nil {
		return sni, nil
	}
	return "", NotFoundError
}
