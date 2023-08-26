/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2023, daeuniverse Organization <dae@v2raya.org>
 */

package sniffing

import (
	"errors"
	"io/fs"

	"github.com/daeuniverse/dae/component/sniffing/internal/quicutils"
	"github.com/daeuniverse/softwind/pool"
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

type QuicReassemblePolicy int

const (
	QuicReassemblePolicy_ReassembleCryptoToBytesFromPool QuicReassemblePolicy = iota
	QuicReassemblePolicy_LinearLocator
	QuicReassemblePolicy_Slow
)

func (s *Sniffer) SniffQuic() (d string, err error) {
	nextBlock := s.buf.Bytes()
	isQuic := false
	for {
		s.quicCryptos, nextBlock, err = sniffQuicBlock(s.quicCryptos, nextBlock)
		if err != nil {
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
			return "", err
		}
		// Should be quic block.
		isQuic = true
		if len(nextBlock) == 0 {
			break
		}
	}
	// Is quic.
	s.buf.Reset()
	sni, err := extractSniFromTls(quicutils.NewLinearLocator(s.quicCryptos))
	if err != nil {
		s.needMore = true
		return "", NotFoundError
	}
	return sni, nil
}

func sniffQuicBlock(cryptos []*quicutils.CryptoFrameOffset, buf []byte) (new []*quicutils.CryptoFrameOffset, next []byte, err error) {
	// QUIC: A UDP-Based Multiplexed and Secure Transport
	// https://datatracker.ietf.org/doc/html/rfc9000#name-initial-packet
	const dstConnIdPos = 6
	boundary := dstConnIdPos
	if len(buf) < boundary {
		return nil, nil, NotApplicableError
	}
	// Check flag.
	// Long header: 4 bits masked
	// High 4 bits are not protected, so we can access QuicFlag_HeaderForm and QuicFlag_LongPacketType without decryption.
	protectedFlag := buf[0]
	if ((protectedFlag >> QuicFlag_HeaderForm) & 0b11) != QuicFlag_HeaderForm_LongHeader {
		return nil, nil, NotApplicableError
	}
	if ((protectedFlag >> QuicFlag_LongPacketType) & 0b11) != QuicFlag_LongPacketType_Initial {
		return nil, nil, NotApplicableError
	}

	// Skip version.

	destConnIdLength := int(buf[boundary-1])
	boundary += destConnIdLength + 1 // +1 because next field has 1B length
	if len(buf) < boundary {
		return nil, nil, NotApplicableError
	}
	destConnId := buf[dstConnIdPos : dstConnIdPos+destConnIdLength]

	srcConnIdLength := int(buf[boundary-1])
	boundary += srcConnIdLength + quicutils.MaxVarintLen64 // The next fields may have quic.MaxVarintLen64 bytes length
	if len(buf) < boundary {
		return nil, nil, NotApplicableError
	}
	tokenLength, n, err := quicutils.BigEndianUvarint(buf[boundary-quicutils.MaxVarintLen64:])
	if err != nil {
		return nil, nil, NotApplicableError
	}
	boundary = boundary - quicutils.MaxVarintLen64 + n      // Correct boundary.
	boundary += int(tokenLength) + quicutils.MaxVarintLen64 // Next fields may have quic.MaxVarintLen64 bytes length
	if len(buf) < boundary {
		return nil, nil, NotApplicableError
	}
	// https://datatracker.ietf.org/doc/html/rfc9000#name-variable-length-integer-enc
	length, n, err := quicutils.BigEndianUvarint(buf[boundary-quicutils.MaxVarintLen64:])
	if err != nil {
		return nil, nil, NotApplicableError
	}
	boundary = boundary - quicutils.MaxVarintLen64 + n // Correct boundary.
	blockEnd := boundary + int(length)
	if len(buf) < blockEnd {
		return nil, nil, NotApplicableError
	}
	boundary += quicutils.MaxPacketNumberLength
	if len(buf) < boundary {
		return nil, nil, NotApplicableError
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
	plaintext, err := quicutils.DecryptQuic_(header, blockEnd, destConnId)
	if err != nil {
		return nil, nil, NotApplicableError
	}
	// Now, we confirm it is exact a quic frame.
	// After here, we should not return NotApplicableError.
	// And we should return nextFrame.
	if new, err = quicutils.ReassembleCryptos(cryptos, plaintext); err != nil {
		if errors.Is(err, fs.ErrClosed) {
			return nil, nil, err
		}
		return nil, buf[blockEnd:], NotFoundError
	}
	return new, buf[blockEnd:], nil
}
