/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2023, daeuniverse Organization <dae@v2raya.org>
 */

package sniffing

import (
	"errors"
	"io/fs"

	"github.com/daeuniverse/dae/component/sniffing/internal/quicutils"
	"github.com/daeuniverse/outbound/pool"
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
	nextBlock := s.buf.Bytes()[s.quicNextRead:]
	isQuic := false
	for {
		s.quicCryptos, nextBlock, err = sniffQuicBlock(s.quicCryptos, nextBlock)
		if err != nil {
			// If block is not a quic block, return it.
			if errors.Is(err, ErrNotApplicable) {
				// But if we have found quic block before, correct it.
				if isQuic {
					// Unexpected non-block
					break
				}
				return "", err
			}
			if errors.Is(err, fs.ErrClosed) {
				// ConnectionClose sniffed.
				return "", ErrNotFound
			}
			// The code should NOT run here.
			return "", err
		}
		// Should be quic block.
		isQuic = true
		if len(nextBlock) == 0 {
			break
		}
	}
	// Is quic.
	s.quicNextRead = s.buf.Len()
	sni, err := extractSniFromTls(quicutils.NewLinearLocator(s.quicCryptos))
	if err != nil {
		s.needMore = true
		return "", ErrNotFound
	}
	return sni, nil
}

func sniffQuicBlock(cryptos []*quicutils.CryptoFrameOffset, buf []byte) (new []*quicutils.CryptoFrameOffset, next []byte, err error) {
	// QUIC: A UDP-Based Multiplexed and Secure Transport
	// https://datatracker.ietf.org/doc/html/rfc9000#name-initial-packet
	const dstConnIdPos = 6
	boundary := dstConnIdPos
	if len(buf) < boundary {
		return cryptos, nil, ErrNotApplicable
	}
	// Check flag.
	// Long header: 4 bits masked
	// High 4 bits are not protected, so we can access QuicFlag_HeaderForm and QuicFlag_LongPacketType without decryption.
	protectedFlag := buf[0]
	if ((protectedFlag >> QuicFlag_HeaderForm) & 0b11) != QuicFlag_HeaderForm_LongHeader {
		return cryptos, nil, ErrNotApplicable
	}
	if ((protectedFlag >> QuicFlag_LongPacketType) & 0b11) != QuicFlag_LongPacketType_Initial {
		return cryptos, nil, ErrNotApplicable
	}

	// Skip version.

	destConnIdLength := int(buf[boundary-1])
	boundary += destConnIdLength + 1 // +1 because next field has 1B length
	if len(buf) < boundary {
		return cryptos, nil, ErrNotApplicable
	}
	destConnId := buf[dstConnIdPos : dstConnIdPos+destConnIdLength]

	srcConnIdLength := int(buf[boundary-1])
	boundary += srcConnIdLength + quicutils.MaxVarintLen64 // The next fields may have quic.MaxVarintLen64 bytes length
	if len(buf) < boundary {
		return cryptos, nil, ErrNotApplicable
	}
	tokenLength, n, err := quicutils.BigEndianUvarint(buf[boundary-quicutils.MaxVarintLen64:])
	if err != nil {
		return cryptos, nil, ErrNotApplicable
	}
	boundary = boundary - quicutils.MaxVarintLen64 + n      // Correct boundary.
	boundary += int(tokenLength) + quicutils.MaxVarintLen64 // Next fields may have quic.MaxVarintLen64 bytes length
	if len(buf) < boundary {
		return cryptos, nil, ErrNotApplicable
	}
	// https://datatracker.ietf.org/doc/html/rfc9000#name-variable-length-integer-enc
	length, n, err := quicutils.BigEndianUvarint(buf[boundary-quicutils.MaxVarintLen64:])
	if err != nil {
		return cryptos, nil, ErrNotApplicable
	}
	boundary = boundary - quicutils.MaxVarintLen64 + n // Correct boundary.
	blockEnd := boundary + int(length)
	if len(buf) < blockEnd {
		return cryptos, nil, ErrNotApplicable
	}
	boundary += quicutils.MaxPacketNumberLength
	if len(buf) < boundary {
		return cryptos, nil, ErrNotApplicable
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
		return cryptos, nil, ErrNotApplicable
	}
	// Now, we confirm it is exact a quic frame.
	// After here, we should not return NotApplicableError.
	// And we should return nextFrame.
	if new, err = quicutils.ReassembleCryptos(cryptos, plaintext); err != nil {
		if errors.Is(err, fs.ErrClosed) {
			return cryptos, nil, err
		}
		return cryptos, buf[blockEnd:], ErrNotApplicable
	}
	return new, buf[blockEnd:], nil
}
