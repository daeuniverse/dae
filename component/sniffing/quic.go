/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package sniffing

import (
	"errors"
	"io/fs"

	"github.com/daeuniverse/dae/component/sniffing/internal/quicutils"
	"github.com/daeuniverse/outbound/pool"
)

const (
	QuicFlag_PacketNumberLength = 0
	QuicFlag_Reserved           = 2
	QuicFlag_LongPacketType     = 4
	QuicFlag_FixedBit           = 6
	QuicFlag_HeaderForm         = 7
)
const (
	QuicFlag_HeaderForm_LongHeader  = 1
	QuicFlag_LongPacketType_Initial = 0
)

const (
	QuicVersion1 = 0x00000001
)

// IsLikelyQuicLongHeaderPacket checks whether the buffer looks like a QUIC
// long-header packet. It is intentionally permissive and does not validate
// packet type or version so control-plane routing can recognize QUIC handshake
// traffic like Initial/0-RTT/Handshake consistently.
func IsLikelyQuicLongHeaderPacket(buf []byte) bool {
	const minQuicLongHeaderLen = 7
	if len(buf) < minQuicLongHeaderLen {
		return false
	}
	protectedFlag := buf[0]

	if ((protectedFlag >> QuicFlag_HeaderForm) & 0b1) != QuicFlag_HeaderForm_LongHeader {
		return false
	}
	if ((protectedFlag >> QuicFlag_FixedBit) & 0b1) == 0 {
		return false
	}
	// QUIC Version Negotiation packets (version=0) are server responses and
	// should not classify client-originated handshake traffic in control path.
	version := uint32(buf[1])<<24 | uint32(buf[2])<<16 | uint32(buf[3])<<8 | uint32(buf[4])
	if version == 0 {
		return false
	}

	// Validate Connection ID length layout per RFC 9000/8999 invariants:
	// DCID Len (1B), DCID, SCID Len (1B), SCID. CID lengths are max 20 bytes.
	destConnIDLen := int(buf[5])
	if destConnIDLen > 20 {
		return false
	}
	srcConnIDLenPos := 6 + destConnIDLen
	if len(buf) <= srcConnIDLenPos {
		return false
	}
	srcConnIDLen := int(buf[srcConnIDLenPos])
	if srcConnIDLen > 20 {
		return false
	}
	if len(buf) < srcConnIDLenPos+1+srcConnIDLen {
		return false
	}
	return true
}

// IsLikelyQuicInitialPacket checks if the buffer appears to be a QUIC Initial packet.
// It validates the Long Header format, Initial packet type, and Fixed bit.
// Version is NOT strictly checked to maintain compatibility with:
//   - QUIC v1 (0x00000001)
//   - QUIC v2 (0x709a50c4)
//   - Draft versions (e.g., 0xff00001d)
//
// This follows the principle of being liberal in what we accept for sniffing purposes.
func IsLikelyQuicInitialPacket(buf []byte) bool {
	if !IsLikelyQuicLongHeaderPacket(buf) {
		return false
	}
	protectedFlag := buf[0]

	if ((protectedFlag >> QuicFlag_LongPacketType) & 0b11) != QuicFlag_LongPacketType_Initial {
		return false
	}

	// Note: Version check intentionally omitted to support all QUIC versions.
	// The header form, packet type, and fixed bit checks are sufficient for
	// identifying likely QUIC Initial packets for sniffing purposes.

	return true
}

func (s *Sniffer) SniffQuic() (d string, err error) {
	nextBlock := s.buf.Bytes()[s.quicNextRead:]
	isQuic := false
	for {
		s.quicCryptos, nextBlock, err = sniffQuicBlock(s, s.quicCryptos, nextBlock)
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

func sniffQuicBlock(s *Sniffer, cryptos []*quicutils.CryptoFrameOffset, buf []byte) (new []*quicutils.CryptoFrameOffset, next []byte, err error) {
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
	s.quicPlaintexts = append(s.quicPlaintexts, plaintext)
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
