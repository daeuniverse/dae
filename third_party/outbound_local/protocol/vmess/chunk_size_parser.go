package vmess

import (
	"encoding/binary"
	"golang.org/x/crypto/sha3"
)

type ShakeSizeParser struct {
	shake  sha3.ShakeHash
	buffer [2]byte
}

func NewShakeSizeParser(nonce []byte) *ShakeSizeParser {
	shake := sha3.NewShake128()
	shake.Write(nonce)
	return &ShakeSizeParser{
		shake: shake,
	}
}

func (*ShakeSizeParser) SizeBytes() int32 {
	return 2
}

func (s *ShakeSizeParser) next() uint16 {
	_, _ = s.shake.Read(s.buffer[:])
	return binary.BigEndian.Uint16(s.buffer[:])
}

func (s *ShakeSizeParser) Decode(b []byte) (uint16, error) {
	mask := s.next()
	size := binary.BigEndian.Uint16(b)
	return mask ^ size, nil
}

func (s *ShakeSizeParser) Encode(size uint16, b []byte) []byte {
	mask := s.next()
	binary.BigEndian.PutUint16(b, mask^size)
	return b[:2]
}

func (s *ShakeSizeParser) NextPaddingLen() uint16 {
	return s.next() % 64
}

func (s *ShakeSizeParser) MaxPaddingLen() uint16 {
	return 64
}

type PlainChunkSizeParser struct{}

func (PlainChunkSizeParser) SizeBytes() int32 {
	return 2
}

func (PlainChunkSizeParser) Encode(size uint16, b []byte) []byte {
	binary.BigEndian.PutUint16(b, size)
	return b[:2]
}

func (PlainChunkSizeParser) Decode(b []byte) (uint16, error) {
	return binary.BigEndian.Uint16(b), nil
}
