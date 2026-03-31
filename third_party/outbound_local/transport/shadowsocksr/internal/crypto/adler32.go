package crypto

import "encoding/binary"

func calcShortAdler32(input []byte, a, b uint32) (uint32, uint32) {
	for _, i := range input {
		a += uint32(i)
		b += a
	}
	a %= 65521
	b %= 65521
	return a, b
}

func CalcAdler32(input []byte) uint32 {
	var a uint32 = 1
	var b uint32 = 0
	const nMax = 5552
	for length := len(input); length > nMax; length -= nMax {
		a, b = calcShortAdler32(input[:nMax], a, b)
		input = input[nMax:]
	}
	a, b = calcShortAdler32(input, a, b)
	return (b << 16) + a
}

func CheckAdler32(input []byte, l int) bool {
	adler32 := CalcAdler32(input[:l-4])
	checksum := binary.LittleEndian.Uint32(input[l-4:])
	return adler32 == checksum
}
