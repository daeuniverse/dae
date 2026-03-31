package crypto

import "encoding/binary"

var (
	crc32Table = make([]uint32, 256)
)

func init() {
	createCRC32Table()
}

func createCRC32Table() {
	for i := 0; i < 256; i++ {
		crc := uint32(i)
		for j := 8; j > 0; j-- {
			if crc&1 == 1 {
				crc = (crc >> 1) ^ 0xEDB88320
			} else {
				crc >>= 1
			}
		}
		crc32Table[i] = crc
	}
}

func CalcCRC32(input []byte, length int, value uint32) uint32 {
	return DoCalcCRC32(input, 0, length, value)
}

func DoCalcCRC32(input []byte, index int, length int, value uint32) uint32 {
	buffer := input
	for i := index; i < length; i++ {
		value = (value >> 8) ^ crc32Table[byte(value&0xFF)^buffer[i]]
	}
	return value ^ 0xFFFFFFFF
}

func DoSetCRC32(buffer []byte, index int, length int) {
	crc := CalcCRC32(buffer[:length-4], length-4, 0xFFFFFFFF)
	binary.LittleEndian.PutUint32(buffer[length-4:], crc^0xFFFFFFFF)
}

func SetCRC32(buffer []byte, length int) {
	DoSetCRC32(buffer, 0, length)
}

func CheckCRC32(buffer []byte, length int) bool {
	crc := CalcCRC32(buffer, length, 0xFFFFFFFF)
	return crc == 0xFFFFFFFF
}
